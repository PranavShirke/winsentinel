"""
WinSentinel - tests for the extra hardening checks, framework mapping, risk register,
PDF report, search API and auto-scan scheduler.
"""

import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from werkzeug.security import generate_password_hash

import web.auth as auth_module
from collectors import extra_checks as ec
from config import get_config
from db.database import (
    create_or_update_admin,
    create_scan,
    get_finding_statuses,
    init_db,
    insert_findings,
    set_finding_status,
    update_scan_status,
)
from db.models import Finding
from reports.pdf_report import build_pdf_report
from reports.report_builder import build_html_report
from reports.report_data import adjusted_posture_score, collect_report_data
from risk.frameworks import map_frameworks
from web.app import create_app
from web.scheduler import MIN_INTERVAL_MINUTES, AutoScanScheduler

PASSWORD = "correct-horse-battery-staple"
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


class ExtraCheckEvaluatorTests(unittest.TestCase):
    """Pure evaluators: no Windows needed."""

    def test_update_recency_bands(self):
        recent = ec.evaluate_update_recency("KB1", "2026-10-10T00:00:00", now=NOW)
        aging = ec.evaluate_update_recency("KB1", "2026-08-01T00:00:00", now=NOW)
        old = ec.evaluate_update_recency("KB1", "2026-01-01T00:00:00", now=NOW)
        self.assertEqual((recent.status, aging.severity, old.severity), ("pass", "Medium", "High"))
        self.assertEqual(ec.evaluate_update_recency(None, None, now=NOW).status, "fail")
        self.assertEqual(ec.evaluate_update_recency("KB1", "garbage", now=NOW).status, "error")

    def test_pending_reboot_and_os_support(self):
        self.assertEqual(ec.evaluate_pending_reboot(True).status, "fail")
        self.assertEqual(ec.evaluate_pending_reboot(False).status, "pass")
        self.assertEqual(ec.evaluate_os_support(19045).status, "fail")   # Windows 10
        self.assertEqual(ec.evaluate_os_support(26300).status, "pass")   # Windows 11

    def test_bitlocker(self):
        self.assertEqual(ec.evaluate_bitlocker(1).status, "pass")
        self.assertEqual(ec.evaluate_bitlocker(0).status, "fail")
        self.assertEqual(ec.evaluate_bitlocker(None).status, "error")  # unknown is never a pass

    def test_uac_levels(self):
        self.assertEqual(ec.evaluate_uac(1, 5, 1)[0].status, "pass")
        self.assertEqual(ec.evaluate_uac(0, 5, 1)[0].severity, "Critical")
        self.assertEqual(ec.evaluate_uac(1, 0, 1)[0].status, "fail")
        self.assertEqual(ec.evaluate_uac(1, 5, 0)[0].status, "fail")
        self.assertEqual(ec.evaluate_uac(None, None, None)[0].status, "error")

    def test_secure_boot(self):
        self.assertEqual(ec.evaluate_secure_boot(1).status, "pass")
        self.assertEqual(ec.evaluate_secure_boot(0).status, "fail")
        self.assertEqual(ec.evaluate_secure_boot(None).status, "fail")

    def test_credential_protections(self):
        self.assertEqual(ec.evaluate_lsa_protection(1).status, "pass")
        self.assertEqual(ec.evaluate_lsa_protection(None).status, "fail")
        self.assertEqual(ec.evaluate_wdigest(1).severity, "High")
        self.assertEqual(ec.evaluate_wdigest(None).status, "pass")
        self.assertEqual(ec.evaluate_autologon("1", True).severity, "Critical")
        self.assertEqual(ec.evaluate_autologon("1", False).status, "fail")
        self.assertEqual(ec.evaluate_autologon(None, False).status, "pass")

    def test_shares_ignore_admin_shares(self):
        defaults = [{"Name": "C$", "Path": "C:\\", "Special": True}, {"Name": "IPC$", "Path": "", "Special": True}]
        self.assertEqual(ec.evaluate_shares(defaults).status, "pass")
        custom = defaults + [{"Name": "Public", "Path": "D:\\Public", "Special": False}]
        finding = ec.evaluate_shares(custom)
        self.assertEqual(finding.status, "fail")
        self.assertIn("Public", finding.evidence)

    def test_startup_entries_flag_user_writable_paths(self):
        safe = [{"name": "Defender", "command": r"C:\Program Files\Windows Defender\x.exe", "location": "HKLM Run"}]
        self.assertEqual(ec.evaluate_startup_entries(safe).status, "pass")
        risky = safe + [{"name": "upd", "command": r"C:\Users\me\AppData\Local\Temp\evil.exe", "location": "HKCU Run"}]
        finding = ec.evaluate_startup_entries(risky)
        self.assertEqual(finding.status, "fail")
        self.assertIn("evil.exe", finding.evidence)

    def test_finding_scoring_is_consistent(self):
        f = ec.evaluate_secure_boot(0)
        self.assertEqual(f.risk_score, f.likelihood * f.impact)
        self.assertEqual(ec.evaluate_secure_boot(1).risk_score, 0)


class FrameworkMappingTests(unittest.TestCase):
    def test_known_findings_map_to_expected_techniques(self):
        self.assertIn("T1110", [t["id"] for t in map_frameworks("Account Lockout Threshold Disabled")["attack"]])
        self.assertIn("T1003.001", [t["id"] for t in map_frameworks("LSA Protection (RunAsPPL) Is Not Enabled")["attack"]])
        self.assertIn("T1547.001", [t["id"] for t in map_frameworks("2 Startup Entries Run From User-Writable Folders")["attack"]])
        self.assertIn("T1136.001", [t["id"] for t in map_frameworks("Account Created")["attack"]])
        cis = [t["id"] for t in map_frameworks("Windows Updates Are Outdated")["cis"]]
        self.assertIn("7.3", cis)

    def test_unknown_title_maps_to_nothing_and_no_duplicates(self):
        self.assertEqual(map_frameworks("Totally unrelated"), {"attack": [], "cis": []})
        ids = [t["id"] for t in map_frameworks("Vulnerability Detected: 7-Zip (CVE-1)")["attack"]]
        self.assertEqual(len(ids), len(set(ids)))


class FeatureWebTests(unittest.TestCase):
    """Risk register, PDF, search and frameworks page against a temporary database."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = get_config()
        self._orig_db = self.cfg.DB_PATH
        self.cfg.DB_PATH = str(Path(self.tmp.name) / "t.db")
        auth_module._login_failures.clear()
        init_db()
        create_or_update_admin("admin", generate_password_hash(PASSWORD))
        self.scan = create_scan("TESTHOST")
        insert_findings([
            Finding(scan_id=self.scan, module="config", title="Weak Minimum Password Length Policy", evidence="len 0",
                    status="fail", likelihood=3, impact=3, risk_score=9, severity="Medium", remediation="Fix"),
            Finding(scan_id=self.scan, module="config", title="Secure Boot Is Disabled", evidence="0",
                    status="fail", likelihood=2, impact=4, risk_score=8, severity="Medium", remediation="Enable"),
            Finding(scan_id=self.scan, module="config", title="User Account Control (UAC) Is Enforced", evidence="ok",
                    status="pass", likelihood=1, impact=1, risk_score=0, severity="Info", remediation="None"),
        ])
        update_scan_status(self.scan, "completed", posture_score=94)
        app = create_app()
        app.config["TESTING"] = True
        self.client = app.test_client()
        page = self.client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        self.client.post("/login", data={"username": "admin", "password": PASSWORD, "csrf_token": token})

    def tearDown(self):
        self.cfg.DB_PATH = self._orig_db
        self.tmp.cleanup()

    def _csrf(self):
        page = self.client.get("/dashboard").get_data(as_text=True)
        return re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)

    def _post_status(self, **kw):
        body = {"scan_id": self.scan, "module": "config", "title": "Weak Minimum Password Length Policy",
                "status": "accepted", "note": "Accepted by lab owner"}
        body.update(kw)
        return self.client.post("/api/findings/status", json=body, headers={"X-CSRFToken": self._csrf()})

    def test_register_requires_csrf(self):
        resp = self.client.post("/api/findings/status", json={})
        self.assertEqual(resp.status_code, 400)

    def test_register_accept_updates_adjusted_score_and_persists(self):
        resp = self._post_status()
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["adjusted_score"], 100 - 3)  # only the other Medium finding still counts
        self.assertEqual(data["register"]["accepted"], 1)
        saved = get_finding_statuses()
        self.assertEqual(list(saved.values())[0]["updated_by"], "admin")
        # Reset to open removes the decision
        self.assertEqual(self._post_status(status="open", note="").status_code, 200)
        self.assertEqual(get_finding_statuses(), {})

    def test_register_validation(self):
        self.assertEqual(self._post_status(note="short").status_code, 422)             # justification too short
        self.assertEqual(self._post_status(status="bogus").status_code, 400)           # unknown state
        self.assertEqual(self._post_status(module="evil").status_code, 400)            # module allow-list
        self.assertEqual(self._post_status(title="Not a real finding").status_code, 404)  # must exist in the scan
        self.assertEqual(self._post_status(scan_id="abc").status_code, 400)

    def test_decisions_shown_in_findings_and_excluded_from_top_risks(self):
        self._post_status()
        findings_html = self.client.get("/findings").get_data(as_text=True)
        self.assertIn('data-register="accepted"', findings_html)
        dash = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("Adjusted for accepted risks", dash)

    def test_pdf_report_is_valid_and_contains_content(self):
        resp = self.client.get("/report/download.pdf")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "application/pdf")
        self.assertTrue(resp.data.startswith(b"%PDF"))
        self.assertGreater(len(resp.data), 3000)
        self.assertIsNone(build_pdf_report(99999))

    def test_html_report_includes_methodology_tags_and_register(self):
        self._post_status()
        html = build_html_report(self.scan)
        for needle in ("Methodology", "Limitations", "ATT&amp;CK", "Risk register: Accepted risk", "Accepted by lab owner"):
            self.assertIn(needle, html)

    def test_report_data_adjusted_score(self):
        self._post_status()
        data = collect_report_data(self.scan)
        self.assertEqual(adjusted_posture_score(data["findings"]), 97)
        self.assertEqual(data["register"]["accepted"], 1)

    def test_search_api_and_frameworks_page(self):
        found = self.client.get("/api/search", query_string={"q": "secure boot"}).get_json()["results"]
        self.assertEqual([r["title"] for r in found], ["Secure Boot Is Disabled"])
        self.assertEqual(self.client.get("/api/search", query_string={"q": "x"}).get_json(), {"results": []})
        page = self.client.get("/frameworks")
        self.assertEqual(page.status_code, 200)
        self.assertIn("T1542.003", page.get_data(as_text=True))

    def test_new_pages_require_login(self):
        anon = self.app_client()
        for path in ("/frameworks", "/api/search?q=abc", "/report/download.pdf"):
            self.assertEqual(anon.get(path).status_code, 302, path)
        self.assertEqual(anon.post("/api/findings/status", json={}).status_code, 400)  # CSRF checked before auth

    def app_client(self):
        return create_app().test_client()


class SchedulerTests(unittest.TestCase):
    def test_interval_has_a_floor(self):
        self.assertEqual(AutoScanScheduler(1).interval_seconds, MIN_INTERVAL_MINUTES * 60)
        self.assertEqual(AutoScanScheduler(60).interval_seconds, 3600)

    def test_scheduler_disabled_by_default(self):
        from web.scheduler import start_scheduler_if_enabled
        with patch.object(get_config(), "AUTO_SCAN_INTERVAL_MINUTES", 0):
            self.assertIsNone(start_scheduler_if_enabled())


if __name__ == "__main__":
    unittest.main()
