"""
WinSentinel - End-to-end web tests.

Exercises the Flask app against a throw-away SQLite database: authentication, every
dashboard page, CSRF, open-redirect protection, security headers, CSV export, scan
comparison and the version-aware CVE matcher.
"""

import re
import tempfile
import unittest
from pathlib import Path

from werkzeug.security import generate_password_hash

from config import get_config
from db.database import (
    init_db,
    create_or_update_admin,
    create_scan,
    update_scan_status,
    insert_findings,
    insert_alerts,
    insert_software,
    insert_scan_metrics,
    get_scan_metrics,
    compare_scans,
)
from db.models import Finding, Alert, SoftwareItem
from collectors.nvd_client import version_is_affected, parse_version
from collectors.software_inventory import match_allowed_software
import web.auth as auth_module
from web.app import create_app

PASSWORD = "correct-horse-battery-staple"


def _finding(scan_id, title, severity="High", status="fail", module="config", risk=12):
    """Build a Finding with consistent scoring fields."""
    return Finding(
        scan_id=scan_id, module=module, title=title, evidence="evidence", status=status,
        likelihood=4, impact=3, risk_score=risk if status == "fail" else 0,
        severity=severity if status == "fail" else "Info", remediation="Fix it.",
    )


class WebAppTests(unittest.TestCase):
    """Full request/response checks against a temporary database."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "test.db")
        self.cfg = get_config()
        self._orig_db = self.cfg.DB_PATH
        self.cfg.DB_PATH = self.db_path
        auth_module._login_failures.clear()

        init_db()
        create_or_update_admin("admin", generate_password_hash(PASSWORD))

        # Scan 1 (baseline) and scan 2 (newer) with a deliberate difference
        self.s1 = create_scan("TESTHOST")
        insert_findings([_finding(self.s1, "SMBv1 enabled", "Critical", risk=20), _finding(self.s1, "RDP exposed")])
        update_scan_status(self.s1, "completed", posture_score=77)

        self.s2 = create_scan("TESTHOST")
        insert_findings([
            _finding(self.s2, "RDP exposed"),
            _finding(self.s2, "Weak password length", "Medium", risk=9),
            _finding(self.s2, "Firewall profiles", status="pass"),
            _finding(self.s2, "=HYPERLINK(evil)", "Low", module="software", risk=3),
        ])
        insert_alerts([Alert(scan_id=self.s2, alert_type="Brute Force Attack", timestamp="2026-01-02T03:04:05+00:00",
                             severity="High", details="d", account="admin", source_ip="10.0.0.9", count=7)])
        insert_software([SoftwareItem(scan_id=self.s2, name="7-Zip", version="23.01", publisher="Igor")])
        insert_scan_metrics(self.s2, {"daily_failures": {"2026-01-02": 7}})
        update_scan_status(self.s2, "completed", posture_score=88)

        app = create_app()
        app.config["TESTING"] = True
        self.app = app
        self.client = app.test_client()

    def tearDown(self):
        self.cfg.DB_PATH = self._orig_db
        self.tmp.cleanup()

    def _login(self, client=None):
        client = client or self.client
        page = client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        return client.post("/login", data={"username": "admin", "password": PASSWORD, "csrf_token": token})

    def _token(self):
        page = self.client.get("/dashboard").get_data(as_text=True)
        return re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)

    # -- authentication ------------------------------------------------
    def test_protected_pages_redirect_to_login(self):
        for path in ("/dashboard", "/findings", "/alerts", "/software", "/history", "/compare", "/report",
                     "/findings/export.csv", "/api/summary", "/scan/status"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 302, path)
            self.assertIn("/login", resp.headers["Location"], path)

    def test_login_requires_csrf_token(self):
        resp = self.client.post("/login", data={"username": "admin", "password": PASSWORD})
        self.assertEqual(resp.status_code, 400)

    def test_login_success_and_every_page_renders(self):
        self.assertEqual(self._login().status_code, 302)
        for path in ("/dashboard", "/findings", "/alerts", "/software", "/history", "/compare", "/report"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200, path)
            html = resp.get_data(as_text=True)
            self.assertNotIn(' style="', html, f"inline style breaks CSP on {path}")
            self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)", f"inline script on {path}")

    def test_open_redirect_is_blocked(self):
        page = self.client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        for evil in ("https://evil.example/x", "//evil.example", "/\\evil.example", "javascript:alert(1)"):
            auth_module._login_failures.clear()
            client = self.app.test_client()
            page = client.get("/login").get_data(as_text=True)
            token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
            resp = client.post("/login", query_string={"next": evil},
                               data={"username": "admin", "password": PASSWORD, "csrf_token": token})
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.headers["Location"].endswith("/dashboard"), evil)

    def test_safe_next_is_followed(self):
        page = self.client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        resp = self.client.post("/login", query_string={"next": "/findings"},
                                data={"username": "admin", "password": PASSWORD, "csrf_token": token})
        self.assertTrue(resp.headers["Location"].endswith("/findings"))

    def test_lockout_after_repeated_failures(self):
        for _ in range(5):
            page = self.client.get("/login").get_data(as_text=True)
            if 'name="csrf_token"' not in page:
                break
            token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
            self.client.post("/login", data={"username": "admin", "password": "wrong", "csrf_token": token})
        locked_page = self.client.get("/login").get_data(as_text=True)
        self.assertIn("Too many failed login attempts", locked_page)

    def test_logout_is_post_only_and_csrf_protected(self):
        self._login()
        self.assertEqual(self.client.get("/logout").status_code, 405)
        self.assertEqual(self.client.post("/logout").status_code, 400)
        resp = self.client.post("/logout", data={"csrf_token": self._token()})
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_scan_start_requires_csrf(self):
        self._login()
        self.assertEqual(self.client.post("/scan/start").status_code, 400)

    # -- headers -------------------------------------------------------
    def test_security_headers_present(self):
        self._login()
        resp = self.client.get("/dashboard")
        csp = resp.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp)
        self.assertEqual(resp.headers["X-Frame-Options"], "DENY")
        self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("no-store", resp.headers["Cache-Control"])
        self.assertIn("Permissions-Policy", resp.headers)

    def test_no_external_urls_in_pages(self):
        self._login()
        for path in ("/dashboard", "/findings", "/compare"):
            html = self.client.get(path).get_data(as_text=True)
            self.assertNotRegex(html, r'(src|href)="https?://', path)

    # -- data behaviour ------------------------------------------------
    def test_latest_completed_scan_is_default(self):
        self._login()
        running = create_scan("TESTHOST")  # still 'running': must not replace the dashboard view
        html = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn(f"SCAN #{self.s2}", html)
        self.assertNotIn(f"SCAN #{running}", html)

    def test_findings_filters_and_bad_params(self):
        self._login()
        html = self.client.get("/findings", query_string={"status": "fail", "severity": "Medium"}).get_data(as_text=True)
        self.assertIn("Weak password length", html)
        self.assertNotIn("RDP exposed", html)
        # Hostile values must be ignored, never crash or inject
        resp = self.client.get("/findings", query_string={"severity": "'; DROP TABLE findings;--", "scan_id": "abc", "search": "<script>"})
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("<script>alert", resp.get_data(as_text=True))

    def test_csv_export_neutralises_formulas(self):
        self._login()
        resp = self.client.get("/findings/export.csv")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "text/csv")
        body = resp.get_data(as_text=True)
        self.assertIn("'=HYPERLINK(evil)", body)
        self.assertNotIn(",=HYPERLINK", body)

    def test_api_summary_uses_real_daily_failures(self):
        self._login()
        data = self.client.get("/api/summary").get_json()
        self.assertEqual(data["scan_id"], self.s2)
        self.assertEqual(data["daily_failures"], {"2026-01-02": 7})

    def test_compare_view_and_helper(self):
        diff = compare_scans(self.s1, self.s2)
        self.assertEqual([f["title"] for f in diff["resolved"]], ["SMBv1 enabled"])
        self.assertEqual({f["title"] for f in diff["new"]}, {"Weak password length", "=HYPERLINK(evil)"})
        self.assertEqual([f["title"] for f in diff["persisting"]], ["RDP exposed"])
        self._login()
        html = self.client.get("/compare", query_string={"old": self.s1, "new": self.s2}).get_data(as_text=True)
        self.assertIn("SMBv1 enabled", html)
        self.assertIn("+11", html)

    def test_report_download_filename_is_sanitised(self):
        self._login()
        resp = self.client.get("/report/download")
        self.assertEqual(resp.status_code, 200)
        self.assertRegex(resp.headers["Content-Disposition"], r'filename=WinSentinel_Audit_Report_[A-Za-z0-9_.-]+\.html$')

    def test_scan_metrics_round_trip(self):
        self.assertEqual(get_scan_metrics(self.s2)["daily_failures"], {"2026-01-02": 7})
        self.assertEqual(get_scan_metrics(self.s1), {})


class VersionMatchingTests(unittest.TestCase):
    """The NVD matcher must keep only CVEs whose ranges include the installed version."""

    @staticmethod
    def _cve(**match):
        base = {"vulnerable": True, "criteria": "cpe:2.3:a:igor_pavlov:7-zip:*:*:*:*:*:*:*:*"}
        base.update(match)
        return {"configurations": [{"nodes": [{"cpeMatch": [base]}]}]}

    def test_parse_version(self):
        self.assertEqual(parse_version("23.01"), (23, 1))
        self.assertEqual(parse_version("3.12.0 (64-bit)"), (3, 12, 0))
        self.assertEqual(parse_version("Unknown"), ())

    def test_range_bounds(self):
        cve = self._cve(versionEndExcluding="24.07")
        self.assertTrue(version_is_affected(cve, "7-zip", "23.01"))
        self.assertFalse(version_is_affected(cve, "7-zip", "24.07"))
        self.assertFalse(version_is_affected(cve, "7-zip", "25.00"))
        start = self._cve(versionStartIncluding="9.0", versionEndIncluding="9.20")
        self.assertTrue(version_is_affected(start, "7-zip", "9.20"))
        self.assertFalse(version_is_affected(start, "7-zip", "9.21"))
        self.assertFalse(version_is_affected(start, "7-zip", "8.9"))

    def test_exact_version_and_unrelated_product(self):
        exact = {"configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:igor_pavlov:7-zip:23.01:*:*:*:*:*:*:*"}]}]}]}
        self.assertTrue(version_is_affected(exact, "7-zip", "23.01"))
        self.assertFalse(version_is_affected(exact, "7-zip", "23.02"))
        other = {"configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:other:tool:1.0:*:*:*:*:*:*:*"}]}]}]}
        self.assertIsNone(version_is_affected(other, "7-zip", "23.01"))
        self.assertIsNone(version_is_affected({}, "7-zip", "23.01"))

    def test_allowlist_uses_whole_words(self):
        items = [SoftwareItem(name="JavaScript Helper Tools"), SoftwareItem(name="Java(TM) SE Development Kit"),
                 SoftwareItem(name="Python 3.12.1 Core Interpreter (64-bit)")]
        matched = {item.name: kw for item, kw in match_allowed_software(items)}
        self.assertNotIn("JavaScript Helper Tools", matched)
        self.assertEqual(matched["Java(TM) SE Development Kit"], "java")
        self.assertEqual(matched["Python 3.12.1 Core Interpreter (64-bit)"], "python")


if __name__ == "__main__":
    unittest.main()
