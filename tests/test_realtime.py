"""
WinSentinel - tests for the live monitor, notifier, extra hardening checks, fix commands,
log analytics, report integrity and the new API routes.
"""

import hashlib
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from werkzeug.security import generate_password_hash

import web.auth as auth_module
from analysis.bruteforce import analyze_security_events, logon_type_label
from collectors import extra_checks as ec
from config import get_config
from db.database import (
    create_or_update_admin,
    create_scan,
    find_report_hash,
    get_live_alerts,
    init_db,
    insert_findings,
    insert_live_alert,
    insert_scan_metrics,
    record_report_hash,
    update_scan_status,
)
from db.models import Finding
from risk.fixes import get_fix
from web import notifier
from web.app import create_app
from web.monitor import LiveMonitor

PASSWORD = "correct-horse-battery-staple"


def _events(n_fail=6, user="Victim", ip="10.0.0.5", logon_type="3", minutes_ago=2):
    """n_fail failed logons followed by nothing, all within the brute-force window."""
    base = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return [{
        "record_id": 1000 + i, "id": 4625, "time_created": (base + timedelta(seconds=i * 5)).isoformat(),
        "target_user_name": user, "ip_address": ip, "logon_type": logon_type,
    } for i in range(n_fail)]


class NotifierTests(unittest.TestCase):
    def setUp(self):
        self.cfg = get_config()

    def test_severity_threshold(self):
        with patch.object(self.cfg, "NOTIFY_MIN_SEVERITY", "High"):
            self.assertTrue(notifier.should_notify("Critical"))
            self.assertTrue(notifier.should_notify("High"))
            self.assertFalse(notifier.should_notify("Medium"))
            self.assertEqual(notifier.notify("t", "b", "Low"), {"all": "skipped (below NOTIFY_MIN_SEVERITY)"})

    def test_channels_and_failures_are_isolated(self):
        with patch.object(self.cfg, "NOTIFY_DESKTOP", True), \
             patch.object(self.cfg, "NOTIFY_WEBHOOK_URL", "https://hooks.example/x"), \
             patch.object(self.cfg, "NOTIFY_MIN_SEVERITY", "High"), \
             patch.object(self.cfg, "SMTP_HOST", None), \
             patch("web.notifier._send_desktop") as desktop, \
             patch("web.notifier._send_webhook", side_effect=RuntimeError("down")) as hook:
            result = notifier.notify("Brute force", "details", "Critical")
        desktop.assert_called_once()
        hook.assert_called_once()
        self.assertEqual(result["desktop"], "sent")
        self.assertTrue(result["webhook"].startswith("error"))  # a failing channel never raises

    def test_webhook_rejects_non_http_urls(self):
        with self.assertRaises(ValueError):
            notifier._send_webhook("file:///etc/passwd", "t", "b")

    def test_desktop_text_goes_through_environment_not_command_line(self):
        evil = "'; Remove-Item C:\\ -Recurse; '"
        with patch("web.notifier.sys.platform", "win32"), patch("web.notifier.subprocess.Popen") as popen:
            notifier._send_desktop(evil, evil)
        args, kwargs = popen.call_args
        self.assertNotIn("Remove-Item", " ".join(args[0]))      # never interpolated into the script
        self.assertIn("Remove-Item", kwargs["env"]["WS_BODY"])  # passed as data via the environment
        self.assertFalse(kwargs.get("shell", False))


class LiveMonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = get_config()
        self._orig = self.cfg.DB_PATH
        self.cfg.DB_PATH = str(Path(self.tmp.name) / "m.db")
        init_db()

    def tearDown(self):
        self.cfg.DB_PATH = self._orig
        self.tmp.cleanup()

    def test_burst_raises_one_alert_and_notifies_once(self):
        monitor = LiveMonitor(60)
        with patch("web.monitor.collect_security_events", return_value=(True, _events(), "")), \
             patch("web.monitor.notify") as notify_mock:
            first = monitor.poll_once()
            second = monitor.poll_once()  # same events again: must not alert twice
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(notify_mock.call_count, 1)
        alerts = get_live_alerts()
        self.assertEqual(alerts[0]["alert_type"], "Brute Force Attack")
        self.assertEqual(alerts[0]["account"], "victim")  # account names are case-insensitive

    def test_few_failures_do_not_alert(self):
        monitor = LiveMonitor(60)
        with patch("web.monitor.collect_security_events", return_value=(True, _events(n_fail=3), "")), \
             patch("web.monitor.notify") as notify_mock:
            self.assertEqual(monitor.poll_once(), [])
        notify_mock.assert_not_called()

    def test_unreadable_log_is_reported_not_swallowed(self):
        monitor = LiveMonitor(60)
        with patch("web.monitor.collect_security_events", return_value=(False, [], "Cannot read the Security log")):
            self.assertEqual(monitor.poll_once(), [])
        self.assertIn("Cannot read", monitor.status()["last_error"])

    def test_interval_floor_and_live_alert_dedupe(self):
        self.assertEqual(LiveMonitor(1).interval_seconds, 20)
        a = insert_live_alert("fp", "T", "2026-01-01T00:00:00", "x", "1.1.1.1", 5, "High", "d")
        b = insert_live_alert("fp", "T", "2026-01-01T00:00:00", "x", "1.1.1.1", 5, "High", "d")
        self.assertIsNotNone(a)
        self.assertIsNone(b)


class AnalyticsTests(unittest.TestCase):
    def test_log_analytics_metrics(self):
        events = _events(n_fail=7, user="Admin", ip="9.9.9.9", logon_type="10")
        events.append({"id": 4624, "time_created": events[-1]["time_created"], "target_user_name": "admin",
                       "ip_address": "9.9.9.9", "logon_type": "2"})
        _, _, metrics = analyze_security_events(events)
        self.assertEqual(metrics["top_failed_accounts"], {"admin": 7})
        self.assertEqual(metrics["top_failed_ips"], {"9.9.9.9": 7})
        self.assertEqual(metrics["failed_by_logon_type"], {"Remote desktop (RDP)": 7})
        self.assertEqual(metrics["success_by_logon_type"], {"Interactive (console)": 1})
        self.assertEqual(sum(metrics["hourly_failures"].values()), 7)

    def test_logon_type_labels(self):
        self.assertEqual(logon_type_label("10"), "Remote desktop (RDP)")
        self.assertEqual(logon_type_label(None), "Unknown")
        self.assertEqual(logon_type_label("99"), "Unknown")


class ExtraHardeningEvaluatorTests(unittest.TestCase):
    def test_defender_exclusions(self):
        self.assertEqual(ec.evaluate_defender_exclusions(None, None, None).status, "pass")
        self.assertEqual(ec.evaluate_defender_exclusions("N/A: Must be an administrator to view exclusions", None, None).status, "error")
        broad = ec.evaluate_defender_exclusions(["C:\\", r"C:\Users\me\Downloads"], ["exe"], ["powershell.exe"])
        self.assertEqual((broad.status, broad.severity), ("fail", "High"))
        narrow = ec.evaluate_defender_exclusions([r"D:\Games\MyGame"], None, None)
        self.assertEqual((narrow.status, narrow.severity), ("fail", "Low"))

    def test_smb_signing_and_powershell(self):
        self.assertEqual(ec.evaluate_smb_signing(True).status, "pass")
        self.assertEqual(ec.evaluate_smb_signing(False).status, "fail")
        self.assertEqual(ec.evaluate_smb_signing(None).status, "error")
        self.assertEqual(ec.evaluate_powershell_policy("Bypass").status, "fail")
        self.assertEqual(ec.evaluate_powershell_policy("RemoteSigned").status, "pass")
        self.assertEqual(ec.evaluate_script_block_logging(1).status, "pass")
        self.assertEqual(ec.evaluate_script_block_logging(None).status, "fail")

    def test_name_resolution(self):
        self.assertEqual(ec.evaluate_llmnr(0).status, "pass")
        self.assertEqual(ec.evaluate_llmnr(None).status, "fail")
        self.assertEqual(ec.evaluate_netbios([2, 2]).status, "pass")
        self.assertEqual(ec.evaluate_netbios([0]).status, "fail")
        self.assertEqual(ec.evaluate_netbios([]).status, "pass")

    def test_local_accounts(self):
        users = [{"Name": "alice", "Enabled": True, "PasswordRequired": True, "PasswordExpires": "2027-01-01T00:00:00"},
                 {"Name": "bob", "Enabled": True, "PasswordRequired": False, "PasswordExpires": None},
                 {"Name": "Guest", "Enabled": False, "PasswordRequired": False, "PasswordExpires": None}]
        titles = [f.title for f in ec.evaluate_local_accounts(users)]
        self.assertIn("Accounts Without a Required Password", titles)
        self.assertIn("Enabled Accounts With Passwords That Never Expire", titles)
        ok = ec.evaluate_local_accounts([users[0], users[2]])
        self.assertEqual([f.status for f in ok], ["pass"])  # disabled accounts are ignored

    def test_winrm(self):
        self.assertEqual(ec.evaluate_winrm("Running").status, "fail")
        self.assertEqual(ec.evaluate_winrm("Stopped").status, "pass")


class FixCommandTests(unittest.TestCase):
    def test_known_findings_have_commands(self):
        self.assertEqual(get_fix("Weak Minimum Password Length Policy")["text"], "net accounts /minpwlen:12")
        self.assertIn("445", get_fix("Risky Listening Port 445 Exposed (SMB)")["text"])
        self.assertEqual(get_fix("Vulnerability Detected: 7-Zip 24.09 (x64) (CVE-2026-1 - CVSS 8.8)")["text"], 'winget upgrade --name "7-Zip"')
        self.assertEqual(get_fix("Secure Boot Is Disabled")["commands"], [])  # firmware: guidance only
        self.assertIsNone(get_fix("Totally unrelated"))

    def test_cve_product_name_cannot_inject_commands(self):
        fix = get_fix('Vulnerability Detected: Evil"; calc; " 1.0 (CVE-2026-1 - CVSS 9.0)')
        self.assertNotIn('"; calc', fix["text"])


class RealtimeWebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = get_config()
        self._orig = self.cfg.DB_PATH
        self.cfg.DB_PATH = str(Path(self.tmp.name) / "w.db")
        auth_module._login_failures.clear()
        init_db()
        create_or_update_admin("admin", generate_password_hash(PASSWORD))
        self.scan = create_scan("TESTHOST")
        insert_findings([Finding(scan_id=self.scan, module="config", title="Weak Minimum Password Length Policy",
                                 evidence="0", status="fail", likelihood=3, impact=3, risk_score=9, severity="Medium",
                                 remediation="Fix")])
        insert_scan_metrics(self.scan, {
            "total_events_analyzed": 10, "failed_logon_count": 7, "successful_logon_count": 3, "privileged_logon_count": 0,
            "top_failed_accounts": {"admin": 7}, "top_failed_ips": {"9.9.9.9": 7},
            "failed_by_logon_type": {"Remote desktop (RDP)": 7}, "success_by_logon_type": {"Interactive (console)": 3},
            "hourly_failures": {"2026-10-19 10:00": 7},
        })
        update_scan_status(self.scan, "completed", posture_score=91)
        app = create_app()
        app.config["TESTING"] = True
        self.client = app.test_client()
        page = self.client.get("/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        self.client.post("/login", data={"username": "admin", "password": PASSWORD, "csrf_token": token})

    def tearDown(self):
        self.cfg.DB_PATH = self._orig
        self.tmp.cleanup()

    def _token(self):
        return re.search(r'name="csrf-token" content="([^"]+)"', self.client.get("/dashboard").get_data(as_text=True)).group(1)

    def test_live_status_api(self):
        insert_live_alert("fp1", "Brute Force Attack", "2026-10-19T10:00:00", "admin", "9.9.9.9", 7, "High", "details")
        data = self.client.get("/api/live/status?since_id=0").get_json()
        self.assertEqual(len(data["alerts"]), 1)
        self.assertEqual(data["max_id"], data["alerts"][0]["id"])
        self.assertIn("enabled", data["monitor"])
        again = self.client.get(f"/api/live/status?since_id={data['max_id']}").get_json()
        self.assertEqual(again["alerts"], [])

    def test_log_analytics_api(self):
        data = self.client.get("/api/log-analytics").get_json()
        self.assertTrue(data["available"])
        self.assertEqual(data["top_accounts"], [{"name": "admin", "count": 7}])
        self.assertEqual(data["logon_types"][0]["name"], "Interactive (console)")

    def test_alerts_page_shows_live_alerts_and_analytics(self):
        insert_live_alert("fp2", "Possible Compromise", "2026-10-19T10:00:00", "root", "1.2.3.4", 9, "Critical", "d")
        html = self.client.get("/alerts").get_data(as_text=True)
        self.assertIn("Live monitor", html)
        self.assertIn("Possible Compromise", html)
        self.assertIn('id="analytics"', html)
        self.assertNotIn(' style="', html)

    def test_findings_page_shows_fix_command(self):
        html = self.client.get("/findings").get_data(as_text=True)
        self.assertIn("net accounts /minpwlen:12", html)
        self.assertIn("data-copy-target", html)

    def test_non_elevated_banner(self):
        with patch("web.views.is_elevated", return_value=False):
            self.assertIn("Running without Administrator rights", self.client.get("/dashboard").get_data(as_text=True))
        with patch("web.views.is_elevated", return_value=True):
            self.assertNotIn("Running without Administrator rights", self.client.get("/dashboard").get_data(as_text=True))

    def test_report_download_records_hash_and_verify_matches(self):
        resp = self.client.get("/report/download.pdf")
        digest = hashlib.sha256(resp.data).hexdigest()
        self.assertEqual(resp.headers["X-Report-SHA256"], digest)
        self.assertEqual(find_report_hash(digest)["scan_id"], self.scan)

        def verify(content):
            return self.client.post("/report/verify", data={"csrf_token": self._token(), "report": (MagicMock_file(content), "r.pdf")},
                                    content_type="multipart/form-data").get_data(as_text=True)
        self.assertIn("Authentic", verify(resp.data))
        tampered = resp.data + b" "
        self.assertIn("No match", verify(tampered))

    def test_verify_requires_login_and_csrf(self):
        anon = create_app().test_client()
        self.assertEqual(anon.get("/report/verify").status_code, 302)
        self.assertEqual(self.client.post("/report/verify", data={}).status_code, 400)
        self.assertEqual(self.client.get("/report/verify").status_code, 200)


def MagicMock_file(content: bytes):
    """In-memory file object for werkzeug's test client multipart upload."""
    import io
    return io.BytesIO(content)


class PrivilegeTests(unittest.TestCase):
    def test_is_elevated_returns_bool(self):
        from collectors.privileges import is_elevated
        self.assertIsInstance(is_elevated(), bool)


class ReportHashHelperTests(unittest.TestCase):
    def test_record_and_find(self):
        with tempfile.TemporaryDirectory() as d:
            db = str(Path(d) / "h.db")
            init_db(db)
            record_report_hash("ab" * 32, 7, "html", 123, "admin", db_path=db)
            self.assertEqual(find_report_hash("ab" * 32, db_path=db)["scan_id"], 7)
            self.assertIsNone(find_report_hash("cd" * 32, db_path=db))


if __name__ == "__main__":
    unittest.main()
