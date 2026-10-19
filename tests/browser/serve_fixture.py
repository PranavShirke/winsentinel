"""
Test fixture server for the browser tests. NEVER run this outside tests.

Starts WinSentinel on a throw-away database with seeded data and an automatic login so the browser
test can reach authenticated pages. The auto-login exists only in this file; the application itself
has no such bypass. It refuses to start unless WINSENTINEL_TEST_FIXTURE=1 is set.

Usage: py tests/browser/serve_fixture.py <port>
"""

import os
import sys
import tempfile
import time

if os.environ.get("WINSENTINEL_TEST_FIXTURE") != "1":
    sys.exit("Refusing to start: set WINSENTINEL_TEST_FIXTURE=1 (this server logs everyone in automatically).")

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from werkzeug.security import generate_password_hash  # noqa: E402

from config import get_config  # noqa: E402

cfg = get_config()
cfg.DB_PATH = os.path.join(tempfile.mkdtemp(prefix="winsentinel-test-"), "fixture.db")

from db.database import (  # noqa: E402
    create_or_update_admin, create_scan, init_db, insert_alerts, insert_findings, insert_live_alert,
    insert_scan_metrics, insert_software, update_scan_status,
)
from db.models import Alert, Finding, SoftwareItem  # noqa: E402

init_db()
create_or_update_admin("admin", generate_password_hash("fixture-password-123"))


def finding(sid, module, title, severity, status, likelihood, impact, evidence, remediation):
    return Finding(scan_id=sid, module=module, title=title, evidence=evidence, status=status, likelihood=likelihood,
                   impact=impact, risk_score=likelihood * impact if status == "fail" else 0,
                   severity=severity if status == "fail" else "Info", remediation=remediation)


old = create_scan("TESTHOST")
insert_findings([finding(old, "config", "SMBv1 Legacy Protocol Enabled", "Critical", "fail", 4, 4, "EnableSMB1Protocol: True", "Disable SMBv1")])
update_scan_status(old, "completed", posture_score=77)

sid = create_scan("TESTHOST")
insert_findings([
    finding(sid, "config", "Weak Minimum Password Length Policy", "Medium", "fail", 3, 3, "net accounts: Minimum password length = 0", "Raise it"),
    finding(sid, "config", "Exposed RDP Port 3389 Without NLA", "High", "fail", 3, 4, "Port 3389 on 0.0.0.0", "Enable NLA"),
    finding(sid, "logs", "Possible Account Compromise: svc_backup", "Critical", "fail", 5, 5, "Success after 9 failures", "Isolate host"),
    finding(sid, "logs", "Brute-Force Logon Activity: administrator", "High", "fail", 4, 3, "12 failed logons", "Block IP"),
    finding(sid, "software", "Vulnerability Detected: 7-Zip 23.01 (CVE-2024-11477 - CVSS 7.8)", "High", "fail", 3, 4, "CVE match", "Update"),
    finding(sid, "config", "Windows Defender Real-Time Protection", "Info", "pass", 1, 1, "Enabled", "None"),
    finding(sid, "config", "Firewall profiles enabled", "Info", "pass", 1, 1, "All on", "None"),
    finding(sid, "software", "CVE Lookup Error for Python", "Error", "error", 1, 1, "NVD timed out", "Retry"),
])
insert_alerts([Alert(scan_id=sid, alert_type="Brute Force Attack", timestamp="2026-10-18T22:10:41+00:00", severity="High",
                     details="12 failed logons in 4 minutes.", account="administrator", source_ip="10.0.0.9", count=12)])
insert_software([SoftwareItem(scan_id=sid, name="7-Zip", version="23.01", publisher="Igor Pavlov")])
insert_scan_metrics(sid, {
    "total_events_analyzed": 40, "failed_logon_count": 12, "successful_logon_count": 3, "privileged_logon_count": 1,
    "daily_failures": {"2026-10-17": 2, "2026-10-18": 24},
    "top_failed_accounts": {"administrator": 9, "svc_backup": 3}, "top_failed_ips": {"10.0.0.9": 12},
    "failed_by_logon_type": {"Network (SMB, shares)": 8, "Remote desktop (RDP)": 4},
    "success_by_logon_type": {"Interactive (console)": 3},
    "hourly_failures": {"2026-10-18 21:00": 3, "2026-10-18 22:00": 9},
})
update_scan_status(sid, "completed", posture_score=53)
insert_live_alert("fixture-live-1", "Brute Force Attack", "2026-10-19T09:00:00+00:00", "administrator", "10.0.0.9", 7, "High",
                  "7 failed logons within 10 minutes (live monitor).")

from web.app import create_app  # noqa: E402

app = create_app()


@app.before_request
def _auto_login():
    from flask import request, session
    if "user_id" not in session and not request.path.startswith(("/login", "/static")) and request.path != "/":
        session.update(user_id=1, username="admin", last_active=time.time())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(sys.argv[1]) if len(sys.argv) > 1 else 5057, debug=False)
