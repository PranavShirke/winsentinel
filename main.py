"""
WinSentinel - Windows Security Audit, Log Analysis and Risk Scoring Framework.

CLI Entrypoint supporting commands:
  - set-password: Set administrator password for the Flask dashboard.
  - scan: Run a local security audit from the command line.
  - serve: Start the local Flask web dashboard on 127.0.0.1:5000.
  - demo: Load sample events and demonstration audit data into the database.
"""

import sys
import os
import argparse
import ctypes
import getpass
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash

from config import get_config
from db.database import (
    init_db,
    create_or_update_admin,
    has_users,
    create_scan,
    update_scan_status,
    insert_findings,
    insert_alerts,
    insert_software,
    insert_scan_metrics,
    get_latest_scan,
)
from db.models import Finding, Alert, SoftwareItem


def check_elevation(warn_only: bool = True) -> bool:
    """
    Check if the current process is running with Windows Administrator privileges.

    Args:
        warn_only: If True, prints a warning message but does not exit.
                   If False, exits the program if not elevated.

    Returns:
        bool: True if running with Administrator privileges, False otherwise.
    """
    is_admin = False
    try:
        if sys.platform == "win32":
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin() != 0)
        else:
            is_admin = bool(os.getuid() == 0) if hasattr(os, "getuid") else False
    except Exception as exc:
        is_admin = False

    if not is_admin:
        warning_msg = (
            "\n"
            + "=" * 70
            + "\n"
            + "[!] WARNING: ELEVATION REQUIRED FOR FULL AUDIT CAPABILITIES\n"
            + "    WinSentinel is not currently running as Administrator.\n"
            + "    Windows Security Event Logs (Get-WinEvent), Defender status,\n"
            + "    and password policy auditing require elevated privileges.\n"
            + "    To resolve: Right-click PowerShell or Windows Terminal\n"
            + "    and select 'Run as administrator'.\n"
            + "=" * 70
            + "\n"
        )
        print(warning_msg, file=sys.stderr)
        if not warn_only:
            sys.exit(1)

    return is_admin


def cmd_set_password(args: argparse.Namespace) -> None:
    """
    Prompt the administrator for a new dashboard password and store its secure hash.

    Args:
        args: Parsed command-line arguments.
    """
    print("[*] WinSentinel Administrator Password Setup")
    init_db()

    username = args.username or "admin"
    password = getpass.getpass(prompt=f"Enter new password for '{username}': ")
    if not password:
        print("[-] Error: Password cannot be blank.", file=sys.stderr)
        sys.exit(1)

    password_confirm = getpass.getpass(prompt="Confirm password: ")
    if password != password_confirm:
        print("[-] Error: Passwords do not match.", file=sys.stderr)
        sys.exit(1)

    if len(password) < 12:
        print("[-] Error: Password must be at least 12 characters.", file=sys.stderr)
        sys.exit(1)

    password_hash = generate_password_hash(password, method="scrypt")
    create_or_update_admin(username=username, password_hash=password_hash)
    print(f"[+] Success: Password for user '{username}' updated successfully.")


def cmd_scan(args: argparse.Namespace) -> None:
    """
    Execute a local Windows security audit via the CLI.

    Args:
        args: Parsed command-line arguments.
    """
    is_admin = check_elevation(warn_only=True)
    if is_admin:
        print("[+] Verified: Running with Administrator privileges.")
    else:
        print("[!] Notice: Running without Administrator privileges. Checks may return errors.")

    print("[*] Initializing database and starting local security audit...")
    init_db()
    hostname = os.environ.get("COMPUTERNAME", "localhost")
    scan_id = create_scan(hostname=hostname)
    print(f"[+] Scan #{scan_id} initiated for host: {hostname}")

    from collectors.config_audit import run_config_audit
    from collectors.event_logs import run_event_log_audit
    from collectors.software_inventory import get_installed_software
    from collectors.nvd_client import audit_software_vulnerabilities

    print("[*] Running Windows Configuration Audit...")
    config_findings = run_config_audit(scan_id=scan_id)
    print(f"[+] Configuration audit generated {len(config_findings)} findings.")

    print("[*] Running Windows Event Log Analysis...")
    alerts, log_findings, metrics = run_event_log_audit(scan_id=scan_id, fallback_to_sample=False)
    print(f"[+] Log analysis generated {len(alerts)} alerts and {len(log_findings)} findings.")

    print("[*] Inventorying Installed Software from Registry...")
    software_list = get_installed_software(scan_id=scan_id)
    print(f"[+] Inventoried {len(software_list)} installed applications.")
    insert_software(software_list, db_path=None)

    print("[*] Auditing Allowlisted Applications against NVD...")
    sw_findings, cves = audit_software_vulnerabilities(software_list, scan_id=scan_id)
    print(f"[+] Software vulnerability check generated {len(sw_findings)} findings.")

    all_findings = config_findings + log_findings + sw_findings
    insert_findings(all_findings, db_path=None)
    insert_alerts(alerts, db_path=None)
    insert_scan_metrics(scan_id, metrics)

    from risk.scoring import calculate_posture_score

    # Calculate posture score using centralized NIST SP 800-30 scoring engine
    posture_score = calculate_posture_score(all_findings)
    update_scan_status(scan_id=scan_id, status="completed", posture_score=posture_score)

    failed_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in all_findings:
        if f.status == "fail" and f.severity in failed_counts:
            failed_counts[f.severity] += 1

    print("\n--- Scan Results Summary ---")
    print(f"Posture Score: {posture_score}/100")
    print(f"Critical: {failed_counts['Critical']}, High: {failed_counts['High']}, Medium: {failed_counts['Medium']}, Low: {failed_counts['Low']}")
    print(f"Active Alerts: {len(alerts)}")
    for a in alerts:
        print(f"  ALERT: [{a.severity.upper()}] {a.alert_type} on '{a.account}'")
    for f in all_findings:
        if f.status == "fail":
            print(f"  FINDING: [{f.severity.upper()}] {f.title} (Risk: {f.risk_score})")

    print("\n[*] To launch the interactive dashboard, run: python main.py serve")


def cmd_serve(args: argparse.Namespace) -> None:
    """
    Start the local Flask web dashboard on 127.0.0.1:5000.

    Args:
        args: Parsed command-line arguments.
    """
    init_db()
    if not has_users():
        print(
            "[-] Error: No administrator account configured.\n"
            "    Please set an admin password first using:\n"
            "    python main.py set-password",
            file=sys.stderr,
        )
        sys.exit(1)

    from web.app import create_app
    cfg = get_config()
    if cfg.SECRET_KEY_IS_EPHEMERAL:
        print(
            "[!] SECRET_KEY is not set in .env: using a random key for this run "
            "(you will be logged out on restart). Generate one with:\n"
            "    python -c \"import secrets; print(secrets.token_hex(32))\"",
            file=sys.stderr,
        )
    app = create_app()

    print("=" * 60)
    print(f"[*] Starting {cfg.PROJECT_NAME} Web Dashboard")
    print(f"[*] Access URL: http://{cfg.HOST}:{cfg.PORT}")
    print(f"[*] Binding: {cfg.HOST} (strictly local, no external exposure)")
    print(f"[*] Legal Scope: Local machine read-only audit only.")
    print("=" * 60)

    # Strictly bind to 127.0.0.1 and debug=False per security specifications
    app.run(host=cfg.HOST, port=cfg.PORT, debug=cfg.DEBUG)


def cmd_demo(args: argparse.Namespace) -> None:
    """
    Load demonstration findings and sample events into the database.

    Args:
        args: Parsed command-line arguments.
    """
    print("[*] Loading demonstration data for WinSentinel...")
    init_db()
    hostname = os.environ.get("COMPUTERNAME", "WIN-DEMO-HOST")
    scan_id = create_scan(hostname=hostname)

    now_iso = datetime.now(timezone.utc).isoformat()

    demo_findings = [
        Finding(
            scan_id=scan_id,
            module="config",
            title="SMBv1 Legacy Protocol Enabled",
            evidence="SMB1 server configuration returned EnableSMB1Protocol: True",
            status="fail",
            likelihood=4,
            impact=4,
            risk_score=16,
            severity="Critical",
            remediation="Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        ),
        Finding(
            scan_id=scan_id,
            module="config",
            title="Exposed RDP Port 3389 Without NLA",
            evidence="Listening port 3389 active on 0.0.0.0; UserAuthentication=0",
            status="fail",
            likelihood=3,
            impact=4,
            risk_score=12,
            severity="High",
            remediation="Enable Network Level Authentication (NLA) and restrict RDP firewall rule.",
        ),
        Finding(
            scan_id=scan_id,
            module="config",
            title="Minimum Password Length Below Recommendation",
            evidence="net accounts: Minimum password length = 0",
            status="fail",
            likelihood=3,
            impact=3,
            risk_score=9,
            severity="Medium",
            remediation="Enforce minimum password length >= 12 via 'net accounts /minpwlen:12'.",
        ),
        Finding(
            scan_id=scan_id,
            module="config",
            title="Windows Defender Real-Time Protection",
            evidence="RealTimeProtectionEnabled: True; Signature age: 0 days",
            status="pass",
            likelihood=1,
            impact=1,
            risk_score=0,
            severity="Info",
            remediation="No remediation needed.",
        ),
    ]

    demo_alerts = [
        Alert(
            scan_id=scan_id,
            alert_type="Brute Force Attack",
            timestamp=now_iso,
            account="Administrator",
            source_ip="192.168.1.105",
            count=12,
            severity="High",
            details="12 failed logon attempts (Event 4625) recorded within 4 minutes targeting account 'Administrator'.",
        )
    ]

    demo_software = [
        SoftwareItem(scan_id=scan_id, name="Google Chrome", version="120.0.6099.130", publisher="Google LLC"),
        SoftwareItem(scan_id=scan_id, name="7-Zip", version="23.01", publisher="Igor Pavlov"),
        SoftwareItem(scan_id=scan_id, name="Python 3.12.0", version="3.12.0", publisher="Python Software Foundation"),
    ]

    insert_findings(demo_findings)
    insert_alerts(demo_alerts)
    insert_software(demo_software)

    # Penalties: Critical (15) + High (8) + Medium (3) = 26; Posture Score = 100 - 26 = 74
    update_scan_status(scan_id=scan_id, status="completed", posture_score=74)
    print(f"[+] Demo scan #{scan_id} loaded successfully with Posture Score: 74/100")


def main() -> None:
    """Parse CLI arguments and dispatch to the appropriate subcommand handler."""
    parser = argparse.ArgumentParser(
        prog="WinSentinel",
        description="Windows Security Audit, Log Analysis and Risk Scoring Framework",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: set-password
    sp_setpass = subparsers.add_parser("set-password", help="Set administrator password for web dashboard")
    sp_setpass.add_argument("--username", "-u", default="admin", help="Username to configure (default: admin)")
    sp_setpass.set_defaults(func=cmd_set_password)

    # Command: scan
    sp_scan = subparsers.add_parser("scan", help="Run local Windows security audit")
    sp_scan.set_defaults(func=cmd_scan)

    # Command: serve
    sp_serve = subparsers.add_parser("serve", help="Start Flask dashboard on 127.0.0.1:5000")
    sp_serve.set_defaults(func=cmd_serve)

    # Command: demo
    sp_demo = subparsers.add_parser("demo", help="Load demonstration data and sample findings")
    sp_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
