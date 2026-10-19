"""
WinSentinel - Sample Events Loader Script.

Loads normalized security events from fixtures/sample_events.json,
runs the brute-force correlation analysis engine, and stores the resulting
alerts and findings into the SQLite database.
Enables offline and lab testing of detection capabilities without requiring live attacks.
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from db.database import (
    init_db,
    create_scan,
    update_scan_status,
    insert_findings,
    insert_alerts,
)
from collectors.event_logs import load_events_from_fixture
from analysis.bruteforce import analyze_security_events


def load_and_analyze_sample_events(scan_id: int = None) -> int:
    """
    Load sample events from fixture and inject resulting alerts and findings.

    Args:
        scan_id: Optional scan ID. If None, creates a new scan.

    Returns:
        int: The scan ID populated with events and alerts.
    """
    init_db()
    if scan_id is None:
        hostname = os.environ.get("COMPUTERNAME", "WIN-LAB-SAMPLE")
        scan_id = create_scan(hostname=hostname)

    events = load_events_from_fixture()
    print(f"[*] Loaded {len(events)} events from fixtures/sample_events.json")

    alerts, findings, metrics = analyze_security_events(events, scan_id=scan_id)
    print(f"[+] Detected {len(alerts)} security alerts and generated {len(findings)} findings.")

    for alert in alerts:
        print(f"    - [{alert.severity.upper()}] {alert.alert_type} on '{alert.account}' (Count: {alert.count})")

    insert_alerts(alerts)
    insert_findings(findings)

    # Calculate posture score deduction: Critical: 15, High: 8, Medium: 3, Low: 1
    penalties = 0
    for f in findings:
        if f.status == "fail":
            if f.severity == "Critical":
                penalties += 15
            elif f.severity == "High":
                penalties += 8
            elif f.severity == "Medium":
                penalties += 3
            elif f.severity == "Low":
                penalties += 1

    posture_score = max(0, 100 - penalties)
    update_scan_status(scan_id=scan_id, status="completed", posture_score=posture_score)
    print(f"[+] Scan #{scan_id} updated. Posture Score: {posture_score}/100")
    return scan_id


if __name__ == "__main__":
    load_and_analyze_sample_events()
