"""
Unit tests for Event Log Analysis and Brute-Force Detection Engine.
"""

import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from analysis.bruteforce import parse_event_timestamp, analyze_security_events
from collectors.event_logs import load_events_from_fixture

FIXTURE_PATH = Path(__file__).resolve().parent.parent / "fixtures" / "sample_events.json"


class TestBruteForceAnalysis(unittest.TestCase):
    """Test suite for sliding-window log correlation rules."""

    def test_timestamp_parsing(self):
        """Verify robust parsing of various timestamp formats into UTC datetimes."""
        ts1 = parse_event_timestamp("2026-10-15T02:10:01Z")
        self.assertEqual(ts1.year, 2026)
        self.assertEqual(ts1.month, 10)
        self.assertEqual(ts1.day, 15)
        self.assertEqual(ts1.hour, 2)
        self.assertEqual(ts1.tzinfo, timezone.utc)

        ts2 = parse_event_timestamp("2026-10-15 02:10:01")
        self.assertEqual(ts2.year, 2026)
        self.assertEqual(ts2.tzinfo, timezone.utc)

        # Invalid/empty string fallback
        ts3 = parse_event_timestamp("")
        self.assertIsNotNone(ts3)
        self.assertEqual(ts3.tzinfo, timezone.utc)

    def test_brute_force_below_threshold(self):
        """Verify that fewer than 5 failures does NOT trigger an alert."""
        base_time = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            {
                "id": 4625,
                "time_created": (base_time + timedelta(minutes=i)).isoformat(),
                "target_user_name": "test_user",
                "ip_address": "192.168.1.10",
            }
            for i in range(4)  # Only 4 attempts
        ]

        alerts, findings, metrics = analyze_security_events(events, scan_id=1)
        self.assertEqual(len(alerts), 0)
        self.assertEqual(metrics["failed_logon_count"], 4)
        # Should record an info passing check
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "pass")

    def test_brute_force_at_threshold(self):
        """Verify 5 failed logons within 10 minutes triggers a High alert."""
        base_time = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            {
                "id": 4625,
                "time_created": (base_time + timedelta(minutes=i)).isoformat(),
                "target_user_name": "victim_user",
                "ip_address": "192.168.1.50",
            }
            for i in range(5)  # Exactly 5 attempts
        ]

        alerts, findings, metrics = analyze_security_events(events, scan_id=1)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "Brute Force Attack")
        self.assertEqual(alerts[0].severity, "High")
        self.assertEqual(alerts[0].account, "victim_user")
        self.assertEqual(alerts[0].count, 5)

        # High Finding generated
        failed_findings = [f for f in findings if f.status == "fail"]
        self.assertEqual(len(failed_findings), 1)
        self.assertEqual(failed_findings[0].severity, "High")

    def test_brute_force_window_expiration(self):
        """Verify that 5 failed logons spread over more than 10 minutes do NOT alert."""
        base_time = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
        # 5 attempts spaced 15 minutes apart (total 60 mins)
        events = [
            {
                "id": 4625,
                "time_created": (base_time + timedelta(minutes=i * 15)).isoformat(),
                "target_user_name": "victim_user",
                "ip_address": "192.168.1.50",
            }
            for i in range(5)
        ]

        alerts, findings, metrics = analyze_security_events(events, scan_id=1)
        self.assertEqual(len(alerts), 0)
        self.assertEqual(metrics["failed_logon_count"], 5)

    def test_possible_compromise_detection(self):
        """Verify successful logon following 5 failures produces a Critical alert."""
        base_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            {
                "id": 4625,
                "time_created": (base_time + timedelta(minutes=i)).isoformat(),
                "target_user_name": "compromised_user",
                "ip_address": "10.0.0.99",
            }
            for i in range(5)
        ]
        # Append successful logon event at minute 6
        events.append({
            "id": 4624,
            "time_created": (base_time + timedelta(minutes=6)).isoformat(),
            "target_user_name": "compromised_user",
            "ip_address": "10.0.0.99",
        })

        alerts, findings, metrics = analyze_security_events(events, scan_id=1)
        compromise_alerts = [a for a in alerts if a.alert_type == "Possible Compromise"]
        self.assertEqual(len(compromise_alerts), 1)
        self.assertEqual(compromise_alerts[0].severity, "Critical")
        self.assertEqual(compromise_alerts[0].account, "compromised_user")

        # Critical Finding generated
        crit_findings = [f for f in findings if f.severity == "Critical"]
        self.assertEqual(len(crit_findings), 1)
        self.assertEqual(crit_findings[0].risk_score, 25)

    def test_account_management_events(self):
        """Verify events 4720, 4740, and 4732 produce respective alerts."""
        ts = "2026-10-17T10:00:00Z"
        events = [
            {
                "id": 4720,
                "time_created": ts,
                "target_user_name": "new_user",
                "subject_user_name": "admin",
            },
            {
                "id": 4740,
                "time_created": ts,
                "target_user_name": "locked_user",
            },
            {
                "id": 4732,
                "time_created": ts,
                "target_user_name": "admin_group",
                "member_name": "new_user",
                "group_name": "Administrators",
                "subject_user_name": "admin",
            },
        ]

        alerts, findings, metrics = analyze_security_events(events, scan_id=1)
        alert_types = {a.alert_type: a.severity for a in alerts}
        self.assertEqual(alert_types.get("Account Created"), "Medium")
        self.assertEqual(alert_types.get("Account Lockout"), "Medium")
        self.assertEqual(alert_types.get("Privileged Group Addition"), "High")

    def test_sample_events_fixture_e2e(self):
        """Verify full analysis of sample_events.json fixture."""
        events = load_events_from_fixture(FIXTURE_PATH)
        self.assertGreater(len(events), 10)

        alerts, findings, metrics = analyze_security_events(events, scan_id=99)

        # Verify alerts
        alert_types = [a.alert_type for a in alerts]
        self.assertIn("Brute Force Attack", alert_types)
        self.assertIn("Possible Compromise", alert_types)
        self.assertIn("Account Created", alert_types)
        self.assertIn("Account Lockout", alert_types)
        self.assertIn("Privileged Group Addition", alert_types)

        # Verify daily failures breakdown exists
        self.assertIn("2026-10-15", metrics["daily_failures"])
        self.assertIn("2026-10-16", metrics["daily_failures"])


if __name__ == "__main__":
    unittest.main()
