"""
Unit tests for Configuration Audit Collector Parsers and Evaluators.
Tests run against static fixtures without requiring live Windows commands.
"""

import os
import unittest
from pathlib import Path
from collections import namedtuple

from collectors.config_audit import (
    parse_net_accounts,
    evaluate_password_policy,
    parse_net_user_list,
    parse_net_user_detail,
    parse_net_localgroup_administrators,
    evaluate_user_accounts,
    parse_firewall_profiles,
    evaluate_firewall_profiles,
    parse_defender_status,
    evaluate_defender_status,
    parse_smb_config,
    evaluate_smb_protocol,
    parse_rdp_registry,
    evaluate_rdp_exposure,
    parse_listening_ports,
    evaluate_listening_ports,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "sample_command_outputs"

# Mock namedtuple for psutil socket connection
MockAddr = namedtuple("MockAddr", ["ip", "port"])
MockConn = namedtuple("MockConn", ["status", "laddr", "pid"])


class TestConfigParsers(unittest.TestCase):
    """Test suite for configuration parsers and rule evaluations."""

    def test_net_accounts_insecure(self):
        """Verify parsing of insecure password policy output."""
        fixture_path = FIXTURES_DIR / "net_accounts_insecure.txt"
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = f.read()

        policy = parse_net_accounts(raw)
        self.assertEqual(policy["min_pw_len"], 0)
        self.assertEqual(policy["lockout_threshold"], 0)
        self.assertEqual(policy["pw_history_len"], 0)

        findings = evaluate_password_policy(policy, scan_id=1)
        # Should fail minimum length, lockout threshold, and history
        failed = [f for f in findings if f.status == "fail"]
        self.assertEqual(len(failed), 3)

        severities = {f.title: f.severity for f in failed}
        self.assertEqual(severities["Weak Minimum Password Length Policy"], "Medium")
        self.assertEqual(severities["Account Lockout Threshold Disabled"], "High")

    def test_net_accounts_secure(self):
        """Verify parsing of hardened password policy output."""
        fixture_path = FIXTURES_DIR / "net_accounts_secure.txt"
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = f.read()

        policy = parse_net_accounts(raw)
        self.assertEqual(policy["min_pw_len"], 14)
        self.assertEqual(policy["lockout_threshold"], 5)
        self.assertEqual(policy["pw_history_len"], 10)

        findings = evaluate_password_policy(policy, scan_id=1)
        failed = [f for f in findings if f.status == "fail"]
        self.assertEqual(len(failed), 0)
        self.assertTrue(all(f.status == "pass" for f in findings))

    def test_net_user_list(self):
        """Verify parsing user accounts list."""
        fixture_path = FIXTURES_DIR / "net_user_list.txt"
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = f.read()

        users = parse_net_user_list(raw)
        self.assertIn("Administrator", users)
        self.assertIn("Guest", users)
        self.assertIn("Pranav", users)
        self.assertIn("DevUser", users)

    def test_guest_account_active(self):
        """Verify active guest account triggers Critical finding."""
        fixture_path = FIXTURES_DIR / "net_user_guest_active.txt"
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = f.read()

        details = parse_net_user_detail(raw)
        self.assertTrue(details["active"])

        findings = evaluate_user_accounts(details, ["Administrator"], scan_id=1)
        guest_findings = [f for f in findings if "Guest" in f.title]
        self.assertEqual(len(guest_findings), 1)
        self.assertEqual(guest_findings[0].status, "fail")
        self.assertEqual(guest_findings[0].severity, "Critical")
        self.assertEqual(guest_findings[0].risk_score, 16)

    def test_guest_account_disabled(self):
        """Verify disabled guest account passes audit."""
        fixture_path = FIXTURES_DIR / "net_user_guest_disabled.txt"
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = f.read()

        details = parse_net_user_detail(raw)
        self.assertFalse(details["active"])

        findings = evaluate_user_accounts(details, ["Administrator"], scan_id=1)
        guest_findings = [f for f in findings if "Guest" in f.title]
        self.assertEqual(len(guest_findings), 1)
        self.assertEqual(guest_findings[0].status, "pass")
        self.assertEqual(guest_findings[0].severity, "Info")

    def test_localgroup_administrators(self):
        """Verify parsing administrators group members."""
        fixture_path = FIXTURES_DIR / "net_localgroup_admins.txt"
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = f.read()

        admins = parse_net_localgroup_administrators(raw)
        self.assertEqual(len(admins), 3)
        self.assertIn("Administrator", admins)
        self.assertIn("Pranav", admins)

    def test_firewall_profiles_all_on(self):
        """Verify all firewall profiles ON passes audit."""
        fixture_path = FIXTURES_DIR / "firewall_all_on.txt"
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = f.read()

        profiles = parse_firewall_profiles(raw)
        self.assertEqual(profiles["Domain"], "ON")
        self.assertEqual(profiles["Private"], "ON")
        self.assertEqual(profiles["Public"], "ON")

        findings = evaluate_firewall_profiles(profiles, scan_id=1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "pass")

    def test_firewall_profiles_public_off(self):
        """Verify disabled public firewall profile produces Critical finding."""
        fixture_path = FIXTURES_DIR / "firewall_public_off.txt"
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = f.read()

        profiles = parse_firewall_profiles(raw)
        self.assertEqual(profiles["Public"], "OFF")

        findings = evaluate_firewall_profiles(profiles, scan_id=1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "fail")
        self.assertEqual(findings[0].severity, "Critical")
        self.assertEqual(findings[0].risk_score, 16)

    def test_defender_status_healthy(self):
        """Verify active Defender with fresh signatures passes."""
        fixture_path = FIXTURES_DIR / "defender_healthy.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = f.read()

        status = parse_defender_status(raw)
        self.assertTrue(status["realtime_enabled"])
        self.assertEqual(status["signature_age_days"], 0)

        findings = evaluate_defender_status(status, scan_id=1)
        self.assertTrue(all(f.status == "pass" for f in findings))

    def test_defender_status_disabled_and_stale(self):
        """Verify disabled real-time protection and stale signatures are flagged."""
        fixture_path = FIXTURES_DIR / "defender_disabled.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = f.read()

        status = parse_defender_status(raw)
        self.assertFalse(status["realtime_enabled"])
        self.assertEqual(status["signature_age_days"], 14)

        findings = evaluate_defender_status(status, scan_id=1)
        failed = [f for f in findings if f.status == "fail"]
        self.assertEqual(len(failed), 2)

        severities = [f.severity for f in failed]
        self.assertIn("Critical", severities)  # Real-time protection disabled
        self.assertIn("High", severities)  # Signatures 14 days old

    def test_smb1_protocol_enabled(self):
        """Verify SMB1 enabled produces Critical finding."""
        fixture_path = FIXTURES_DIR / "smb_legacy_enabled.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = f.read()

        smb_cfg = parse_smb_config(raw)
        self.assertTrue(smb_cfg["smb1_enabled"])

        findings = evaluate_smb_protocol(smb_cfg, scan_id=1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "fail")
        self.assertEqual(findings[0].severity, "Critical")
        self.assertEqual(findings[0].risk_score, 20)

    def test_smb1_protocol_disabled(self):
        """Verify SMB1 disabled passes check."""
        fixture_path = FIXTURES_DIR / "smb_legacy_disabled.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            raw = f.read()

        smb_cfg = parse_smb_config(raw)
        self.assertFalse(smb_cfg["smb1_enabled"])

        findings = evaluate_smb_protocol(smb_cfg, scan_id=1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "pass")

    def test_rdp_exposure_scenarios(self):
        """Verify RDP disabled, enabled without NLA, and enabled with NLA."""
        # 1. RDP Disabled
        rdp_off = parse_rdp_registry(f_deny_ts=1, user_auth=0)
        findings_off = evaluate_rdp_exposure(rdp_off, scan_id=1)
        self.assertEqual(findings_off[0].status, "pass")

        # 2. RDP Enabled without NLA (Critical)
        rdp_insecure = parse_rdp_registry(f_deny_ts=0, user_auth=0)
        findings_insecure = evaluate_rdp_exposure(rdp_insecure, scan_id=1)
        self.assertEqual(findings_insecure[0].status, "fail")
        self.assertEqual(findings_insecure[0].severity, "Critical")
        self.assertEqual(findings_insecure[0].risk_score, 16)

        # 3. RDP Enabled with NLA (Pass)
        rdp_secure = parse_rdp_registry(f_deny_ts=0, user_auth=1)
        findings_secure = evaluate_rdp_exposure(rdp_secure, scan_id=1)
        self.assertEqual(findings_secure[0].status, "pass")

    def test_listening_ports(self):
        """Verify psutil listening port analysis flags high-risk ports."""
        risky_map = {
            23: "Telnet",
            445: "SMB over TCP",
            3389: "RDP",
        }
        mock_conns = [
            MockConn(status="LISTEN", laddr=MockAddr("0.0.0.0", 23), pid=100),
            MockConn(status="LISTEN", laddr=MockAddr("0.0.0.0", 445), pid=4),
            MockConn(status="LISTEN", laddr=MockAddr("127.0.0.1", 8080), pid=500),  # Not in risky map
            MockConn(status="ESTABLISHED", laddr=MockAddr("192.168.1.5", 445), pid=4),  # Not LISTEN
        ]

        flagged = parse_listening_ports(mock_conns, risky_map)
        self.assertEqual(len(flagged), 2)
        ports_flagged = [item["port"] for item in flagged]
        self.assertIn(23, ports_flagged)
        self.assertIn(445, ports_flagged)
        self.assertNotIn(8080, ports_flagged)

        findings = evaluate_listening_ports(flagged, scan_id=1)
        self.assertEqual(len(findings), 2)
        severities = {f.title: f.severity for f in findings}
        self.assertTrue(any("23" in title and sev == "Critical" for title, sev in severities.items()))
        self.assertTrue(any("445" in title and sev == "High" for title, sev in severities.items()))


if __name__ == "__main__":
    unittest.main()
