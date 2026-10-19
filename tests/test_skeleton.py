"""
Unit tests for Phase 1 Skeleton: Database, Models, and Configuration.
"""

import os
import tempfile
import unittest
from werkzeug.security import generate_password_hash, check_password_hash

from config import get_config
from db.models import Finding, Alert, SoftwareItem, Scan
from db.database import (
    init_db,
    create_or_update_admin,
    get_user_by_username,
    has_users,
    create_scan,
    update_scan_status,
    insert_findings,
    insert_alerts,
    insert_software,
    get_latest_scan,
    get_findings_by_scan_id,
    get_alerts_by_scan_id,
    get_software_by_scan_id,
    get_scan_summary_counts,
    insert_cached_cve,
    get_cached_cves,
)


class TestSkeleton(TestCase := unittest.TestCase):
    """Test suite for database schema, models, and helpers."""

    def setUp(self):
        """Set up temporary database for testing."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_db.name
        self.temp_db.close()
        init_db(self.db_path)

    def tearDown(self):
        """Clean up temporary database file."""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_config_defaults(self):
        """Verify essential configuration constants."""
        cfg = get_config()
        self.assertEqual(cfg.PROJECT_NAME, "WinSentinel")
        self.assertFalse(cfg.DEBUG)
        self.assertEqual(cfg.HOST, "127.0.0.1")
        self.assertEqual(cfg.PORT, 5000)
        self.assertEqual(cfg.BRUTE_FORCE_FAILURE_THRESHOLD, 5)
        self.assertIn("Critical", cfg.POSTURE_PENALTIES)

    def test_user_creation_and_auth(self):
        """Verify admin user creation and password hashing."""
        self.assertFalse(has_users(self.db_path))
        hashed = generate_password_hash("SuperSecret123!", method="scrypt")
        create_or_update_admin("admin", hashed, self.db_path)
        self.assertTrue(has_users(self.db_path))

        user = get_user_by_username("admin", self.db_path)
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "admin")
        self.assertTrue(check_password_hash(user["password_hash"], "SuperSecret123!"))

    def test_scan_lifecycle(self):
        """Verify scan creation, finding insertion, alert insertion, and summaries."""
        scan_id = create_scan("TEST-PC", self.db_path)
        self.assertIsInstance(scan_id, int)

        finding = Finding(
            scan_id=scan_id,
            module="config",
            title="SMBv1 Enabled",
            evidence="EnableSMB1Protocol: True",
            status="fail",
            likelihood=4,
            impact=4,
            risk_score=16,
            severity="Critical",
            remediation="Disable SMBv1",
        )
        insert_findings([finding], self.db_path)

        alert = Alert(
            scan_id=scan_id,
            alert_type="Brute Force Attack",
            timestamp="2026-10-19T00:00:00Z",
            account="admin",
            source_ip="10.0.0.5",
            count=6,
            severity="High",
            details="6 failed logon attempts",
        )
        insert_alerts([alert], self.db_path)

        software = SoftwareItem(
            scan_id=scan_id,
            name="Google Chrome",
            version="120.0",
            publisher="Google LLC",
        )
        insert_software([software], self.db_path)

        update_scan_status(scan_id, "completed", posture_score=85, db_path=self.db_path)

        latest = get_latest_scan(self.db_path)
        self.assertEqual(latest["id"], scan_id)
        self.assertEqual(latest["posture_score"], 85)
        self.assertEqual(latest["status"], "completed")

        findings = get_findings_by_scan_id(scan_id, db_path=self.db_path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "SMBv1 Enabled")

        alerts = get_alerts_by_scan_id(scan_id, db_path=self.db_path)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "Brute Force Attack")

        sw = get_software_by_scan_id(scan_id, db_path=self.db_path)
        self.assertEqual(len(sw), 1)
        self.assertEqual(sw[0]["name"], "Google Chrome")

        summary = get_scan_summary_counts(scan_id, db_path=self.db_path)
        self.assertEqual(summary["failed_findings"], 1)
        self.assertEqual(summary["active_alerts"], 1)
        self.assertEqual(summary["software_total"], 1)

    def test_cve_cache(self):
        """Verify CVE caching and retrieval."""
        insert_cached_cve("chrome", "120.0", "CVE-2023-9999", 8.8, "Test CVE", self.db_path)
        cached = get_cached_cves("chrome", "120.0", max_age_hours=24, db_path=self.db_path)
        self.assertEqual(len(cached), 1)
        self.assertEqual(cached[0]["cve_id"], "CVE-2023-9999")
        self.assertEqual(cached[0]["cvss_score"], 8.8)


if __name__ == "__main__":
    unittest.main()
