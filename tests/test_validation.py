"""
Unit and Integration tests for Web Security, Input Validation, Auth Throttling, and CSRF.
"""

import unittest
import tempfile
import os
import json
from werkzeug.security import generate_password_hash

from config import get_config
from db.database import init_db, create_or_update_admin, create_scan, update_scan_status
from web.app import create_app
from web.security import (
    validate_scan_id,
    validate_severity,
    validate_module,
    validate_status,
    sanitize_search_query,
)
from web.auth import record_failed_attempt, is_locked_out, clear_failed_attempts


class TestWebSecurityAndValidation(unittest.TestCase):
    """Test suite for web security hardening, headers, validation, and auth."""

    def setUp(self):
        """Set up test Flask app and temporary database."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_db.name
        self.temp_db.close()

        # Override config DB_PATH for tests
        cfg = get_config()
        self.orig_db_path = cfg.DB_PATH
        cfg.DB_PATH = self.db_path
        init_db(self.db_path)

        # Seed admin user
        hashed = generate_password_hash("AdminPass123!", method="scrypt")
        create_or_update_admin("admin", hashed, self.db_path)

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        """Clean up temporary database and restore config."""
        cfg = get_config()
        cfg.DB_PATH = self.orig_db_path
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_input_validation_helpers(self):
        """Verify strict allowlist and range validation for query parameters."""
        # Scan ID
        self.assertEqual(validate_scan_id(1), 1)
        self.assertEqual(validate_scan_id("42"), 42)
        self.assertIsNone(validate_scan_id(-5))
        self.assertIsNone(validate_scan_id("abc"))
        self.assertIsNone(validate_scan_id(None))

        # Severity
        self.assertEqual(validate_severity("critical"), "Critical")
        self.assertEqual(validate_severity("HIGH"), "High")
        self.assertIsNone(validate_severity("super_critical"))
        self.assertIsNone(validate_severity(None))

        # Module
        self.assertEqual(validate_module("CONFIG"), "config")
        self.assertEqual(validate_module("logs"), "logs")
        self.assertIsNone(validate_module("kernel"))

        # Status
        self.assertEqual(validate_status("FAIL"), "fail")
        self.assertEqual(validate_status("pass"), "pass")
        self.assertIsNone(validate_status("unknown"))

        # Search Query sanitization
        self.assertEqual(sanitize_search_query("  password  "), "password")
        long_str = "A" * 150
        self.assertEqual(len(sanitize_search_query(long_str, max_len=100)), 100)

    def test_security_headers_enforced(self):
        """Verify security headers on all outgoing responses."""
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)

        # CSP
        csp = resp.headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)

        # X-Frame-Options
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

        # X-Content-Type-Options
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")

        # Referrer-Policy
        self.assertEqual(resp.headers.get("Referrer-Policy"), "no-referrer")

    def test_unauthenticated_redirect(self):
        """Verify protected views require authentication."""
        resp = self.client.get("/dashboard")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers["Location"])

    def test_login_throttling(self):
        """Verify 5 failed attempts locks login for 5 minutes."""
        test_ip = "192.0.2.1"
        clear_failed_attempts(test_ip)

        for i in range(4):
            count, locked = record_failed_attempt(test_ip)
            self.assertFalse(locked)
            self.assertEqual(count, i + 1)

        # 5th attempt must lock
        count, locked = record_failed_attempt(test_ip)
        self.assertTrue(locked)
        self.assertEqual(count, 5)

        is_locked, remaining = is_locked_out(test_ip)
        self.assertTrue(is_locked)
        self.assertGreater(remaining, 0)
        clear_failed_attempts(test_ip)

    def test_csrf_protection_on_post(self):
        """Verify that POST mutating requests without CSRF token are blocked."""
        # Simulated logged-in session
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"

        # POST without CSRF token
        resp = self.client.post("/scan/start", data={})
        self.assertEqual(resp.status_code, 400)

    def test_authenticated_api_summary(self):
        """Verify GET /api/summary returns valid JSON feed for Chart.js."""
        scan_id = create_scan("TEST-HOST", self.db_path)
        update_scan_status(scan_id, "completed", posture_score=88, db_path=self.db_path)

        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"

        resp = self.client.get(f"/api/summary?scan_id={scan_id}")
        self.assertEqual(resp.status_code, 200)

        data = json.loads(resp.data)
        self.assertEqual(data["scan_id"], scan_id)
        self.assertEqual(data["posture_score"], 88)
        self.assertIn("severity_counts", data)
        self.assertIn("module_counts", data)
        self.assertIn("daily_failures", data)


if __name__ == "__main__":
    unittest.main()
