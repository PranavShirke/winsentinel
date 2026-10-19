"""
Unit tests for Software Inventory Enumeration and NVD Vulnerability Auditing.
"""

import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock

from db.models import SoftwareItem
from db.database import init_db, insert_cached_cve, get_cached_cves
from collectors.software_inventory import (
    clean_version_string,
    match_allowed_software,
    get_installed_software,
)
from collectors.nvd_client import (
    map_cvss_to_impact,
    map_product_to_likelihood,
    calculate_cve_severity,
    NvdClient,
    audit_software_vulnerabilities,
)


class TestSoftwareAndNvd(unittest.TestCase):
    """Test suite for software inventory matching and NVD scoring."""

    def setUp(self):
        """Initialize temporary database for cache tests."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_db.name
        self.temp_db.close()
        init_db(self.db_path)

    def tearDown(self):
        """Clean up temporary database."""
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_clean_version_string(self):
        """Verify version string cleanup."""
        self.assertEqual(clean_version_string("  120.0.1  "), "120.0.1")
        self.assertEqual(clean_version_string(""), "Unknown")
        self.assertEqual(clean_version_string(None), "Unknown")

    def test_allowlist_matching(self):
        """Verify allowlist accurately filters target software."""
        software_list = [
            SoftwareItem(name="Google Chrome", version="120.0.6099.130"),
            SoftwareItem(name="Mozilla Firefox (x64 en-US)", version="118.0"),
            SoftwareItem(name="7-Zip 23.01 (x64)", version="23.01"),
            SoftwareItem(name="Docker Desktop", version="4.25.0"),  # Not in allowlist
            SoftwareItem(name="Git", version="2.42.0"),  # Not in allowlist
        ]

        matched = match_allowed_software(software_list)
        matched_names = [item.name for item, kw in matched]

        self.assertIn("Google Chrome", matched_names)
        self.assertIn("Mozilla Firefox (x64 en-US)", matched_names)
        self.assertIn("7-Zip 23.01 (x64)", matched_names)
        self.assertNotIn("Docker Desktop", matched_names)
        self.assertNotIn("Git", matched_names)

    def test_cvss_to_impact_mapping(self):
        """Verify CVSS score to NIST impact conversion."""
        self.assertEqual(map_cvss_to_impact(9.8), 5)  # Critical
        self.assertEqual(map_cvss_to_impact(9.0), 5)
        self.assertEqual(map_cvss_to_impact(8.5), 4)  # Significant
        self.assertEqual(map_cvss_to_impact(7.0), 4)
        self.assertEqual(map_cvss_to_impact(6.5), 3)  # Moderate
        self.assertEqual(map_cvss_to_impact(4.0), 3)
        self.assertEqual(map_cvss_to_impact(3.5), 2)  # Minor
        self.assertEqual(map_cvss_to_impact(0.0), 2)

    def test_product_likelihood_mapping(self):
        """Verify product attack exposure likelihood."""
        self.assertEqual(map_product_to_likelihood("google chrome"), 4)  # Browser
        self.assertEqual(map_product_to_likelihood("mozilla firefox"), 4)  # Browser
        self.assertEqual(map_product_to_likelihood("7-zip"), 3)  # Archive handler
        self.assertEqual(map_product_to_likelihood("vlc media player"), 3)  # Media parser
        self.assertEqual(map_product_to_likelihood("python"), 2)  # Dev runtime
        self.assertEqual(map_product_to_likelihood("notepad++"), 2)  # Editor

    def test_severity_calculation(self):
        """Verify Risk Score to severity band mapping."""
        # Browser with CVSS 9.8 -> Likelihood 4 x Impact 5 = Risk 20 -> Critical
        self.assertEqual(calculate_cve_severity(20), "Critical")
        # 7-Zip with CVSS 7.8 -> Likelihood 3 x Impact 4 = Risk 12 -> High
        self.assertEqual(calculate_cve_severity(12), "High")
        # Python with CVSS 5.0 -> Likelihood 2 x Impact 3 = Risk 6 -> Medium
        self.assertEqual(calculate_cve_severity(6), "Medium")
        # Minor -> Risk 4 -> Low
        self.assertEqual(calculate_cve_severity(4), "Low")

    def test_nvd_cache_hit_avoids_network(self):
        """Verify that cached CVEs return immediately without outbound HTTP calls."""
        insert_cached_cve(
            product="7-zip",
            version="23.01",
            cve_id="CVE-2023-TEST",
            cvss_score=8.5,
            description="Cached test vulnerability",
            db_path=self.db_path,
        )

        client = NvdClient(delay_seconds=0.0)
        # Mock requests.get to assert it is never called
        with patch("requests.get") as mock_get:
            success, cves, msg = client.query_cves("7-zip", "23.01", db_path=self.db_path)
            self.assertTrue(success)
            self.assertEqual(len(cves), 1)
            self.assertEqual(cves[0]["cve_id"], "CVE-2023-TEST")
            self.assertIn("cache", msg.lower())
            mock_get.assert_not_called()

    def test_offline_mode_graceful_handling(self):
        """Verify offline mode skips network and yields structured error findings."""
        software_list = [SoftwareItem(name="7-Zip", version="19.00")]
        findings, cves = audit_software_vulnerabilities(
            software_list=software_list,
            scan_id=1,
            offline_mode=True,
            db_path=self.db_path,
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "error")
        self.assertIn("Offline Mode", findings[0].title)

    def test_live_registry_enumeration(self):
        """Verify Windows Registry enumeration returns non-empty list on host."""
        software = get_installed_software(scan_id=1)
        # On Windows host, this will discover installed software
        self.assertIsInstance(software, list)
        self.assertGreater(len(software), 0)


if __name__ == "__main__":
    unittest.main()
