"""
Unit tests for Risk Scoring Engine, Posture Calculation, and Remediation Mapping.
"""

import unittest
from db.models import Finding
from risk.scoring import (
    calculate_risk_score,
    get_severity_band,
    calculate_posture_score,
    get_scoring_methodology_doc,
)
from risk.remediation import get_remediation_guide


class TestRiskScoring(unittest.TestCase):
    """Test suite for NIST SP 800-30 risk scoring calculations."""

    def test_risk_score_matrix(self):
        """Verify Likelihood x Impact multiplication and clamping."""
        self.assertEqual(calculate_risk_score(1, 1), 1)
        self.assertEqual(calculate_risk_score(5, 5), 25)
        self.assertEqual(calculate_risk_score(4, 3), 12)
        self.assertEqual(calculate_risk_score(3, 4), 12)
        # Clamping
        self.assertEqual(calculate_risk_score(0, 0), 1)
        self.assertEqual(calculate_risk_score(10, 10), 25)

    def test_severity_bands(self):
        """Verify NIST SP 800-30 severity band boundaries."""
        self.assertEqual(get_severity_band(1), "Low")
        self.assertEqual(get_severity_band(4), "Low")
        self.assertEqual(get_severity_band(5), "Medium")
        self.assertEqual(get_severity_band(9), "Medium")
        self.assertEqual(get_severity_band(10), "High")
        self.assertEqual(get_severity_band(15), "High")
        self.assertEqual(get_severity_band(16), "Critical")
        self.assertEqual(get_severity_band(25), "Critical")

        # Passing and Error statuses
        self.assertEqual(get_severity_band(20, status="pass"), "Info")
        self.assertEqual(get_severity_band(20, status="error"), "Error")

    def test_posture_score_baseline(self):
        """Verify 100 baseline score when all checks pass."""
        findings = [
            Finding(title="Pass 1", module="config", evidence="ok", status="pass", severity="Info"),
            Finding(title="Pass 2", module="logs", evidence="ok", status="pass", severity="Info"),
            Finding(title="Pass 3", module="software", evidence="ok", status="pass", severity="Info"),
        ]
        score = calculate_posture_score(findings)
        self.assertEqual(score, 100)

    def test_posture_score_penalties(self):
        """Verify individual deductions: Critical (-15), High (-8), Medium (-3), Low (-1)."""
        # 1 Critical failure: 100 - 15 = 85
        f_crit = [Finding(title="Crit", module="config", evidence="fail", status="fail", severity="Critical")]
        self.assertEqual(calculate_posture_score(f_crit), 85)

        # 1 High failure: 100 - 8 = 92
        f_high = [Finding(title="High", module="config", evidence="fail", status="fail", severity="High")]
        self.assertEqual(calculate_posture_score(f_high), 92)

        # 1 Medium failure: 100 - 3 = 97
        f_med = [Finding(title="Med", module="config", evidence="fail", status="fail", severity="Medium")]
        self.assertEqual(calculate_posture_score(f_med), 97)

        # 1 Low failure: 100 - 1 = 99
        f_low = [Finding(title="Low", module="config", evidence="fail", status="fail", severity="Low")]
        self.assertEqual(calculate_posture_score(f_low), 99)

    def test_posture_score_combined_and_floor(self):
        """Verify combination penalties and flooring at 0."""
        # Combination: 1 Critical (15) + 2 High (16) + 1 Medium (3) + 2 Low (2) = 36 deductions -> 64
        findings = [
            Finding(title="C1", module="config", evidence="", status="fail", severity="Critical"),
            Finding(title="H1", module="config", evidence="", status="fail", severity="High"),
            Finding(title="H2", module="config", evidence="", status="fail", severity="High"),
            Finding(title="M1", module="config", evidence="", status="fail", severity="Medium"),
            Finding(title="L1", module="config", evidence="", status="fail", severity="Low"),
            Finding(title="L2", module="config", evidence="", status="fail", severity="Low"),
            Finding(title="Pass", module="config", evidence="", status="pass", severity="Info"),
            Finding(title="Err", module="config", evidence="", status="error", severity="Error"),
        ]
        self.assertEqual(calculate_posture_score(findings), 64)

        # Massive penalties floored at 0
        extreme_findings = [
            Finding(title=f"Crit {i}", module="config", evidence="", status="fail", severity="Critical")
            for i in range(10)  # 10 x 15 = 150 points
        ]
        self.assertEqual(calculate_posture_score(extreme_findings), 0)

    def test_remediation_lookup(self):
        """Verify remediation guides return commands and guidance."""
        f_pw = Finding(
            title="Weak Minimum Password Length Policy",
            module="config",
            evidence="",
            status="fail",
            severity="Medium",
        )
        guide_pw = get_remediation_guide(f_pw)
        self.assertIn("minpwlen:12", guide_pw["command"])

        f_port = Finding(
            title="Risky Listening Port 445 Exposed (SMB)",
            module="config",
            evidence="",
            status="fail",
            severity="High",
        )
        guide_port = get_remediation_guide(f_port)
        self.assertIn("445", guide_port["command"])

        f_cve = Finding(
            title="Vulnerability Detected: Google Chrome",
            module="software",
            evidence="",
            status="fail",
            severity="Critical",
        )
        guide_cve = get_remediation_guide(f_cve)
        self.assertIn("winget", guide_cve["command"])

    def test_methodology_doc(self):
        """Verify scoring methodology metadata structure."""
        doc = get_scoring_methodology_doc()
        self.assertIn("NIST SP 800-30", doc["framework"])
        self.assertIn("Critical", doc["severity_bands"])
        self.assertEqual(doc["penalties"]["Critical"], 15)


if __name__ == "__main__":
    unittest.main()
