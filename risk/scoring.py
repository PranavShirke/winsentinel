"""
WinSentinel - Risk Scoring Engine (NIST SP 800-30 Aligned).

Calculates qualitative and quantitative risk metrics for system security findings:
  - Risk Score = Likelihood (1-5) x Impact (1-5), ranging from 1 to 25.
  - Severity Bands:
      * Critical: 16 - 25
      * High:     10 - 15
      * Medium:    5 - 9
      * Low:       1 - 4
      * Info:      Passing checks (score = 0)
      * Error:     Failed command / access denied (score = 0)

Posture Score (0-100):
  100 - (Critical x 15 + High x 8 + Medium x 3 + Low x 1), floored at 0.
"""

from typing import List, Dict, Any, Tuple
from config import get_config
from db.models import Finding


def calculate_risk_score(likelihood: int, impact: int) -> int:
    """
    Calculate the risk score using the NIST SP 800-30 Likelihood x Impact matrix.

    Args:
        likelihood: Threat likelihood rating (1 to 5).
        impact: Consequence impact rating (1 to 5).

    Returns:
        int: Product of likelihood and impact, clamped between 1 and 25.
    """
    clamped_l = max(1, min(5, int(likelihood)))
    clamped_i = max(1, min(5, int(impact)))
    return clamped_l * clamped_i


def get_severity_band(risk_score: int, status: str = "fail") -> str:
    """
    Determine the severity band corresponding to a risk score and check status.

    Args:
        risk_score: Numerical risk score (1-25).
        status: Finding status ('pass', 'fail', or 'error').

    Returns:
        str: Severity level ('Critical', 'High', 'Medium', 'Low', 'Info', 'Error').
    """
    if status == "pass":
        return "Info"
    if status == "error":
        return "Error"

    if risk_score >= 16:
        return "Critical"
    elif risk_score >= 10:
        return "High"
    elif risk_score >= 5:
        return "Medium"
    else:
        return "Low"


def calculate_posture_score(findings: List[Finding]) -> int:
    """
    Calculate the overall system security posture score on a scale of 0 to 100.

    Baseline score is 100. Deductions are assessed for failed findings:
      - Critical: -15 points each
      - High:      -8 points each
      - Medium:    -3 points each
      - Low:       -1 point each
      - Info/Error: 0 points deducted

    The final score is floored at 0 to avoid negative values.

    Args:
        findings: List of Finding instances.

    Returns:
        int: Calculated posture score between 0 and 100.
    """
    cfg = get_config()
    penalties = cfg.POSTURE_PENALTIES

    total_deductions = 0
    for f in findings:
        if f.status == "fail":
            severity = f.severity if f.severity in penalties else get_severity_band(f.risk_score, "fail")
            total_deductions += penalties.get(severity, 0)

    score = 100 - total_deductions
    return max(0, score)


def get_scoring_methodology_doc() -> Dict[str, Any]:
    """
    Return comprehensive documentation of the scoring methodology.

    Used by the dashboard, reports, and academic defense presentations.

    Returns:
        Dict[str, Any]: Methodology summary, formula, and matrix details.
    """
    return {
        "framework": "NIST SP 800-30 Rev. 1 (Guide for Conducting Risk Assessments)",
        "formula": "Risk Score = Likelihood (1-5) x Impact (1-5)",
        "posture_formula": "Posture Score = max(0, 100 - (Crit x 15 + High x 8 + Med x 3 + Low x 1))",
        "severity_bands": {
            "Critical": "16 - 25: Immediate exploitation potential with catastrophic impact.",
            "High": "10 - 15: Significant vulnerability with elevated likelihood of compromise.",
            "Medium": "5 - 9: Moderate risk requiring remediation within standard maintenance cycles.",
            "Low": "1 - 4: Minor deviation from security best practices with limited impact.",
            "Info": "0: Passing audit check indicating compliant configuration.",
            "Error": "0: Incomplete audit check due to insufficient access or missing tool.",
        },
        "penalties": {
            "Critical": 15,
            "High": 8,
            "Medium": 3,
            "Low": 1,
        },
    }
