"""
WinSentinel - Report data assembler.

Builds the enriched data set (findings with risk-register status and framework tags, alerts
with ATT&CK tags, adjusted posture score) shared by the dashboard, the HTML report and the
PDF report so all three always agree.
"""

from typing import Any, Dict, List, Optional

from config import get_config
from db.database import (
    finding_fingerprint,
    get_alerts_by_scan_id,
    get_finding_statuses,
    get_findings_by_scan_id,
    get_scan_by_id,
    get_scan_summary_counts,
    get_software_by_scan_id,
)
from risk.frameworks import map_frameworks

# Register states that remove a finding from the "adjusted" score (decision recorded with a note)
EXCLUDED_FROM_ADJUSTED = ("accepted", "false_positive")


def enrich_findings(findings: List[Dict[str, Any]], statuses: Optional[Dict[str, Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """
    Attach register status/note and ATT&CK + CIS tags to finding dicts (returns new dicts).

    Args:
        findings: Rows from get_findings_by_scan_id.
        statuses: Register decisions (loaded if omitted).
    """
    statuses = statuses if statuses is not None else get_finding_statuses()
    enriched = []
    for f in findings:
        decision = statuses.get(finding_fingerprint(f["module"], f["title"]), {})
        item = dict(f)
        item["register_status"] = decision.get("status", "open")
        item["register_note"] = decision.get("note", "")
        item["register_by"] = decision.get("updated_by", "")
        item["register_at"] = (decision.get("updated_at") or "")[:19].replace("T", " ")
        item["frameworks"] = map_frameworks(f["title"])
        enriched.append(item)
    return enriched


def adjusted_posture_score(findings: List[Dict[str, Any]]) -> int:
    """
    Posture score if accepted risks and false positives are excluded.

    Uses the same penalties as the raw score (Critical 15, High 8, Medium 3, Low 1).

    Args:
        findings: Enriched findings (must contain register_status).
    """
    penalties = get_config().POSTURE_PENALTIES
    total = sum(
        penalties.get(f["severity"], 0)
        for f in findings
        if f["status"] == "fail" and f.get("register_status", "open") not in EXCLUDED_FROM_ADJUSTED
    )
    return max(0, 100 - total)


def register_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Count failed findings per register state (open, in_progress, accepted, false_positive)."""
    counts = {"open": 0, "in_progress": 0, "accepted": 0, "false_positive": 0}
    for f in findings:
        if f["status"] == "fail":
            counts[f.get("register_status", "open")] += 1
    return counts


def collect_report_data(scan_id: int) -> Optional[Dict[str, Any]]:
    """
    Gather everything a report needs for one scan.

    Returns:
        None if the scan does not exist, otherwise a dict with scan, summary, findings,
        alerts (with frameworks), software, adjusted_score and register counts.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        return None
    findings = enrich_findings(get_findings_by_scan_id(scan_id))
    alerts = []
    for a in get_alerts_by_scan_id(scan_id):
        item = dict(a)
        item["frameworks"] = map_frameworks(a["alert_type"])
        alerts.append(item)
    return {
        "scan": scan,
        "summary": get_scan_summary_counts(scan_id),
        "findings": findings,
        "alerts": alerts,
        "software": get_software_by_scan_id(scan_id),
        "adjusted_score": adjusted_posture_score(findings),
        "register": register_counts(findings),
    }
