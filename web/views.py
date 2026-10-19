"""
WinSentinel - Dashboard & API Views Blueprint.

Provides routes for the SOC-style web dashboard:
  - GET /: Main Dashboard overview with summary cards and charts.
  - GET /findings: Filterable table of audit check findings.
  - GET /alerts: Correlated security log incident events.
  - GET /software: Installed software inventory and NVD CVE matches.
  - GET /history: Historical scan timeline and posture trend chart.
  - GET /report: Report preview page.
  - POST /scan/start: Initiates background scan execution.
  - GET /scan/status: Status polling endpoint for the active scan.
  - GET /api/summary: JSON endpoint providing Chart.js dataset feeds.
"""

import os
from typing import Dict, Any, Optional, Tuple, List
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    session,
    Response,
)

from db.database import (
    get_latest_scan,
    get_scan_by_id,
    get_all_scans,
    get_findings_by_scan_id,
    get_alerts_by_scan_id,
    get_software_by_scan_id,
    get_scan_summary_counts,
)
from web.auth import login_required
from web.security import (
    validate_scan_id,
    validate_severity,
    validate_module,
    validate_status,
    sanitize_search_query,
)
from web.scanner import get_scan_manager

views_bp = Blueprint("views", __name__)


def resolve_active_scan(scan_id_arg: Any = None) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """Helper to resolve the target scan record and summary counts."""
    validated_id = validate_scan_id(scan_id_arg)
    if validated_id:
        scan = get_scan_by_id(validated_id)
    else:
        scan = get_latest_scan()

    if scan:
        summary = get_scan_summary_counts(scan["id"])
    else:
        summary = {
            "severity": {},
            "modules": {},
            "failed_findings": 0,
            "active_alerts": 0,
            "software_total": 0,
            "vulnerable_software": 0,
        }

    return scan, summary


@views_bp.context_processor
def inject_global_template_context():
    """Inject hostname, last scan timestamp, and helper variables into all templates."""
    hostname = os.environ.get("COMPUTERNAME", "localhost")
    latest = get_latest_scan()
    last_time = latest["started_at"][:19] if latest and latest.get("started_at") else None
    return {
        "current_hostname": hostname,
        "last_scan_time": last_time,
    }


# -------------------------------------------------------------------------
# Page Routes
# -------------------------------------------------------------------------

@views_bp.route("/")
@login_required
def dashboard():
    """Render the primary SOC security dashboard."""
    scan_id_param = request.args.get("scan_id")
    scan, summary = resolve_active_scan(scan_id_param)

    top_risks = []
    if scan:
        # Fetch top 5 failed findings ordered by risk_score desc
        all_failed = get_findings_by_scan_id(scan["id"], status="fail")
        top_risks = all_failed[:5]

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        scan=scan,
        summary=summary,
        top_risks=top_risks,
    )


@views_bp.route("/findings")
@login_required
def findings():
    """Render the findings table with filtering controls."""
    scan_id_param = request.args.get("scan_id")
    scan, summary = resolve_active_scan(scan_id_param)

    findings_list = []
    selected_severity = validate_severity(request.args.get("severity"))
    selected_module = validate_module(request.args.get("module"))
    selected_status = validate_status(request.args.get("status"))
    selected_search = sanitize_search_query(request.args.get("search"))

    if scan:
        findings_list = get_findings_by_scan_id(
            scan_id=scan["id"],
            severity=selected_severity,
            module=selected_module,
            status=selected_status,
            search=selected_search,
        )

    return render_template(
        "findings.html",
        active_page="findings",
        scan=scan,
        findings=findings_list,
        selected_severity=selected_severity,
        selected_module=selected_module,
        selected_status=selected_status,
        selected_search=selected_search,
    )


@views_bp.route("/alerts")
@login_required
def alerts():
    """Render the security log incident alerts table."""
    scan_id_param = request.args.get("scan_id")
    scan, summary = resolve_active_scan(scan_id_param)

    alerts_list = []
    if scan:
        alerts_list = get_alerts_by_scan_id(scan["id"])

    return render_template(
        "alerts.html",
        active_page="alerts",
        scan=scan,
        alerts=alerts_list,
    )


@views_bp.route("/software")
@login_required
def software():
    """Render installed software and associated CVE findings."""
    scan_id_param = request.args.get("scan_id")
    scan, summary = resolve_active_scan(scan_id_param)

    software_list = []
    cve_findings = []
    if scan:
        software_list = get_software_by_scan_id(scan["id"])
        cve_findings = get_findings_by_scan_id(scan["id"], module="software", status="fail")

    return render_template(
        "software.html",
        active_page="software",
        scan=scan,
        software_list=software_list,
        cve_findings=cve_findings,
    )


@views_bp.route("/history")
@login_required
def history():
    """Render historical scans list and posture trend."""
    scans_list = get_all_scans(limit=50)
    return render_template(
        "history.html",
        active_page="history",
        all_scans=scans_list,
    )


@views_bp.route("/report")
@login_required
def report_preview():
    """Render report summary preview page."""
    scan_id_param = request.args.get("scan_id")
    scan, summary = resolve_active_scan(scan_id_param)
    return render_template(
        "report_preview.html",
        active_page="report",
        scan=scan,
        summary=summary,
    )


@views_bp.route("/report/download")
@login_required
def download_report():
    """Generate and download standalone HTML report (Detailed in Phase 7)."""
    scan_id_param = request.args.get("scan_id")
    scan, summary = resolve_active_scan(scan_id_param)
    if not scan:
        return "No scan available to generate report", 404

    from reports.report_builder import build_html_report
    html_content = build_html_report(scan["id"])
    filename = f"WinSentinel_Audit_Report_{scan['hostname']}_Scan_{scan['id']}.html"

    return Response(
        html_content,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# -------------------------------------------------------------------------
# API Endpoints (Background Scan & JSON Feeds)
# -------------------------------------------------------------------------

@views_bp.route("/scan/start", methods=["POST"])
@login_required
def start_scan():
    """API endpoint to trigger a new background audit scan."""
    mgr = get_scan_manager()
    started, scan_id, msg = mgr.start_scan()
    status_code = 200 if started else 409
    return jsonify({
        "status": "started" if started else "error",
        "scan_id": scan_id,
        "message": msg,
    }), status_code


@views_bp.route("/scan/status")
@login_required
def scan_status():
    """API endpoint to poll the progress of the active scan."""
    mgr = get_scan_manager()
    return jsonify(mgr.get_status())


@views_bp.route("/api/summary")
@login_required
def api_summary():
    """
    JSON API feeding Chart.js datasets without inline script tags.

    Returns:
      - posture_score
      - severity_counts
      - module_counts
      - daily_failures
      - scan_history
      - top_risks
    """
    scan_id_param = request.args.get("scan_id")
    scan, summary = resolve_active_scan(scan_id_param)

    severity_counts = summary.get("severity", {})
    module_counts = summary.get("modules", {})

    # Extract daily failure counts from alerts or event metrics
    daily_failures: Dict[str, int] = {}
    if scan:
        alerts = get_alerts_by_scan_id(scan["id"])
        for a in alerts:
            date_key = a["timestamp"][:10]
            daily_failures[date_key] = daily_failures.get(date_key, 0) + a.get("count", 1)

    all_scans = get_all_scans(limit=15)
    history_records = [
        {
            "id": s["id"],
            "started_at": s["started_at"],
            "posture_score": s["posture_score"],
        }
        for s in all_scans
    ]

    top_risks = []
    if scan:
        failed = get_findings_by_scan_id(scan["id"], status="fail")
        top_risks = [
            {
                "title": f["title"],
                "severity": f["severity"],
                "risk_score": f["risk_score"],
                "module": f["module"],
            }
            for f in failed[:5]
        ]

    return jsonify({
        "scan_id": scan["id"] if scan else None,
        "hostname": scan["hostname"] if scan else os.environ.get("COMPUTERNAME", "localhost"),
        "posture_score": scan["posture_score"] if scan else 100,
        "severity_counts": severity_counts,
        "module_counts": module_counts,
        "daily_failures": daily_failures,
        "scan_history": history_records,
        "top_risks": top_risks,
    })
