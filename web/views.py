"""
WinSentinel - Dashboard & API Views Blueprint.

Provides routes for the SOC-style web dashboard:
  - GET /: Main Dashboard overview with summary cards and charts.
  - GET /findings: Filterable table of audit check findings.
  - GET /alerts: Correlated security log incident events.
  - GET /software: Installed software inventory and NVD CVE matches.
  - GET /history: Historical scan timeline and posture trend chart.
  - GET /report: Report preview page.
  - GET /compare: Drift view between two scans (new / resolved / persisting findings).
  - GET /findings/export.csv: CSV export of a scan's findings.
  - POST /scan/start: Initiates background scan execution.
  - GET /scan/status: Status polling endpoint for the active scan.
  - GET /api/summary: JSON endpoint providing Chart.js dataset feeds.
"""

import csv
import hashlib
import io
import os
import re
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
    get_latest_completed_scan,
    get_scan_metrics,
    compare_scans,
    get_scan_by_id,
    get_all_scans,
    get_findings_by_scan_id,
    get_alerts_by_scan_id,
    get_software_by_scan_id,
    get_scan_summary_counts,
)
from db.database import (
    REGISTER_STATUSES,
    find_report_hash,
    get_live_alerts,
    get_recent_report_hashes,
    record_report_hash,
    set_finding_status,
)
from reports.report_data import (
    EXCLUDED_FROM_ADJUSTED,
    adjusted_posture_score,
    enrich_findings,
    register_counts,
)
from risk.frameworks import map_frameworks
from web.auth import login_required
from web.security import (
    validate_scan_id,
    validate_severity,
    validate_module,
    validate_status,
    validate_register,
    sanitize_search_query,
)
from web.scanner import get_scan_manager
from web.monitor import monitor_status
from collectors.privileges import is_elevated

views_bp = Blueprint("views", __name__)


def resolve_active_scan(scan_id_arg: Any = None) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """Helper to resolve the target scan record and summary counts."""
    validated_id = validate_scan_id(scan_id_arg)
    if validated_id:
        scan = get_scan_by_id(validated_id)
    else:
        scan = get_latest_completed_scan()

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
    latest = get_latest_completed_scan()
    last_time = latest["started_at"][:19].replace("T", " ") if latest and latest.get("started_at") else None
    from web.scheduler import get_scheduler
    sched = get_scheduler()
    return {
        "current_hostname": hostname,
        "last_scan_time": last_time,
        "is_elevated": is_elevated(),
        "auto_scan_minutes": sched.interval_seconds // 60 if sched else 0,
        "auto_scan_next": int(sched.next_run) if sched and sched.next_run else 0,
    }


# -------------------------------------------------------------------------
# Page Routes
# -------------------------------------------------------------------------

@views_bp.route("/")
def welcome():
    """Render the public product landing page before administrator login."""
    return render_template("welcome.html")


@views_bp.route("/dashboard")
@login_required
def dashboard():
    """Render the primary SOC security dashboard."""
    scan_id_param = request.args.get("scan_id")
    scan, summary = resolve_active_scan(scan_id_param)

    top_risks = []
    adjusted_score = None
    score_delta = None
    register = {"open": 0, "in_progress": 0, "accepted": 0, "false_positive": 0}
    if scan:
        previous = [s for s in get_all_scans(limit=50)
                    if s["status"] == "completed" and s["id"] < scan["id"] and s["posture_score"] is not None]
        if previous and scan.get("posture_score") is not None:
            score_delta = scan["posture_score"] - previous[0]["posture_score"]
        enriched = enrich_findings(get_findings_by_scan_id(scan["id"]))
        adjusted_score = adjusted_posture_score(enriched)
        register = register_counts(enriched)
        # Top 5 risks still needing action (decided-away items are excluded)
        top_risks = [
            f for f in enriched
            if f["status"] == "fail" and f["register_status"] not in EXCLUDED_FROM_ADJUSTED
        ][:5]

    return render_template(
        "dashboard.html",
        active_page="dashboard",
        scan=scan,
        summary=summary,
        top_risks=top_risks,
        adjusted_score=adjusted_score,
        score_delta=score_delta,
        register=register,
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
    selected_register = validate_register(request.args.get("register"))

    if scan:
        findings_list = enrich_findings(get_findings_by_scan_id(
            scan_id=scan["id"],
            severity=selected_severity,
            module=selected_module,
            status=selected_status,
            search=selected_search,
        ))
        if selected_register:
            findings_list = [f for f in findings_list if f["register_status"] == selected_register]

    return render_template(
        "findings.html",
        active_page="findings",
        scan=scan,
        findings=findings_list,
        selected_severity=selected_severity,
        selected_module=selected_module,
        selected_status=selected_status,
        selected_search=selected_search,
        selected_register=selected_register,
    )


@views_bp.route("/alerts")
@login_required
def alerts():
    """Render the security log incident alerts table."""
    scan_id_param = request.args.get("scan_id")
    scan, summary = resolve_active_scan(scan_id_param)

    alerts_list = []
    if scan:
        alerts_list = [dict(a, frameworks=map_frameworks(a["alert_type"])) for a in get_alerts_by_scan_id(scan["id"])]

    live_alerts = [dict(a, frameworks=map_frameworks(a["alert_type"])) for a in get_live_alerts(limit=50)]

    return render_template(
        "alerts.html",
        active_page="alerts",
        scan=scan,
        alerts=alerts_list,
        live_alerts=live_alerts,
        monitor=monitor_status(),
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


def _serve_report(content: bytes, mimetype: str, filename: str, kind: str, scan_id: int) -> Response:
    """
    Send a report file and remember its SHA-256 so the file can be verified later.

    The digest is also returned in the X-Report-SHA256 header.
    """
    digest = hashlib.sha256(content).hexdigest()
    record_report_hash(digest, scan_id, kind, len(content), created_by=session.get("username", ""))
    return Response(
        content,
        mimetype=mimetype,
        headers={"Content-Disposition": f"attachment; filename={filename}", "X-Report-SHA256": digest},
    )


@views_bp.route("/report/verify", methods=["GET", "POST"])
@login_required
def verify_report():
    """
    Check whether a report file is byte-for-byte one that WinSentinel produced.

    The uploaded file is hashed (SHA-256) and looked up among the hashes recorded when reports were
    downloaded. A match proves the file was not modified since; no match means it was altered or
    came from elsewhere. The upload is never stored or executed.
    """
    result = None
    if request.method == "POST":
        upload = request.files.get("report")
        if not upload or not upload.filename:
            result = {"state": "error", "message": "Choose a report file to verify."}
        else:
            data = upload.read()
            digest = hashlib.sha256(data).hexdigest()
            record = find_report_hash(digest)
            result = {"state": "match" if record else "nomatch", "sha256": digest, "record": record, "size": len(data)}
    return render_template("verify.html", active_page="report", result=result, recent=get_recent_report_hashes())


@views_bp.route("/report/download")
@login_required
def download_report():
    """Generate and download standalone HTML report (Detailed in Phase 7)."""
    scan_id_param = request.args.get("scan_id")
    scan, summary = resolve_active_scan(scan_id_param)
    if not scan:
        return "No scan available to generate report", 404

    from reports.report_builder import build_html_report
    html_bytes = build_html_report(scan["id"]).encode("utf-8")
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", scan["hostname"])[:40]  # no header injection
    filename = f"WinSentinel_Audit_Report_{safe_host}_Scan_{scan['id']}.html"
    return _serve_report(html_bytes, "text/html", filename, "html", scan["id"])


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection (=, +, -, @) in exported text cells."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", chr(9), chr(13)):
        return "'" + value
    return value


@views_bp.route("/findings/export.csv")
@login_required
def export_findings_csv():
    """Download all findings of a scan as CSV for spreadsheets and ticketing tools."""
    scan, _ = resolve_active_scan(request.args.get("scan_id"))
    if not scan:
        return "No scan available to export", 404

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["scan_id", "module", "severity", "status", "risk_score", "likelihood", "impact", "title", "evidence", "remediation"])
    for f in get_findings_by_scan_id(scan["id"]):
        writer.writerow([_csv_safe(v) for v in (
            scan["id"], f["module"], f["severity"], f["status"], f["risk_score"],
            f["likelihood"], f["impact"], f["title"], f["evidence"], f["remediation"],
        )])
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=WinSentinel_Findings_Scan_{scan['id']}.csv"},
    )


@views_bp.route("/compare")
@login_required
def compare():
    """Show what changed between two scans: new, resolved and persisting findings."""
    completed = [s for s in get_all_scans(limit=50) if s["status"] == "completed"]
    new_id = validate_scan_id(request.args.get("new"))
    old_id = validate_scan_id(request.args.get("old"))
    valid_ids = {s["id"] for s in completed}

    if new_id not in valid_ids:
        new_id = completed[0]["id"] if completed else None
    if old_id not in valid_ids or old_id == new_id:
        older = [s["id"] for s in completed if new_id and s["id"] < new_id]
        old_id = older[0] if older else None

    diff = compare_scans(old_id, new_id) if old_id and new_id else None
    scans_by_id = {s["id"]: s for s in completed}
    return render_template(
        "compare.html",
        active_page="compare",
        completed_scans=completed,
        old_scan=scans_by_id.get(old_id),
        new_scan=scans_by_id.get(new_id),
        diff=diff,
    )


@views_bp.route("/frameworks")
@login_required
def frameworks():
    """Show how this scan's findings map onto MITRE ATT&CK techniques and CIS Controls v8 safeguards."""
    scan, _ = resolve_active_scan(request.args.get("scan_id"))
    attack: Dict[str, Dict[str, Any]] = {}
    cis: Dict[str, Dict[str, Any]] = {}
    rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2}

    def add(bucket, tag, finding):
        row = bucket.setdefault(tag["id"], {"id": tag["id"], "name": tag["name"], "failed": [], "passed": 0, "worst": ""})
        if finding["status"] == "fail":
            row["failed"].append(finding["title"])
            if rank.get(finding["severity"], 0) > rank.get(row["worst"], 0):
                row["worst"] = finding["severity"]
        elif finding["status"] == "pass":
            row["passed"] += 1

    if scan:
        for f in enrich_findings(get_findings_by_scan_id(scan["id"])):
            if f["register_status"] in EXCLUDED_FROM_ADJUSTED:
                continue
            for tag in f["frameworks"]["attack"]:
                add(attack, tag, f)
            for tag in f["frameworks"]["cis"]:
                add(cis, tag, f)

    def ordered(bucket):
        return sorted(bucket.values(), key=lambda r: (-rank.get(r["worst"], 0), -len(r["failed"]), r["id"]))

    return render_template(
        "frameworks.html",
        active_page="frameworks",
        scan=scan,
        attack=ordered(attack),
        cis=ordered(cis),
    )


@views_bp.route("/api/log-analytics")
@login_required
def api_log_analytics():
    """Chart data for the Security-log analytics panel (top accounts / IPs, logon types, hourly failures)."""
    scan, _ = resolve_active_scan(request.args.get("scan_id"))
    metrics = get_scan_metrics(scan["id"]) if scan else {}

    def pairs(d):
        return [{"name": k, "count": v} for k, v in (d or {}).items()]

    failed_types = metrics.get("failed_by_logon_type", {})
    success_types = metrics.get("success_by_logon_type", {})
    labels = sorted(set(failed_types) | set(success_types))
    return jsonify({
        "available": bool(metrics.get("total_events_analyzed")),
        "totals": {k: metrics.get(k, 0) for k in
                   ("total_events_analyzed", "failed_logon_count", "successful_logon_count", "privileged_logon_count")},
        "top_accounts": pairs(metrics.get("top_failed_accounts")),
        "top_ips": pairs(metrics.get("top_failed_ips")),
        "logon_types": [{"name": n, "failed": failed_types.get(n, 0), "success": success_types.get(n, 0)} for n in labels],
        "hourly": pairs(metrics.get("hourly_failures")),
    })


@views_bp.route("/api/live/status")
@login_required
def api_live_status():
    """
    Live-monitor status plus any live alerts newer than `since_id` (polled by the browser every ~20s).
    """
    since_id = validate_scan_id(request.args.get("since_id")) or 0
    alerts = get_live_alerts(since_id=since_id, limit=20)
    return jsonify({
        "monitor": monitor_status(),
        "elevated": is_elevated(),
        "alerts": [
            {"id": a["id"], "type": a["alert_type"], "severity": a["severity"], "account": a["account"],
             "source_ip": a["source_ip"], "count": a["count"], "details": a["details"], "timestamp": a["timestamp"]}
            for a in alerts
        ],
        "max_id": max([a["id"] for a in alerts], default=since_id),
    })


@views_bp.route("/api/search")
@login_required
def api_search():
    """Command-palette search: findings of the active scan matching a short text query."""
    scan, _ = resolve_active_scan(request.args.get("scan_id"))
    query = sanitize_search_query(request.args.get("q"), max_len=60)
    if not scan or not query:
        return jsonify({"results": []})
    rows = get_findings_by_scan_id(scan["id"], search=query)[:8]
    return jsonify({"results": [
        {"title": r["title"], "severity": r["severity"], "module": r["module"], "status": r["status"]} for r in rows
    ]})


@views_bp.route("/report/download.pdf")
@login_required
def download_report_pdf():
    """Generate and download the A4 PDF report for a scan."""
    scan, _ = resolve_active_scan(request.args.get("scan_id"))
    if not scan:
        return "No scan available to generate report", 404

    from reports.pdf_report import build_pdf_report
    pdf = build_pdf_report(scan["id"])
    safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", scan["hostname"])[:40]
    filename = f"WinSentinel_Audit_Report_{safe_host}_Scan_{scan['id']}.pdf"
    return _serve_report(pdf, "application/pdf", filename, "pdf", scan["id"])


# -------------------------------------------------------------------------
# API Endpoints (Background Scan & JSON Feeds)
# -------------------------------------------------------------------------

@views_bp.route("/api/findings/status", methods=["POST"])
@login_required
def update_finding_status():
    """
    Record a risk-register decision for a finding (accept, mark false positive, in progress, reopen).

    Expects JSON: {scan_id, module, title, status, note}. The finding must exist in the given scan,
    and accepted / false_positive decisions require a justification of at least 8 characters.
    """
    payload = request.get_json(silent=True) or {}
    scan_id = validate_scan_id(payload.get("scan_id"))
    module = validate_module(payload.get("module"))
    title = payload.get("title")
    status = validate_register(payload.get("status"))
    note = str(payload.get("note") or "").strip()[:500]

    if not (scan_id and module and status and isinstance(title, str)):
        return jsonify({"status": "error", "message": "Invalid request."}), 400
    if status not in REGISTER_STATUSES:
        return jsonify({"status": "error", "message": "Invalid status."}), 400
    known = {f["title"] for f in get_findings_by_scan_id(scan_id, module=module)}
    if title not in known:
        return jsonify({"status": "error", "message": "Finding not found in this scan."}), 404
    if status in EXCLUDED_FROM_ADJUSTED and len(note) < 8:
        return jsonify({"status": "error", "message": "Please give a justification (at least 8 characters)."}), 422

    set_finding_status(module, title, status, note, updated_by=session.get("username", ""))
    findings = enrich_findings(get_findings_by_scan_id(scan_id))
    return jsonify({
        "status": "ok",
        "register_status": status,
        "adjusted_score": adjusted_posture_score(findings),
        "register": register_counts(findings),
    })


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

    # Real per-day 4625 counts saved by the log analysis step of this scan
    daily_failures: Dict[str, int] = {}
    if scan:
        daily_failures = get_scan_metrics(scan["id"]).get("daily_failures", {})

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

    adjusted = None
    register = {}
    if scan:
        enriched = enrich_findings(get_findings_by_scan_id(scan["id"]))
        adjusted = adjusted_posture_score(enriched)
        register = register_counts(enriched)

    return jsonify({
        "adjusted_score": adjusted,
        "register": register,
        "scan_id": scan["id"] if scan else None,
        "hostname": scan["hostname"] if scan else os.environ.get("COMPUTERNAME", "localhost"),
        "posture_score": scan["posture_score"] if scan else None,
        "severity_counts": severity_counts,
        "module_counts": module_counts,
        "daily_failures": daily_failures,
        "scan_history": history_records,
        "top_risks": top_risks,
    })
