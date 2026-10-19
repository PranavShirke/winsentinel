"""
WinSentinel - Standalone HTML Report Builder.

Generates a fully self-contained, downloadable HTML compliance audit report
with inlined CSS, @media print rules for clean A4 printing, and complete
sections for executive summary, findings table, incident alerts, software
inventory, and scope/ethics statement.

Usage (from views.py):
    from reports.report_builder import build_html_report
    html = build_html_report(scan_id=1)
"""

from typing import Any, Dict, List, Optional
from db.database import (
    get_scan_by_id,
    get_findings_by_scan_id,
    get_alerts_by_scan_id,
    get_software_by_scan_id,
    get_scan_summary_counts,
)


# ---------------------------------------------------------------------------
# Helper: severity badge colours (inline styles, no external CSS needed)
# ---------------------------------------------------------------------------
_SEVERITY_COLORS: Dict[str, str] = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
    "info": "#64748b",
    "error": "#a78bfa",
}

_SEVERITY_BG: Dict[str, str] = {
    "critical": "rgba(239,68,68,0.15)",
    "high": "rgba(249,115,22,0.15)",
    "medium": "rgba(234,179,8,0.15)",
    "low": "rgba(34,197,94,0.15)",
    "info": "rgba(100,116,139,0.15)",
    "error": "rgba(167,139,250,0.15)",
}


def _badge(text: str) -> str:
    """Return an inline-styled severity badge span for the HTML report."""
    key = text.lower()
    color = _SEVERITY_COLORS.get(key, "#64748b")
    bg = _SEVERITY_BG.get(key, "rgba(100,116,139,0.15)")
    return (
        f'<span style="display:inline-block;padding:2px 8px;font-size:11px;'
        f"font-weight:700;text-transform:uppercase;border-radius:4px;"
        f"background:{bg};color:{color};border:1px solid {color};"
        f'">{text}</span>'
    )


def _score_color(score: Optional[int]) -> str:
    """Return the HEX colour appropriate for a posture score value."""
    if score is None:
        return "#64748b"
    if score >= 80:
        return "#22c55e"
    if score >= 60:
        return "#eab308"
    if score >= 40:
        return "#f97316"
    return "#ef4444"


def _esc(text: Any) -> str:
    """HTML-escape a value to prevent XSS in the rendered report."""
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# Section Builders
# ---------------------------------------------------------------------------

def _build_inline_css() -> str:
    """Return the complete inline CSS stylesheet for the standalone report."""
    return """
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
         margin:0;padding:40px;color:#1e293b;line-height:1.6;font-size:14px;background:#fff;}
    h1{font-size:26px;color:#0f172a;margin:0 0 4px 0;}
    h2{font-size:18px;color:#1e293b;margin:32px 0 12px;border-bottom:2px solid #e2e8f0;padding-bottom:6px;}
    h3{font-size:15px;color:#334155;margin:16px 0 8px;}
    p{margin:6px 0;}
    .report-header{border-bottom:3px solid #3b82f6;padding-bottom:16px;margin-bottom:28px;}
    .report-meta{font-size:13px;color:#64748b;margin-top:6px;}
    .score-block{display:inline-block;font-size:36px;font-weight:800;margin:8px 0;}
    .summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
                  gap:14px;margin:16px 0 28px;}
    .summary-card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;}
    .summary-card .label{font-size:11px;font-weight:600;text-transform:uppercase;
                         letter-spacing:.5px;color:#64748b;}
    .summary-card .value{font-size:28px;font-weight:700;color:#1e293b;margin-top:4px;}
    table{width:100%;border-collapse:collapse;margin:12px 0 24px;font-size:13px;}
    th{background:#f1f5f9;padding:10px 12px;text-align:left;font-size:11px;
       font-weight:700;text-transform:uppercase;letter-spacing:.4px;
       color:#64748b;border-bottom:2px solid #e2e8f0;}
    td{padding:10px 12px;border-bottom:1px solid #f1f5f9;vertical-align:top;}
    tr:hover td{background:#fafafa;}
    .evidence{font-family:ui-monospace,SFMono-Regular,Consolas,"Courier New",monospace;
              background:#f8fafc;border:1px solid #e2e8f0;border-radius:4px;
              padding:8px 10px;font-size:12px;color:#334155;white-space:pre-wrap;
              word-break:break-all;}
    .remediation{background:#eff6ff;border-left:3px solid #3b82f6;
                 padding:8px 12px;border-radius:0 4px 4px 0;
                 font-size:12px;color:#1d4ed8;margin-top:6px;}
    .section-note{background:#f0fdf4;border:1px solid #86efac;border-radius:6px;
                  padding:12px 16px;margin:16px 0;font-size:13px;color:#166534;}
    .ethics-box{background:#fefce8;border:1px solid #fde68a;border-radius:6px;
                padding:14px 16px;margin-top:8px;font-size:13px;color:#92400e;}
    .footer{margin-top:48px;padding-top:16px;border-top:1px solid #e2e8f0;
            font-size:11px;color:#94a3b8;text-align:center;}
    @media print{
      @page{size:A4;margin:15mm;}
      body{margin:0;padding:20px;font-size:12px;}
      h2{page-break-before:always;}
      h1+h2{page-break-before:avoid;}
      table{page-break-inside:auto;}
      tr{page-break-inside:avoid;}
    }
    """


def _build_executive_summary(scan: Dict, summary: Dict) -> str:
    """Build the Executive Summary section of the report."""
    score = scan.get("posture_score")
    score_color = _score_color(score)
    score_display = f"{score}/100" if score is not None else "N/A"
    sev = summary.get("severity", {})

    return f"""
    <h2>Executive Summary</h2>
    <div class="summary-grid">
      <div class="summary-card">
        <div class="label">Posture Score</div>
        <div class="value" style="color:{score_color};">{_esc(score_display)}</div>
      </div>
      <div class="summary-card">
        <div class="label">Failed Findings</div>
        <div class="value">{_esc(summary.get("failed_findings", 0))}</div>
      </div>
      <div class="summary-card">
        <div class="label">Active Alerts</div>
        <div class="value">{_esc(summary.get("active_alerts", 0))}</div>
      </div>
      <div class="summary-card">
        <div class="label">Vulnerable Apps</div>
        <div class="value">{_esc(summary.get("vulnerable_software", 0))} / {_esc(summary.get("software_total", 0))}</div>
      </div>
    </div>
    <table>
      <thead><tr><th>Severity</th><th>Failed Findings Count</th></tr></thead>
      <tbody>
        <tr><td>{_badge("Critical")}</td><td>{_esc(sev.get("Critical", 0))}</td></tr>
        <tr><td>{_badge("High")}</td><td>{_esc(sev.get("High", 0))}</td></tr>
        <tr><td>{_badge("Medium")}</td><td>{_esc(sev.get("Medium", 0))}</td></tr>
        <tr><td>{_badge("Low")}</td><td>{_esc(sev.get("Low", 0))}</td></tr>
        <tr><td>{_badge("Info")}</td><td>{_esc(sev.get("Info", 0))}</td></tr>
      </tbody>
    </table>
    """


def _build_findings_section(findings: List[Dict]) -> str:
    """Build the full Audit Findings section table."""
    if not findings:
        return "<h2>Audit Findings</h2><p>No findings recorded for this scan.</p>"

    rows = ""
    for f in findings:
        status_badge = _badge(f.get("status", "").upper())
        sev_badge = _badge(f.get("severity", "Info"))
        evidence = _esc(f.get("evidence", ""))
        remediation = _esc(f.get("remediation", ""))
        risk = f.get("risk_score", 0)
        likelihood = f.get("likelihood", 0)
        impact = f.get("impact", 0)

        remed_html = ""
        if remediation and f.get("status") != "pass":
            remed_html = f'<div class="remediation"><strong>Remediation:</strong> {remediation}</div>'

        rows += f"""
        <tr>
          <td>{sev_badge}</td>
          <td><strong>{_esc(f.get("title",""))}</strong>
              <div class="evidence">{evidence}</div>
              {remed_html}
          </td>
          <td>{_esc(f.get("module","")).upper()}</td>
          <td><strong>{_esc(risk)}</strong><br><small>L:{_esc(likelihood)} &times; I:{_esc(impact)}</small></td>
          <td>{status_badge}</td>
        </tr>"""

    return f"""
    <h2>Audit Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Finding &amp; Evidence</th>
          <th>Module</th>
          <th>Risk Score</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    """


def _build_alerts_section(alerts: List[Dict]) -> str:
    """Build the Correlated Incident Alerts section table."""
    if not alerts:
        return "<h2>Incident Alerts</h2><p>No correlated security alerts detected in this scan.</p>"

    rows = ""
    for a in alerts:
        sev_badge = _badge(a.get("severity", "Info"))
        rows += f"""
        <tr>
          <td style="font-size:12px;">{_esc(str(a.get("timestamp",""))[:19])}</td>
          <td><strong>{_esc(a.get("alert_type",""))}</strong></td>
          <td><code>{_esc(a.get("account",""))}</code></td>
          <td><code>{_esc(a.get("source_ip",""))}</code></td>
          <td><strong>{_esc(a.get("count", 0))}</strong></td>
          <td>{sev_badge}</td>
          <td style="font-size:12px;">{_esc(a.get("details",""))}</td>
        </tr>"""

    return f"""
    <h2>Incident Alerts</h2>
    <table>
      <thead>
        <tr>
          <th>Timestamp</th><th>Incident Type</th><th>Account</th>
          <th>Source IP</th><th>Attempts</th><th>Severity</th><th>Details</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    """


def _build_software_section(software: List[Dict]) -> str:
    """Build the Software Inventory section table."""
    if not software:
        return "<h2>Software Inventory</h2><p>No software inventory data recorded for this scan.</p>"

    rows = ""
    for s in software:
        cve_flag = ""
        if s.get("cve_ids"):
            cve_ids = _esc(s["cve_ids"])
            cve_flag = f'<br><small style="color:#ef4444;">CVEs: {cve_ids}</small>'

        rows += f"""
        <tr>
          <td>{_esc(s.get("name",""))}</td>
          <td>{_esc(s.get("version",""))}{cve_flag}</td>
          <td>{_esc(s.get("publisher",""))}</td>
          <td>{"Yes" if s.get("cve_ids") else "—"}</td>
        </tr>"""

    return f"""
    <h2>Software Inventory</h2>
    <table>
      <thead>
        <tr><th>Application</th><th>Version</th><th>Publisher</th><th>CVE Flags</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    """


# ---------------------------------------------------------------------------
# Main Report Builder
# ---------------------------------------------------------------------------

def build_html_report(scan_id: int) -> str:
    """
    Construct a complete, fully self-contained standalone HTML audit report.

    The report includes:
      - Report header with host, scan ID, timestamp
      - Executive summary with posture score, severity breakdown card grid
      - Full findings table with evidence and remediation steps
      - Correlated incident alerts table
      - Software inventory with CVE flags
      - Scope / ethics statement

    All data is HTML-escaped. No external CSS, JS, or font requests are made
    (complies with the strict CSP and local-only requirements).

    Args:
        scan_id: Primary key of the scan to report on.

    Returns:
        str: Complete standalone HTML document as a UTF-8 string.
    """
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "<html><body><h1>Error: Scan Not Found</h1></body></html>"

    findings = get_findings_by_scan_id(scan_id)
    alerts = get_alerts_by_scan_id(scan_id)
    software = get_software_by_scan_id(scan_id)
    summary = get_scan_summary_counts(scan_id)

    hostname = _esc(scan.get("hostname", "Unknown"))
    started = _esc(str(scan.get("started_at", ""))[:19])
    score = scan.get("posture_score")
    score_display = f"{score}/100" if score is not None else "N/A"
    score_color = _score_color(score)
    css = _build_inline_css()

    exec_summary_html = _build_executive_summary(scan, summary)
    findings_html = _build_findings_section(findings)
    alerts_html = _build_alerts_section(alerts)
    software_html = _build_software_section(software)

    total_checks = len(findings)
    failed_checks = sum(1 for f in findings if (f.get("status") or "") == "fail")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WinSentinel Audit Report - {hostname} (Scan #{_esc(scan_id)})</title>
  <style>{css}</style>
</head>
<body>

  <!-- Report Header -->
  <div class="report-header">
    <h1>WinSentinel Security Audit &amp; Compliance Report</h1>
    <div class="report-meta">
      <strong>Target Host:</strong> {hostname} &nbsp;|&nbsp;
      <strong>Scan ID:</strong> #{_esc(scan_id)} &nbsp;|&nbsp;
      <strong>Generated:</strong> {started} &nbsp;|&nbsp;
      <strong>Posture Score:</strong>
      <span class="score-block" style="font-size:18px;color:{score_color};">{_esc(score_display)}</span>
    </div>
    <div class="report-meta" style="margin-top:4px;">
      <strong>Total Checks:</strong> {_esc(total_checks)} &nbsp;|&nbsp;
      <strong>Failed:</strong> {_esc(failed_checks)} &nbsp;|&nbsp;
      <strong>Alerts:</strong> {_esc(len(alerts))} &nbsp;|&nbsp;
      <strong>Software Inventoried:</strong> {_esc(len(software))}
    </div>
  </div>

  {exec_summary_html}
  {findings_html}
  {alerts_html}
  {software_html}

  <!-- Scope & Ethics Statement -->
  <h2>Scope &amp; Legal Ethics Statement</h2>
  <div class="ethics-box">
    <strong>Authorized Scope:</strong> This security audit was performed exclusively on the
    local host (<code>127.0.0.1</code> / <code>{hostname}</code>) under authorized,
    read-only conditions. No network exploitation, active directory modification,
    or automated remediation was performed. All checks are passive and non-destructive.
    <br><br>
    <strong>Academic Notice:</strong> This report was generated by WinSentinel as part of
    an academic cybersecurity project covering VAPT, Security Information Management,
    and Application Security.
  </div>

  <div class="footer">
    WinSentinel v1.0 &mdash; Windows Security Audit, Log Analysis &amp; Risk Scoring Framework &mdash;
    Scan #{_esc(scan_id)} &mdash; Host: {hostname}
  </div>

</body>
</html>"""
