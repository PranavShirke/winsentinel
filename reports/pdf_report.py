"""
WinSentinel - PDF Report Builder (reportlab).

Produces an A4 compliance report: cover and executive summary, methodology, findings by
severity with remediation and ATT&CK / CIS tags, risk-register decisions, incident alerts,
vulnerable software, limitations and the scope / ethics statement.
"""

import io
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from reports.report_data import collect_report_data
from risk.scoring import get_scoring_methodology_doc

INK = colors.HexColor("#0b0f15")
TEAL = colors.HexColor("#0e8f8d")
GRID = colors.HexColor("#c9d2dd")
SEV_COLORS = {
    "Critical": colors.HexColor("#d92d3f"),
    "High": colors.HexColor("#e06a1b"),
    "Medium": colors.HexColor("#b8860b"),
    "Low": colors.HexColor("#2f9e5b"),
    "Info": colors.HexColor("#64748b"),
    "Error": colors.HexColor("#7c5cd6"),
}
REGISTER_LABELS = {"open": "Open", "in_progress": "In progress", "accepted": "Accepted risk", "false_positive": "False positive"}

LIMITATIONS = [
    "WinSentinel audits only the local machine and is strictly read-only: it never changes settings or exploits anything.",
    "Several checks (Security event log, BitLocker, some policy values) need Administrator rights; without them they are reported as errors, never as passes.",
    "CVE matching covers an allow-list of well-known products. NVD data is matched by exact CPE product name and published version range; products absent from NVD or lacking version data can produce false negatives.",
    "Software versions come from the Windows registry and may be coarse; confirm any flagged CVE against the vendor advisory before acting.",
    "ATT&CK and CIS Controls tags are rule-based guidance for triage, not a formal benchmark assessment.",
    "The posture score is a prioritisation aid (100 minus severity penalties), not a certification.",
]


def _styles() -> Dict[str, ParagraphStyle]:
    """Create the paragraph styles used throughout the PDF."""
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontSize=24, leading=28, textColor=INK, alignment=TA_LEFT, spaceAfter=4),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontSize=15, textColor=TEAL, spaceBefore=14, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=11.5, textColor=INK, spaceBefore=8, spaceAfter=3),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontSize=9, leading=12.5),
        "small": ParagraphStyle("s", parent=base["BodyText"], fontSize=7.8, leading=10.5, textColor=colors.HexColor("#3a4656")),
        "cell": ParagraphStyle("c", parent=base["BodyText"], fontSize=8.2, leading=10.6),
        "mono": ParagraphStyle("m", parent=base["Code"], fontSize=7.4, leading=9.6, textColor=colors.HexColor("#27313f")),
    }


def _p(text: Any, style: ParagraphStyle) -> Paragraph:
    """Paragraph with user/scan text XML-escaped (reportlab parses markup)."""
    return Paragraph(escape(str(text if text is not None else "")), style)


def _table(rows: List[List[Any]], widths: List[float], header: bool = True) -> Table:
    """Create a consistently styled table."""
    tbl = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, GRID),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eef5")), ("TEXTCOLOR", (0, 0), (-1, 0), INK)]
    tbl.setStyle(TableStyle(style))
    return tbl


def _sev_cell(sev: str, st: Dict[str, ParagraphStyle]) -> Paragraph:
    """Severity label coloured by band (text is always present)."""
    color = SEV_COLORS.get(sev, colors.grey).hexval()[2:]
    return Paragraph(f'<font color="#{color}"><b>{escape(sev.upper())}</b></font>', st["cell"])


def _tags(frameworks: Dict[str, List[Dict[str, str]]]) -> str:
    """Compact 'ATT&CK T1110 | CIS 5.2' tag line."""
    parts = []
    if frameworks.get("attack"):
        parts.append("ATT&CK " + ", ".join(t["id"] for t in frameworks["attack"]))
    if frameworks.get("cis"):
        parts.append("CIS v8 " + ", ".join(t["id"] for t in frameworks["cis"]))
    return "  |  ".join(parts)


def _footer(canvas, doc) -> None:
    """Page footer with scope notice and page number."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(18 * mm, 10 * mm, "WinSentinel  |  Read-only local audit  |  Confidential")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf_report(scan_id: int) -> Optional[bytes]:
    """
    Build the PDF report for a scan.

    Args:
        scan_id: Scan primary key.

    Returns:
        PDF bytes, or None if the scan does not exist.
    """
    data = collect_report_data(scan_id)
    if data is None:
        return None
    scan, summary = data["scan"], data["summary"]
    findings, alerts, software = data["findings"], data["alerts"], data["software"]
    st = _styles()
    width = A4[0] - 36 * mm
    story: List[Any] = []

    # ---- Cover and executive summary
    score = scan.get("posture_score")
    story += [
        Paragraph("WinSentinel", ParagraphStyle("k", fontSize=10, textColor=TEAL, spaceAfter=2)),
        Paragraph("Security Audit &amp; Risk Report", st["title"]),
        _p(f"Host {scan['hostname']}  |  Scan #{scan_id}  |  {str(scan['started_at'])[:19].replace('T', ' ')} UTC", st["body"]),
        Spacer(1, 8),
    ]
    sev = summary.get("severity", {})
    kpis = [[
        _p("POSTURE SCORE", st["small"]), _p("ADJUSTED SCORE", st["small"]),
        _p("FAILED CHECKS", st["small"]), _p("ALERTS", st["small"]), _p("VULNERABLE APPS", st["small"]),
    ], [
        Paragraph(f"<b>{score if score is not None else 'N/A'}</b>/100", ParagraphStyle("kv", fontSize=17, leading=20)),
        Paragraph(f"<b>{data['adjusted_score']}</b>/100", ParagraphStyle("kv2", fontSize=17, leading=20)),
        Paragraph(f"<b>{summary['failed_findings']}</b>", ParagraphStyle("kv3", fontSize=17, leading=20)),
        Paragraph(f"<b>{summary['active_alerts']}</b>", ParagraphStyle("kv4", fontSize=17, leading=20)),
        Paragraph(f"<b>{summary['vulnerable_software']}</b>", ParagraphStyle("kv5", fontSize=17, leading=20)),
    ]]
    story.append(_table(kpis, [width / 5] * 5, header=False))
    story.append(Spacer(1, 6))
    story.append(_p(
        f"Failed findings by severity: Critical {sev.get('Critical', 0)}, High {sev.get('High', 0)}, "
        f"Medium {sev.get('Medium', 0)}, Low {sev.get('Low', 0)}. Adjusted score excludes risks formally "
        f"accepted ({data['register']['accepted']}) or marked false positive ({data['register']['false_positive']}) in the risk register.",
        st["body"],
    ))

    # ---- Scope
    story += [
        Paragraph("Scope and ethics", st["h1"]),
        _p("This audit ran only on the local host, in read-only mode. No remote scanning, exploitation, "
           "Active Directory changes or automated remediation was performed.", st["body"]),
    ]

    # ---- Methodology
    method = get_scoring_methodology_doc()
    story += [
        Paragraph("Methodology", st["h1"]),
        _p(f"Framework: {method['framework']}.", st["body"]),
        _p(f"Finding risk: {method['formula']}.", st["body"]),
        _p(f"Posture: {method['posture_formula']}.", st["body"]),
        Spacer(1, 4),
        _table(
            [[_p("Band", st["cell"]), _p("Meaning", st["cell"])]] +
            [[_sev_cell(k, st), _p(v, st["cell"])] for k, v in method["severity_bands"].items()],
            [28 * mm, width - 28 * mm],
        ),
    ]

    # ---- Findings
    failed = [f for f in findings if f["status"] == "fail"]
    story.append(Paragraph(f"Findings requiring action ({len(failed)})", st["h1"]))
    if not failed:
        story.append(_p("No failed findings.", st["body"]))
    for f in failed:
        block = [
            Paragraph(f'{escape(f["title"])}', st["h2"]),
            _table([[
                _sev_cell(f["severity"], st),
                _p(f"Risk {f['risk_score']} (L{f['likelihood']} x I{f['impact']})", st["cell"]),
                _p(f["module"].upper(), st["cell"]),
                _p(REGISTER_LABELS.get(f["register_status"], "Open"), st["cell"]),
            ]], [28 * mm, 38 * mm, 26 * mm, width - 92 * mm], header=False),
            Spacer(1, 2),
            _p("Evidence: " + f["evidence"], st["mono"]),
            _p("Remediation: " + f["remediation"], st["body"]),
        ]
        tags = _tags(f["frameworks"])
        if tags:
            block.append(_p(tags, st["small"]))
        if f["register_status"] != "open":
            block.append(_p(f"Register: {REGISTER_LABELS[f['register_status']]} by {f['register_by'] or 'n/a'} on "
                            f"{f['register_at']}. Note: {f['register_note']}", st["small"]))
        story.append(KeepTogether(block))

    # ---- Alerts
    story.append(Paragraph(f"Security event alerts ({len(alerts)})", st["h1"]))
    if not alerts:
        story.append(_p("No brute-force or privileged-activity patterns detected (or the Security log was not readable, "
                        "see the event-log finding).", st["body"]))
    else:
        rows = [[_p(h, st["cell"]) for h in ("Time", "Severity", "Incident", "Account", "Source", "Events", "ATT&CK")]]
        for a in alerts:
            rows.append([
                _p(str(a["timestamp"])[:19].replace("T", " "), st["cell"]), _sev_cell(a["severity"], st),
                _p(a["alert_type"], st["cell"]), _p(a["account"], st["cell"]), _p(a["source_ip"], st["cell"]),
                _p(a["count"], st["cell"]), _p(", ".join(t["id"] for t in a["frameworks"]["attack"]), st["cell"]),
            ])
        story.append(_table(rows, [30 * mm, 20 * mm, 32 * mm, 26 * mm, 24 * mm, 12 * mm, width - 144 * mm]))

    # ---- Software
    cve = [f for f in findings if f["module"] == "software" and f["status"] == "fail"]
    story.append(Paragraph(f"Vulnerable software ({len(cve)} of {len(software)} inventoried)", st["h1"]))
    if cve:
        story.append(_table(
            [[_p("Severity", st["cell"]), _p("Finding", st["cell"]), _p("Risk", st["cell"])]] +
            [[_sev_cell(f["severity"], st), _p(f["title"], st["cell"]), _p(f["risk_score"], st["cell"])] for f in cve],
            [24 * mm, width - 38 * mm, 14 * mm],
        ))
    else:
        story.append(_p("No allow-listed application has a known CVE affecting its installed version.", st["body"]))

    # ---- Limitations and appendix
    story.append(Paragraph("Limitations", st["h1"]))
    for line in LIMITATIONS:
        story.append(_p("- " + line, st["body"]))

    passed = [f for f in findings if f["status"] == "pass"]
    story.append(Paragraph(f"Appendix: passed checks ({len(passed)})", st["h1"]))
    story.append(_table(
        [[_p("Check", st["cell"]), _p("Evidence", st["cell"])]] +
        [[_p(f["title"], st["cell"]), _p(f["evidence"], st["cell"])] for f in passed] or [[_p("None", st["cell"]), _p("", st["cell"])]],
        [width * 0.38, width * 0.62],
    ))

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=18 * mm, title=f"WinSentinel Report - Scan {scan_id}", author="WinSentinel")
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()
