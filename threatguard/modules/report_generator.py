"""
PDF report generator for THREATGUARD using ReportLab.

Generates a professional, downloadable PDF report containing:
  - Website URL and scan metadata
  - Security, Privacy and Trust scores
  - All findings with evidence and recommendations
  - AI explanations (if available)
  - Scoring methodology note
"""
from __future__ import annotations

import os
from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from utils.helpers import ensure_outputs_dir, format_datetime, report_filename, severity_color

# ── Colour palette ─────────────────────────────────────────────────────────────
_NAVY = colors.HexColor("#0D1B2A")
_BLUE = colors.HexColor("#1E90FF")
_GREEN = colors.HexColor("#00C851")
_AMBER = colors.HexColor("#FFD700")
_ORANGE = colors.HexColor("#FF8C00")
_RED = colors.HexColor("#FF4444")
_LIGHT_GREY = colors.HexColor("#F0F4F8")
_DARK_GREY = colors.HexColor("#4A5568")
_WHITE = colors.white

_SEVERITY_COLORS = {
    "Critical": _RED,
    "High": _ORANGE,
    "Medium": _AMBER,
    "Low": _BLUE,
    "Informational": colors.HexColor("#90EE90"),
}


def generate_pdf_report(
    url: str,
    scan_id: int,
    scan_date: datetime,
    security_score: float,
    privacy_score: float,
    trust_score: float,
    findings: list[dict],
    ai_explanations: dict[int, str] | None = None,
) -> str:
    """
    Generate a PDF report and save it to the outputs/ directory.

    Returns
    -------
    str  – absolute path to the generated PDF.
    """
    out_dir = ensure_outputs_dir()
    filename = report_filename(url, scan_id)
    filepath = os.path.join(out_dir, filename)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        title=f"ThreatGuard Report – {url}",
        author="THREATGUARD Security Analysis System",
    )

    styles = _build_styles()
    story = []

    # ── Cover Section ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph("THREATGUARD", styles["title"]))
    story.append(Paragraph("Threat Detection & Privacy Analysis System", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=_BLUE, spaceAfter=12))
    story.append(Spacer(1, 0.5 * cm))

    # Meta table
    meta = [
        ["Website", url],
        ["Scan ID", f"#{scan_id}"],
        ["Scan Date", format_datetime(scan_date)],
        ["Report Generated", format_datetime(datetime.utcnow())],
        ["Total Findings", str(len(findings))],
    ]
    meta_table = Table(meta, colWidths=[4 * cm, 13 * cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), _LIGHT_GREY),
        ("TEXTCOLOR", (0, 0), (0, -1), _NAVY),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_WHITE, _LIGHT_GREY]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 1 * cm))

    # ── Score Summary ──────────────────────────────────────────────────────────
    story.append(Paragraph("Score Summary", styles["section_heading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BLUE, spaceAfter=8))

    score_data = [
        ["Score Type", "Score", "Rating"],
        ["Security Score", f"{security_score:.1f} / 100", _score_label(security_score)],
        ["Privacy Score", f"{privacy_score:.1f} / 100", _score_label(privacy_score)],
        ["Trust Score", f"{trust_score:.1f} / 100", _score_label(trust_score)],
    ]
    score_table = Table(score_data, colWidths=[6 * cm, 5 * cm, 6 * cm])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("ALIGN", (1, 0), (2, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_WHITE, _LIGHT_GREY]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 0.5 * cm))

    # Scoring note
    story.append(Paragraph(
        "<i>Note: These are heuristic posture scores calculated from detected findings "
        "using deterministic rules. They are not formal security guarantees.</i>",
        styles["note"],
    ))
    story.append(Spacer(1, 1 * cm))

    # ── Severity Distribution ──────────────────────────────────────────────────
    story.append(Paragraph("Severity Distribution", styles["section_heading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BLUE, spaceAfter=8))

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        sev = f.get("severity", "Informational")
        if sev in sev_counts:
            sev_counts[sev] += 1

    sev_data = [["Severity", "Count"]] + [
        [sev, str(cnt)] for sev, cnt in sev_counts.items()
    ]
    sev_table = Table(sev_data, colWidths=[8 * cm, 9 * cm])
    sev_colors_style = []
    for i, (sev, _) in enumerate(sev_counts.items(), start=1):
        c = _SEVERITY_COLORS.get(sev, _DARK_GREY)
        sev_colors_style.append(("TEXTCOLOR", (0, i), (0, i), c))
        sev_colors_style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))

    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_WHITE, _LIGHT_GREY]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ] + sev_colors_style))
    story.append(sev_table)
    story.append(PageBreak())

    # ── Detailed Findings ──────────────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", styles["section_heading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BLUE, spaceAfter=12))

    if not findings:
        story.append(Paragraph("No findings detected in this scan.", styles["body"]))
    else:
        for idx, finding in enumerate(findings, start=1):
            sev = finding.get("severity", "Informational")
            sev_color = _SEVERITY_COLORS.get(sev, _DARK_GREY)

            # Finding header
            story.append(Paragraph(
                f"<b>#{idx} – {finding.get('finding_name', 'Unknown Finding')}</b>",
                styles["finding_title"],
            ))

            # Metadata row
            meta_row = [
                ["Category", finding.get("category", "").title()],
                ["Severity", sev],
                ["Confidence", finding.get("confidence", "")],
            ]
            meta_mini = Table(meta_row, colWidths=[3.5 * cm, 13.5 * cm])
            meta_mini.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (1, 1), (1, 1), sev_color),
                ("FONTNAME", (1, 1), (1, 1), "Helvetica-Bold"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(meta_mini)
            story.append(Spacer(1, 0.2 * cm))

            # Evidence
            if finding.get("evidence"):
                story.append(Paragraph("<b>Evidence:</b>", styles["field_label"]))
                story.append(Paragraph(str(finding["evidence"])[:600], styles["evidence"]))

            # Impact
            if finding.get("impact"):
                story.append(Paragraph("<b>Business Impact:</b>", styles["field_label"]))
                story.append(Paragraph(str(finding["impact"])[:400], styles["body"]))

            # Recommendation
            if finding.get("recommendation"):
                story.append(Paragraph("<b>Recommended Fix:</b>", styles["field_label"]))
                story.append(Paragraph(str(finding["recommendation"])[:400], styles["body"]))

            # AI explanation
            if ai_explanations and idx - 1 in ai_explanations:
                ai_text = ai_explanations[idx - 1]
                if ai_text and "not available" not in ai_text.lower()[:30]:
                    story.append(Paragraph("<b>AI Explanation:</b>", styles["field_label"]))
                    story.append(Paragraph(ai_text[:800], styles["ai_text"]))

            story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E0"), spaceAfter=8))
            story.append(Spacer(1, 0.3 * cm))

    # ── Footer ─────────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph("THREATGUARD – Scoring Methodology", styles["section_heading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=_BLUE, spaceAfter=8))
    methodology_text = """
    <b>Security Score</b> = 100 − Σ(security finding penalties)<br/>
    <b>Privacy Score</b> = 100 − Σ(privacy finding penalties)<br/>
    <b>Trust Score</b> = (Security Score × 0.5) + (Privacy Score × 0.5)<br/><br/>
    Penalty values: Critical=25, High=15, Medium=8, Low=3, Informational=0.<br/>
    Scores are capped at 0 (minimum) and 100 (maximum).<br/><br/>
    These scores are heuristic indicators of security posture based on passive,
    read-only checks. They are not a guarantee of security and should not replace
    a professional security audit.
    """
    story.append(Paragraph(methodology_text, styles["body"]))

    story.append(Spacer(1, 2 * cm))
    story.append(Paragraph(
        f"Generated by THREATGUARD on {format_datetime(datetime.utcnow())}  |  "
        "This report is for educational and informational purposes only.",
        styles["footer"],
    ))

    # Build PDF
    doc.build(story)

    # Write to file
    with open(filepath, "wb") as f:
        f.write(buffer.getvalue())

    return filepath


def _build_styles() -> dict:
    base = getSampleStyleSheet()
    styles = {}

    styles["title"] = ParagraphStyle(
        "title", fontSize=28, fontName="Helvetica-Bold",
        textColor=_NAVY, alignment=TA_CENTER, spaceAfter=4,
    )
    styles["subtitle"] = ParagraphStyle(
        "subtitle", fontSize=12, fontName="Helvetica",
        textColor=_DARK_GREY, alignment=TA_CENTER, spaceAfter=12,
    )
    styles["section_heading"] = ParagraphStyle(
        "section_heading", fontSize=14, fontName="Helvetica-Bold",
        textColor=_NAVY, spaceAfter=4, spaceBefore=16,
    )
    styles["finding_title"] = ParagraphStyle(
        "finding_title", fontSize=11, fontName="Helvetica-Bold",
        textColor=_NAVY, spaceAfter=4, spaceBefore=12,
    )
    styles["field_label"] = ParagraphStyle(
        "field_label", fontSize=9, fontName="Helvetica-Bold",
        textColor=_DARK_GREY, spaceAfter=2, spaceBefore=4,
    )
    styles["body"] = ParagraphStyle(
        "body", fontSize=9, fontName="Helvetica",
        textColor=colors.HexColor("#2D3748"), spaceAfter=4, leading=14,
    )
    styles["evidence"] = ParagraphStyle(
        "evidence", fontSize=8, fontName="Courier",
        textColor=colors.HexColor("#2D3748"),
        backColor=_LIGHT_GREY, spaceAfter=4, leading=12,
        leftIndent=8, rightIndent=8,
    )
    styles["ai_text"] = ParagraphStyle(
        "ai_text", fontSize=9, fontName="Helvetica-Oblique",
        textColor=colors.HexColor("#2B4162"), spaceAfter=4, leading=14,
        backColor=colors.HexColor("#EBF4FF"),
        leftIndent=6, rightIndent=6,
    )
    styles["note"] = ParagraphStyle(
        "note", fontSize=8, fontName="Helvetica-Oblique",
        textColor=_DARK_GREY, alignment=TA_LEFT,
    )
    styles["footer"] = ParagraphStyle(
        "footer", fontSize=8, fontName="Helvetica",
        textColor=_DARK_GREY, alignment=TA_CENTER,
    )

    return styles


def _score_label(score: float) -> str:
    if score >= 80:
        return "Good"
    elif score >= 60:
        return "Fair"
    elif score >= 40:
        return "Poor"
    else:
        return "Critical Risk"
