from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
import os


# =========================================================
# PDF REPORT GENERATOR
# =========================================================

def generate_pdf_report(results, output_path):
    """
    Generate a PDF security scan report.

    results:
        Dictionary containing scan results.

    output_path:
        Path where the PDF should be saved.
    """

    os.makedirs(
        os.path.dirname(output_path) or ".",
        exist_ok=True
    )

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        spaceAfter=10
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=11,
        leading=16,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=16,
        leading=20,
        spaceBefore=12,
        spaceAfter=10,
        textColor=colors.HexColor("#1e3a8a")
    )

    normal_style = ParagraphStyle(
        "NormalReport",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=14,
        spaceAfter=6
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["Normal"],
        fontSize=8,
        leading=11
    )

    story = []

    # =====================================================
    # DATA
    # =====================================================

    target = results.get(
        "target",
        "Unknown"
    )

    scan_time = results.get(
        "scan_time",
        "Unknown"
    )

    risk_score = results.get(
        "risk_score",
        0
    )

    risk_level = results.get(
        "risk_level",
        "Informational"
    )

    status_code = results.get(
        "status_code",
        "Unknown"
    )

    server = results.get(
        "server",
        "Not detected"
    )

    technologies = results.get(
        "technologies",
        []
    )

    pages = results.get(
        "pages",
        []
    )

    parameters = results.get(
        "parameters",
        []
    )

    js_files = results.get(
        "js_files",
        []
    )

    api_endpoints = results.get(
        "api_endpoints",
        []
    )

    findings = results.get(
        "findings",
        []
    )

    severity_counts = results.get(
        "severity_counts",
        {}
    )

    cookies = results.get(
        "cookies",
        []
    )

    # =====================================================
    # TITLE
    # =====================================================

    story.append(
        Paragraph(
            "🛡️ Web Vulnerability Scanner",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Security Assessment Report",
            subtitle_style
        )
    )

    # =====================================================
    # TARGET INFORMATION
    # =====================================================

    story.append(
        Paragraph(
            "Scan Information",
            heading_style
        )
    )

    scan_info = [
        [
            Paragraph("<b>Target</b>", normal_style),
            Paragraph(str(target), normal_style)
        ],
        [
            Paragraph("<b>Scan Time</b>", normal_style),
            Paragraph(str(scan_time), normal_style)
        ],
        [
            Paragraph("<b>HTTP Status</b>", normal_style),
            Paragraph(str(status_code), normal_style)
        ],
        [
            Paragraph("<b>Server</b>", normal_style),
            Paragraph(str(server), normal_style)
        ]
    ]

    scan_table = Table(
        scan_info,
        colWidths=[
            45 * mm,
            125 * mm
        ]
    )

    scan_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#e2e8f0")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#cbd5e1")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(scan_table)
    story.append(Spacer(1, 10))

    # =====================================================
    # RISK SUMMARY
    # =====================================================

    story.append(
        Paragraph(
            "Risk Summary",
            heading_style
        )
    )

    risk_data = [
        [
            Paragraph("<b>Risk Score</b>", normal_style),
            Paragraph(
                f"<b>{risk_score}/100</b>",
                normal_style
            )
        ],
        [
            Paragraph("<b>Risk Level</b>", normal_style),
            Paragraph(
                f"<b>{risk_level}</b>",
                normal_style
            )
        ],
        [
            Paragraph("<b>Total Findings</b>", normal_style),
            Paragraph(
                str(len(findings)),
                normal_style
            )
        ]
    ]

    risk_table = Table(
        risk_data,
        colWidths=[
            60 * mm,
            110 * mm
        ]
    )

    risk_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#dbeafe")
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#cbd5e1")
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),
            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(risk_table)
    story.append(Spacer(1, 12))

    # =====================================================
    # SEVERITY SUMMARY
    # =====================================================

    story.append(
        Paragraph(
            "Severity Summary",
            heading_style
        )
    )

    severity_data = [
        [
            Paragraph("<b>Severity</b>", normal_style),
            Paragraph("<b>Count</b>", normal_style)
        ],
        [
            "Critical",
            str(severity_counts.get("Critical", 0))
        ],
        [
            "High",
            str(severity_counts.get("High", 0))
        ],
        [
            "Medium",
            str(severity_counts.get("Medium", 0))
        ],
        [
            "Low",
            str(severity_counts.get("Low", 0))
        ],
        [
            "Info",
            str(severity_counts.get("Info", 0))
        ]
    ]

    severity_table = Table(
        severity_data,
        colWidths=[
            100 * mm,
            70 * mm
        ]
    )

    severity_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#1e3a8a")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#cbd5e1")
            ),
            (
                "ALIGN",
                (1, 1),
                (1, -1),
                "CENTER"
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(severity_table)

    # =====================================================
    # TECHNOLOGIES
    # =====================================================

    story.append(
        Paragraph(
            "Detected Technologies",
            heading_style
        )
    )

    if technologies:

        technology_text = ", ".join(
            str(item)
            for item in technologies
        )

        story.append(
            Paragraph(
                technology_text,
                normal_style
            )
        )

    else:

        story.append(
            Paragraph(
                "No technologies detected.",
                normal_style
            )
        )

    # =====================================================
    # DISCOVERY
    # =====================================================

    story.append(
        Paragraph(
            "Discovery Summary",
            heading_style
        )
    )

    discovery_data = [
        [
            Paragraph("<b>Category</b>", normal_style),
            Paragraph("<b>Count</b>", normal_style)
        ],
        [
            "Pages",
            str(len(pages))
        ],
        [
            "Parameters",
            str(len(parameters))
        ],
        [
            "JavaScript Files",
            str(len(js_files))
        ],
        [
            "API Endpoints",
            str(len(api_endpoints))
        ]
    ]

    discovery_table = Table(
        discovery_data,
        colWidths=[
            100 * mm,
            70 * mm
        ]
    )

    discovery_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#1e3a8a")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor("#cbd5e1")
            ),
            (
                "ALIGN",
                (1, 1),
                (1, -1),
                "CENTER"
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )

    story.append(discovery_table)

    # =====================================================
    # SECURITY FINDINGS
    # =====================================================

    story.append(
        Paragraph(
            "Security Findings",
            heading_style
        )
    )

    if findings:

        for index, finding in enumerate(
            findings,
            start=1
        ):

            name = finding.get(
                "name",
                "Unknown Finding"
            )

            severity = finding.get(
                "severity",
                "Info"
            )

            description = finding.get(
                "description",
                "No description available."
            )

            recommendation = finding.get(
                "recommendation",
                "No recommendation available."
            )

            story.append(
                Paragraph(
                    f"<b>{index}. {name}</b>",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Severity:</b> {severity}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Description:</b> {description}",
                    normal_style
                )
            )

            story.append(
                Paragraph(
                    f"<b>Recommendation:</b> {recommendation}",
                    normal_style
                )
            )

            story.append(
                Spacer(1, 6)
            )

    else:

        story.append(
            Paragraph(
                "No security findings were detected.",
                normal_style
            )
        )

    # =====================================================
    # COOKIES
    # =====================================================

    if cookies:

        story.append(
            Paragraph(
                "Cookie Security",
                heading_style
            )
        )

        cookie_data = [
            [
                "Name",
                "Secure",
                "HttpOnly",
                "SameSite"
            ]
        ]

        for cookie in cookies:

            cookie_data.append([
                str(cookie.get(
                    "name",
                    "Unknown"
                )),
                "Yes" if cookie.get(
                    "secure"
                ) else "No",
                "Yes" if cookie.get(
                    "httponly"
                ) else "No",
                str(cookie.get(
                    "samesite",
                    "Not detected"
                ))
            ])

        cookie_table = Table(
            cookie_data,
            repeatRows=1,
            colWidths=[
                55 * mm,
                35 * mm,
                35 * mm,
                45 * mm
            ]
        )

        cookie_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#1e3a8a")
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#cbd5e1")
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )
            ])
        )

        story.append(cookie_table)

    # =====================================================
    # FOOTER / DISCLAIMER
    # =====================================================

    story.append(
        Spacer(1, 20)
    )

    story.append(
        Paragraph(
            "Generated by Web Vulnerability Scanner",
            subtitle_style
        )
    )

    story.append(
        Paragraph(
            "Use this scanner only on systems you own "
            "or have explicit permission to test.",
            small_style
        )
    )

    # =====================================================
    # BUILD PDF
    # =====================================================

    doc.build(story)

    return output_path