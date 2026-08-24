from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


def generate_pdf_report(data, output_file):

    document = SimpleDocTemplate(
        output_file,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=22,
        spaceAfter=20
    )

    heading_style = ParagraphStyle(
        "ReportHeading",
        parent=styles["Heading2"],
        fontSize=15,
        spaceBefore=15,
        spaceAfter=10
    )

    normal_style = styles["BodyText"]

    story = []

    # =====================================
    # TITLE
    # =====================================

    story.append(
        Paragraph(
            "Web Vulnerability Scanner Report",
            title_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Target:</b> {data.get('target', 'N/A')}",
            normal_style
        )
    )

    story.append(
        Paragraph(
            f"<b>Scan Time:</b> {data.get('scan_time', 'N/A')}",
            normal_style
        )
    )

    story.append(Spacer(1, 20))

    # =====================================
    # RISK SUMMARY
    # =====================================

    story.append(
        Paragraph(
            "Risk Summary",
            heading_style
        )
    )

    risk_data = [
        ["Risk Score", "Risk Level"],
        [
            str(data.get("risk_score", 0)),
            str(data.get("risk_level", "Unknown"))
        ]
    ]

    risk_table = Table(
        risk_data,
        colWidths=[200, 200]
    )

    risk_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#e2e8f0")),
            ("TEXTCOLOR", (0, 1), (-1, 1), colors.black),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 1, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 10),
        ])
    )

    story.append(risk_table)

    # =====================================
    # SEVERITY
    # =====================================

    story.append(
        Paragraph(
            "Severity Summary",
            heading_style
        )
    )

    severity = data.get(
        "severity_counts",
        {}
    )

    severity_data = [
        ["Severity", "Count"],
        ["Critical", severity.get("Critical", 0)],
        ["High", severity.get("High", 0)],
        ["Medium", severity.get("Medium", 0)],
        ["Low", severity.get("Low", 0)],
        ["Info", severity.get("Info", 0)]
    ]

    severity_table = Table(
        severity_data,
        colWidths=[250, 150]
    )

    severity_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 1, colors.grey),
            ("ALIGN", (1, 1), (1, -1), "CENTER"),
            ("PADDING", (0, 0), (-1, -1), 8),
        ])
    )

    story.append(severity_table)

    # =====================================
    # TECHNOLOGIES
    # =====================================

    story.append(
        Paragraph(
            "Detected Technologies",
            heading_style
        )
    )

    technologies = data.get(
        "technologies",
        []
    )

    if technologies:

        for technology in technologies:

            if isinstance(
                technology,
                dict
            ):

                name = technology.get(
                    "name",
                    "Unknown"
                )

                confidence = technology.get(
                    "confidence",
                    ""
                )

                text = (
                    f"• {name} "
                    f"{confidence}"
                )

            else:

                text = f"• {technology}"

            story.append(
                Paragraph(
                    text,
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

    # =====================================
    # DISCOVERED PAGES
    # =====================================

    story.append(
        Paragraph(
            "Discovered Pages",
            heading_style
        )
    )

    pages = data.get(
        "pages",
        []
    )

    if pages:

        for page in pages:

            story.append(
                Paragraph(
                    f"• {page}",
                    normal_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No pages discovered.",
                normal_style
            )
        )

    # =====================================
    # PARAMETERS
    # =====================================

    story.append(
        Paragraph(
            "Discovered Parameters",
            heading_style
        )
    )

    parameters = data.get(
        "parameters",
        []
    )

    if parameters:

        for parameter in parameters:

            if isinstance(
                parameter,
                dict
            ):

                name = parameter.get(
                    "parameter",
                    "Unknown"
                )

                url = parameter.get(
                    "url",
                    ""
                )

                text = (
                    f"• <b>{name}</b> "
                    f"- {url}"
                )

            else:

                text = f"• {parameter}"

            story.append(
                Paragraph(
                    text,
                    normal_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No parameters discovered.",
                normal_style
            )
        )

    # =====================================
    # API ENDPOINTS
    # =====================================

    story.append(
        Paragraph(
            "API Endpoints",
            heading_style
        )
    )

    endpoints = data.get(
        "api_endpoints",
        []
    )

    if endpoints:

        for endpoint in endpoints:

            story.append(
                Paragraph(
                    f"• {endpoint}",
                    normal_style
                )
            )

    else:

        story.append(
            Paragraph(
                "No API endpoints discovered.",
                normal_style
            )
        )

    # =====================================
    # FINDINGS
    # =====================================

    story.append(PageBreak())

    story.append(
        Paragraph(
            "Security Findings",
            heading_style
        )
    )

    findings = data.get(
        "findings",
        []
    )

    if findings:

        for number, finding in enumerate(
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

            url = finding.get(
                "url",
                "N/A"
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
                    f"{number}. {name}",
                    heading_style
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
                    f"<b>URL:</b> {url}",
                    normal_style
                )
            )

            story.append(
                Spacer(1, 5)
            )

            story.append(
                Paragraph(
                    f"<b>Description:</b> {description}",
                    normal_style
                )
            )

            story.append(
                Spacer(1, 5)
            )

            story.append(
                Paragraph(
                    f"<b>Recommendation:</b> "
                    f"{recommendation}",
                    normal_style
                )
            )

            story.append(
                Spacer(1, 15)
            )

    else:

        story.append(
            Paragraph(
                "No security findings detected.",
                normal_style
            )
        )

    # =====================================
    # BUILD PDF
    # =====================================

    document.build(story)