from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


def generate_pdf_report(data, output_path):

    document = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = styles["Title"]
    title_style.alignment = TA_CENTER

    heading_style = styles["Heading2"]
    body_style = styles["BodyText"]

    story = []

    # ======================================
    # TITLE
    # ======================================

    story.append(
        Paragraph(
            "Web Vulnerability Scanner",
            title_style
        )
    )

    story.append(
        Spacer(1, 20)
    )

    story.append(
        Paragraph(
            "Security Assessment Report",
            styles["Heading2"]
        )
    )

    story.append(
        Spacer(1, 15)
    )

    # ======================================
    # TARGET INFORMATION
    # ======================================

    target = data.get(
        "target",
        "Unknown"
    )

    scan_time = data.get(
        "scan_time",
        "Unknown"
    )

    story.append(
        Paragraph(
            f"<b>Target:</b> {target}",
            body_style
        )
    )

    story.append(
        Spacer(1, 8)
    )

    story.append(
        Paragraph(
            f"<b>Scan Time:</b> {scan_time}",
            body_style
        )
    )

    story.append(
        Spacer(1, 20)
    )

    # ======================================
    # SUMMARY
    # ======================================

    story.append(
        Paragraph(
            "Scan Summary",
            heading_style
        )
    )

    story.append(
        Spacer(1, 10)
    )

    pages = data.get(
        "pages",
        []
    )

    parameters = data.get(
        "parameters",
        []
    )

    js_files = data.get(
        "js_files",
        []
    )

    api_endpoints = data.get(
        "api_endpoints",
        []
    )

    findings = data.get(
        "findings",
        []
    )

    summary_data = [
        ["Metric", "Count"],
        ["Pages", str(len(pages))],
        ["Parameters", str(len(parameters))],
        ["JavaScript Files", str(len(js_files))],
        ["API Endpoints", str(len(api_endpoints))],
        ["Security Findings", str(len(findings))]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[300, 100]
    )

    summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.grey
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
                colors.grey
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    story.append(
        summary_table
    )

    story.append(
        Spacer(1, 20)
    )

    # ======================================
    # SEVERITY SUMMARY
    # ======================================

    story.append(
        Paragraph(
            "Severity Summary",
            heading_style
        )
    )

    story.append(
        Spacer(1, 10)
    )

    severity = data.get(
        "severity_counts",
        {}
    )

    severity_data = [
        ["Severity", "Count"],
        [
            "Critical",
            str(severity.get("Critical", 0))
        ],
        [
            "High",
            str(severity.get("High", 0))
        ],
        [
            "Medium",
            str(severity.get("Medium", 0))
        ],
        [
            "Low",
            str(severity.get("Low", 0))
        ],
        [
            "Info",
            str(severity.get("Info", 0))
        ]
    ]

    severity_table = Table(
        severity_data,
        colWidths=[300, 100]
    )

    severity_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.grey
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
                colors.grey
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )

    story.append(
        severity_table
    )

    story.append(
        PageBreak()
    )

    # ======================================
    # FINDINGS
    # ======================================

    story.append(
        Paragraph(
            "Security Findings",
            heading_style
        )
    )

    story.append(
        Spacer(1, 15)
    )

    if not findings:

        story.append(
            Paragraph(
                "No security findings were detected "
                "by the current scanner checks.",
                body_style
            )
        )

    else:

        for number, finding in enumerate(
            findings,
            start=1
        ):

            name = finding.get(
                "name",
                "Unknown Finding"
            )

            finding_url = finding.get(
                "url",
                ""
            )

            finding_severity = finding.get(
                "severity",
                "Info"
            )

            description = finding.get(
                "description",
                ""
            )

            recommendation = finding.get(
                "recommendation",
                ""
            )

            parameter = finding.get(
                "parameter"
            )

            story.append(
                Paragraph(
                    f"{number}. {name}",
                    styles["Heading3"]
                )
            )

            story.append(
                Spacer(1, 5)
            )

            story.append(
                Paragraph(
                    f"<b>Severity:</b> "
                    f"{finding_severity}",
                    body_style
                )
            )

            story.append(
                Spacer(1, 5)
            )

            story.append(
                Paragraph(
                    f"<b>URL:</b> "
                    f"{finding_url}",
                    body_style
                )
            )

            if parameter:

                story.append(
                    Spacer(1, 5)
                )

                story.append(
                    Paragraph(
                        f"<b>Parameter:</b> "
                        f"{parameter}",
                        body_style
                    )
                )

            story.append(
                Spacer(1, 5)
            )

            story.append(
                Paragraph(
                    f"<b>Description:</b> "
                    f"{description}",
                    body_style
                )
            )

            story.append(
                Spacer(1, 5)
            )

            story.append(
                Paragraph(
                    f"<b>Recommendation:</b> "
                    f"{recommendation}",
                    body_style
                )
            )

            story.append(
                Spacer(1, 20)
            )

    # ======================================
    # METHODOLOGY
    # ======================================

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "Scanning Methodology",
            heading_style
        )
    )

    story.append(
        Spacer(1, 10)
    )

    methodology = [
        "Web page crawling",
        "URL parameter discovery",
        "JavaScript file discovery",
        "API endpoint discovery",
        "HTTP security-header analysis",
        "Cookie security analysis",
        "Reflected-input detection",
        "SQL error-indicator detection"
    ]

    for item in methodology:

        story.append(
            Paragraph(
                f"• {item}",
                body_style
            )
        )

        story.append(
            Spacer(1, 5)
        )

    story.append(
        Spacer(1, 20)
    )

    story.append(
        Paragraph(
            "Disclaimer: This report was generated "
            "by an automated security scanner. "
            "Findings should be manually validated "
            "before being treated as confirmed "
            "vulnerabilities.",
            body_style
        )
    )

    # ======================================
    # BUILD PDF
    # ======================================

    document.build(
        story
    )