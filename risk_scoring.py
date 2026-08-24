# ==========================================
# RISK SCORING ENGINE
# ==========================================

SEVERITY_POINTS = {
    "Critical": 30,
    "High": 20,
    "Medium": 8,
    "Low": 2,
    "Info": 0
}


def calculate_risk(findings):

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }

    # ======================================
    # COUNT FINDINGS
    # ======================================

    for finding in findings:

        severity = finding.get(
            "severity",
            "Info"
        )

        severity = str(
            severity
        ).strip()

        # Normalize severity names

        if severity.lower() == "critical":
            severity = "Critical"

        elif severity.lower() == "high":
            severity = "High"

        elif severity.lower() == "medium":
            severity = "Medium"

        elif severity.lower() == "low":
            severity = "Low"

        elif severity.lower() == "info":
            severity = "Info"

        else:
            severity = "Info"

        severity_counts[severity] += 1

    # ======================================
    # CALCULATE RISK
    # ======================================

    critical_score = min(
        severity_counts["Critical"],
        2
    ) * 30

    high_score = min(
        severity_counts["High"],
        3
    ) * 20

    medium_score = min(
        severity_counts["Medium"],
        5
    ) * 8

    low_score = min(
        severity_counts["Low"],
        5
    ) * 2

    score = (
        critical_score
        + high_score
        + medium_score
        + low_score
    )

    # Maximum 100

    score = min(
        score,
        100
    )

    # ======================================
    # RISK LEVEL
    # ======================================

    if score >= 80:

        risk_level = "Critical"

    elif score >= 60:

        risk_level = "High"

    elif score >= 35:

        risk_level = "Medium"

    elif score >= 15:

        risk_level = "Low"

    else:

        risk_level = "Informational"

    return {
        "score": score,
        "level": risk_level,
        "severity_counts": severity_counts
    }