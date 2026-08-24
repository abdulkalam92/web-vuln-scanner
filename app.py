from flask import (
    Flask,
    render_template,
    request,
    send_file
)

from datetime import datetime

import os
import json

from scanner import scan_target
from crawler import crawl

from checks import (
    check_security_headers,
    check_cookies,
    check_server_disclosure,
    check_information_disclosure
)

try:
    from vulnerability_checks import test_reflected_input
except ImportError:
    test_reflected_input = None

from reporter import generate_pdf_report


# =========================================================
# FLASK
# =========================================================

app = Flask(__name__)


# =========================================================
# DIRECTORIES
# =========================================================

REPORTS_DIR = "reports"

HISTORY_FILE = "scan_history.json"

os.makedirs(
    REPORTS_DIR,
    exist_ok=True
)


# =========================================================
# RISK SCORING
# =========================================================

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

    for finding in findings:

        severity = finding.get(
            "severity",
            "Info"
        )

        if severity not in severity_counts:
            severity = "Info"

        severity_counts[severity] += 1

    score = 0

    score += min(
        severity_counts["Critical"],
        2
    ) * SEVERITY_POINTS["Critical"]

    score += min(
        severity_counts["High"],
        3
    ) * SEVERITY_POINTS["High"]

    score += min(
        severity_counts["Medium"],
        5
    ) * SEVERITY_POINTS["Medium"]

    score += min(
        severity_counts["Low"],
        5
    ) * SEVERITY_POINTS["Low"]

    score = min(
        score,
        100
    )

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


# =========================================================
# URL NORMALIZATION
# =========================================================

def normalize_url(url):

    url = url.strip()

    if not url.startswith(
        ("http://", "https://")
    ):
        url = "https://" + url

    return url


# =========================================================
# TECHNOLOGIES
# =========================================================

def collect_technologies(
    scan_result,
    all_technologies
):

    technologies = scan_result.get(
        "technologies",
        []
    )

    for technology in technologies:

        if technology not in all_technologies:

            all_technologies.append(
                technology
            )


# =========================================================
# SAVE HISTORY
# =========================================================

def save_history(results):

    history = []

    if os.path.exists(HISTORY_FILE):

        try:

            with open(
                HISTORY_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                history = json.load(file)

        except Exception as error:

            print(
                "History read error:",
                error
            )

            history = []

    history.insert(
        0,
        results
    )

    history = history[:20]

    try:

        with open(
            HISTORY_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                history,
                file,
                indent=4,
                default=str
            )

    except Exception as error:

        print(
            "History save error:",
            error
        )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# =========================================================
# HISTORY
# =========================================================

@app.route("/history", methods=["GET"])
def history():

    history_data = []

    if os.path.exists(HISTORY_FILE):

        try:

            with open(
                HISTORY_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                history_data = json.load(file)

        except Exception as error:

            print(
                "History read error:",
                error
            )

    return render_template(
        "history.html",
        history=history_data
    )


# =========================================================
# SCAN
# =========================================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    url = request.form.get(
        "url",
        ""
    ).strip()

    if not url:

        return render_template(
            "index.html",
            error="Please enter a URL."
        )

    url = normalize_url(url)

    print(
        f"Starting scan: {url}"
    )

    all_findings = []

    all_technologies = []

    pages = []

    parameters = []

    js_files = []

    api_endpoints = []

    scan_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # =====================================================
    # TARGET SCAN
    # =====================================================

    try:

        scan_result = scan_target(
            url
        )

    except Exception as error:

        print(
            "Scanner error:",
            error
        )

        return render_template(
            "index.html",
            error=(
                "Scanner error: "
                + str(error)
            )
        )

    if scan_result.get("error"):

        return render_template(
            "index.html",
            error=(
                "Unable to scan target: "
                + str(
                    scan_result["error"]
                )
            )
        )

    # =====================================================
    # TECHNOLOGIES
    # =====================================================

    collect_technologies(
        scan_result,
        all_technologies
    )

    # =====================================================
    # RESPONSE DATA
    # =====================================================

    headers = scan_result.get(
        "headers",
        {}
    )

    cookies = scan_result.get(
        "cookies",
        []
    )

    server = scan_result.get(
        "server"
    )

    # =====================================================
    # SECURITY HEADERS
    # =====================================================

    try:

        all_findings.extend(
            check_security_headers(
                headers
            )
        )

    except Exception as error:

        print(
            "Security header check error:",
            error
        )

    # =====================================================
    # COOKIES
    # =====================================================

    try:

        all_findings.extend(
            check_cookies(
                cookies
            )
        )

    except Exception as error:

        print(
            "Cookie check error:",
            error
        )

    # =====================================================
    # SERVER DISCLOSURE
    # =====================================================

    try:

        all_findings.extend(
            check_server_disclosure(
                server
            )
        )

    except Exception as error:

        print(
            "Server disclosure error:",
            error
        )

    # =====================================================
    # INFORMATION DISCLOSURE
    # =====================================================

    try:

        all_findings.extend(
            check_information_disclosure(
                headers
            )
        )

    except Exception as error:

        print(
            "Information disclosure error:",
            error
        )

    # =====================================================
    # CRAWLER
    # =====================================================

    try:

        pages = crawl(
            url
        )

        if not pages:
            pages = [url]

    except Exception as error:

        print(
            "Crawler error:",
            error
        )

        pages = [url]

    print(
        f"Discovered {len(pages)} page(s)"
    )

    # =====================================================
    # PARAMETERS
    # =====================================================

    try:

        from crawler import find_parameters

        for page in pages:

            try:

                found_parameters = find_parameters(
                    page
                )

                for parameter in found_parameters or []:

                    if parameter not in parameters:

                        parameters.append(
                            parameter
                        )

            except Exception as error:

                print(
                    "Parameter discovery error:",
                    error
                )

    except ImportError:

        pass

    # =====================================================
    # JAVASCRIPT
    # =====================================================

    try:

        from crawler import find_javascript_files

        for page in pages:

            try:

                found_js = find_javascript_files(
                    page
                )

                for js in found_js or []:

                    if js not in js_files:

                        js_files.append(
                            js
                        )

            except Exception as error:

                print(
                    "JavaScript discovery error:",
                    error
                )

    except ImportError:

        pass

    # =====================================================
    # API ENDPOINTS
    # =====================================================

    try:

        from crawler import find_api_endpoints

        for page in pages:

            try:

                found_apis = find_api_endpoints(
                    page
                )

                for endpoint in found_apis or []:

                    if endpoint not in api_endpoints:

                        api_endpoints.append(
                            endpoint
                        )

            except Exception as error:

                print(
                    "API discovery error:",
                    error
                )

    except ImportError:

        pass

    # =====================================================
    # REFLECTED INPUT
    # =====================================================

    if test_reflected_input:

        for parameter in parameters:

            try:

                finding = test_reflected_input(
                    url,
                    parameter
                )

                if isinstance(
                    finding,
                    list
                ):

                    all_findings.extend(
                        finding
                    )

                elif isinstance(
                    finding,
                    dict
                ):

                    all_findings.append(
                        finding
                    )

            except Exception as error:

                print(
                    "Reflection test error:",
                    error
                )

    # =====================================================
    # REMOVE DUPLICATES
    # =====================================================

    unique_findings = []

    seen_findings = set()

    for finding in all_findings:

        if not isinstance(
            finding,
            dict
        ):
            continue

        key = (
            finding.get("name"),
            finding.get("severity"),
            finding.get("description")
        )

        if key not in seen_findings:

            seen_findings.add(
                key
            )

            unique_findings.append(
                finding
            )

    all_findings = unique_findings

    # =====================================================
    # RISK
    # =====================================================

    risk_result = calculate_risk(
        all_findings
    )

    # =====================================================
    # FINAL RESULTS
    # =====================================================

    results = {

        "target": url,

        "final_url": scan_result.get(
            "final_url"
        ),

        "status_code": scan_result.get(
            "status_code"
        ),

        "technologies": all_technologies,

        "scan_time": scan_time,

        "pages": pages,

        "parameters": parameters,

        "js_files": js_files,

        "api_endpoints": api_endpoints,

        "findings": all_findings,

        "severity_counts": risk_result[
            "severity_counts"
        ],

        "risk_score": risk_result[
            "score"
        ],

        "risk_level": risk_result[
            "level"
        ],

        "server": server,

        "cookies": cookies
    }

    # =====================================================
    # SAVE HISTORY
    # =====================================================

    save_history(
        results
    )

    # =====================================================
    # GENERATE PDF
    # =====================================================

    safe_timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    report_filename = (
        f"scan_report_{safe_timestamp}.pdf"
    )

    report_path = os.path.join(
        REPORTS_DIR,
        report_filename
    )

    try:

        generate_pdf_report(
            results,
            report_path
        )

        results["report_file"] = (
            report_filename
        )

        print(
            f"PDF report created: {report_path}"
        )

    except Exception as error:

        print(
            "PDF generation error:",
            error
        )

        results["report_file"] = None

    # =====================================================
    # DISPLAY
    # =====================================================

    return render_template(
        "index.html",
        results=results
    )


# =========================================================
# DOWNLOAD PDF
# =========================================================

@app.route(
    "/report/<filename>",
    methods=["GET"]
)
def download_report(filename):

    # Prevent path traversal
    safe_filename = os.path.basename(
        filename
    )

    report_path = os.path.join(
        REPORTS_DIR,
        safe_filename
    )

    if not os.path.isfile(
        report_path
    ):

        return (
            "Report not found.",
            404
        )

    return send_file(
        report_path,
        as_attachment=True,
        download_name=safe_filename,
        mimetype="application/pdf"
    )


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )