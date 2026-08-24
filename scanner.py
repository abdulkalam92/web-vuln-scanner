import requests
import re

USER_AGENT = "Mini-Web-Vulnerability-Scanner/1.0"


# =========================================================
# TECHNOLOGY DETECTION
# =========================================================

def detect_technologies(response):

    technologies = []

    headers = {
        str(key).lower(): str(value)
        for key, value in response.headers.items()
    }

    html = response.text.lower()

    # -----------------------------------------------------
    # Server
    # -----------------------------------------------------

    server = headers.get("server", "").lower()

    if "nginx" in server:
        technologies.append("Nginx")

    elif "apache" in server:
        technologies.append("Apache")

    elif "iis" in server:
        technologies.append("Microsoft IIS")


    # -----------------------------------------------------
    # Cloudflare
    # -----------------------------------------------------

    if (
        "cf-ray" in headers
        or "cloudflare" in server
    ):
        technologies.append("Cloudflare")


    # -----------------------------------------------------
    # X-Powered-By
    # -----------------------------------------------------

    powered_by = headers.get(
        "x-powered-by",
        ""
    ).lower()

    if "express" in powered_by:
        technologies.append("Express.js")

    if "php" in powered_by:
        technologies.append("PHP")

    if "asp.net" in powered_by:
        technologies.append("ASP.NET")


    # -----------------------------------------------------
    # React
    # -----------------------------------------------------

    if (
        "react" in html
        or "__react" in html
        or "_react" in html
    ):
        technologies.append("React")


    # -----------------------------------------------------
    # Angular
    # -----------------------------------------------------

    if (
        "ng-version" in html
        or "angular" in html
    ):
        technologies.append("Angular")


    # -----------------------------------------------------
    # Vue.js
    # -----------------------------------------------------

    if (
        "vue" in html
        or "__vue__" in html
    ):
        technologies.append("Vue.js")


    # -----------------------------------------------------
    # WordPress
    # -----------------------------------------------------

    if (
        "wp-content" in html
        or "wp-includes" in html
        or "wordpress" in html
    ):
        technologies.append("WordPress")


    # -----------------------------------------------------
    # Bootstrap
    # -----------------------------------------------------

    if "bootstrap" in html:
        technologies.append("Bootstrap")


    # -----------------------------------------------------
    # jQuery
    # -----------------------------------------------------

    if (
        "jquery" in html
        or "jquery.min.js" in html
    ):
        technologies.append("jQuery")


    # -----------------------------------------------------
    # Next.js
    # -----------------------------------------------------

    if (
        "__next_data__" in html
        or "_next/static" in html
    ):
        technologies.append("Next.js")


    # -----------------------------------------------------
    # Django
    # -----------------------------------------------------

    if (
        "csrfmiddlewaretoken" in html
        or "django" in html
    ):
        technologies.append("Django")


    # -----------------------------------------------------
    # Flask
    # -----------------------------------------------------

    if (
        "werkzeug" in headers.get("server", "").lower()
        or "flask" in html
    ):
        technologies.append("Flask")


    # -----------------------------------------------------
    # Java
    # -----------------------------------------------------

    if (
        "jsessionid" in html
        or "spring" in html
    ):
        technologies.append("Java / Spring")


    # -----------------------------------------------------
    # Remove duplicates
    # -----------------------------------------------------

    return list(
        dict.fromkeys(technologies)
    )


# =========================================================
# SCAN TARGET
# =========================================================

def scan_target(url):

    result = {

        "url": url,

        "final_url": None,

        "status_code": None,

        "headers": {},

        "server": None,

        "cookies": [],

        "technologies": [],

        "error": None
    }


    try:

        response = requests.get(

            url,

            timeout=10,

            allow_redirects=True,

            headers={
                "User-Agent": USER_AGENT
            }
        )


        # -------------------------------------------------
        # Basic response information
        # -------------------------------------------------

        result["final_url"] = response.url

        result["status_code"] = response.status_code

        result["headers"] = dict(
            response.headers
        )

        result["server"] = response.headers.get(
            "Server"
        )


        # -------------------------------------------------
        # Technology detection
        # -------------------------------------------------

        result["technologies"] = (
            detect_technologies(response)
        )


        # -------------------------------------------------
        # Cookie information
        # -------------------------------------------------

        for cookie in response.cookies:

            samesite = None

            try:

                samesite = (
                    cookie.get_nonstandard_attr(
                        "SameSite"
                    )
                )

            except Exception:

                pass


            result["cookies"].append({

                "name":
                    cookie.name,

                "secure":
                    bool(cookie.secure),

                "httponly":
                    bool(
                        cookie.has_nonstandard_attr(
                            "HttpOnly"
                        )
                    ),

                "samesite":
                    samesite,

                "domain":
                    cookie.domain,

                "path":
                    cookie.path,

                "expires":
                    cookie.expires
            })


    except requests.RequestException as error:

        result["error"] = str(error)


    return result