# =========================================================
# SECURITY CHECKS
# =========================================================


def make_finding(
    name,
    severity,
    description,
    recommendation
):
    return {
        "name": name,
        "severity": severity,
        "description": description,
        "recommendation": recommendation
    }


# =========================================================
# SECURITY HEADERS
# =========================================================

def check_security_headers(headers):

    findings = []

    if not headers:
        return findings

    normalized = {}

    for key, value in headers.items():
        normalized[str(key).lower()] = str(value)

    # -----------------------------------------------------
    # Content-Security-Policy
    # -----------------------------------------------------

    if "content-security-policy" not in normalized:

        findings.append(
            make_finding(
                "Missing Content-Security-Policy",
                "Medium",
                "Content-Security-Policy header was not detected.",
                "Implement a suitable Content-Security-Policy."
            )
        )

    # -----------------------------------------------------
    # Strict-Transport-Security
    # -----------------------------------------------------

    if "strict-transport-security" not in normalized:

        findings.append(
            make_finding(
                "Missing HSTS Header",
                "Medium",
                "Strict-Transport-Security header was not detected.",
                "Enable HSTS for HTTPS applications."
            )
        )

    # -----------------------------------------------------
    # X-Content-Type-Options
    # -----------------------------------------------------

    if "x-content-type-options" not in normalized:

        findings.append(
            make_finding(
                "Missing X-Content-Type-Options",
                "Low",
                "X-Content-Type-Options header was not detected.",
                "Set X-Content-Type-Options to nosniff."
            )
        )

    # -----------------------------------------------------
    # X-Frame-Options
    # -----------------------------------------------------

    if "x-frame-options" not in normalized:

        findings.append(
            make_finding(
                "Missing X-Frame-Options",
                "Low",
                "X-Frame-Options header was not detected.",
                "Set X-Frame-Options to DENY or SAMEORIGIN."
            )
        )

    # -----------------------------------------------------
    # Referrer-Policy
    # -----------------------------------------------------

    if "referrer-policy" not in normalized:

        findings.append(
            make_finding(
                "Missing Referrer-Policy",
                "Low",
                "Referrer-Policy header was not detected.",
                "Configure an appropriate Referrer-Policy."
            )
        )

    # -----------------------------------------------------
    # Permissions-Policy
    # -----------------------------------------------------

    if "permissions-policy" not in normalized:

        findings.append(
            make_finding(
                "Missing Permissions-Policy",
                "Low",
                "Permissions-Policy header was not detected.",
                "Configure Permissions-Policy to restrict unnecessary browser features."
            )
        )

    return findings


# =========================================================
# COOKIE SECURITY
# =========================================================

def check_cookies(cookies):

    findings = []

    if not cookies:
        return findings

    for cookie in cookies:

        name = cookie.get(
            "name",
            "Unknown"
        )

        secure = cookie.get(
            "secure",
            False
        )

        httponly = cookie.get(
            "httponly",
            False
        )

        samesite = cookie.get(
            "samesite"
        )

        # -------------------------------------------------
        # Secure flag
        # -------------------------------------------------

        if not secure:

            findings.append(
                make_finding(
                    f"Insecure Cookie: {name}",
                    "Medium",
                    (
                        f"The cookie '{name}' does not "
                        "appear to use the Secure flag."
                    ),
                    (
                        "Set the Secure attribute on cookies "
                        "that should only be transmitted over HTTPS."
                    )
                )
            )

        # -------------------------------------------------
        # HttpOnly flag
        # -------------------------------------------------

        if not httponly:

            findings.append(
                make_finding(
                    f"Cookie Missing HttpOnly: {name}",
                    "Medium",
                    (
                        f"The cookie '{name}' does not "
                        "appear to use the HttpOnly flag."
                    ),
                    (
                        "Use the HttpOnly attribute for cookies "
                        "that do not need JavaScript access."
                    )
                )
            )

        # -------------------------------------------------
        # SameSite flag
        # -------------------------------------------------

        if not samesite:

            findings.append(
                make_finding(
                    f"Cookie Missing SameSite: {name}",
                    "Low",
                    (
                        f"The cookie '{name}' does not "
                        "have a detectable SameSite attribute."
                    ),
                    (
                        "Configure an appropriate SameSite "
                        "policy such as Lax or Strict."
                    )
                )
            )

    return findings


# =========================================================
# SERVER VERSION DISCLOSURE
# =========================================================

def check_server_disclosure(server):

    findings = []

    if not server:
        return findings

    server_string = str(server)

    has_version = False

    for character in server_string:

        if character.isdigit():

            has_version = True
            break

    if has_version:

        findings.append(
            make_finding(
                "Server Version Disclosure",
                "Low",
                (
                    f"The Server header exposes server "
                    f"information: {server_string}"
                ),
                (
                    "Minimize unnecessary server and "
                    "version information in HTTP responses."
                )
            )
        )

    return findings


# =========================================================
# INFORMATION DISCLOSURE
# =========================================================

def check_information_disclosure(headers):

    findings = []

    if not headers:
        return findings

    normalized = {}

    for key, value in headers.items():
        normalized[str(key).lower()] = str(value)

    # -----------------------------------------------------
    # X-Powered-By
    # -----------------------------------------------------

    if "x-powered-by" in normalized:

        value = normalized[
            "x-powered-by"
        ]

        findings.append(
            make_finding(
                "Technology Disclosure",
                "Low",
                (
                    "The X-Powered-By header exposes "
                    f"technology information: {value}"
                ),
                (
                    "Remove or minimize technology "
                    "identification headers."
                )
            )
        )

    return findings