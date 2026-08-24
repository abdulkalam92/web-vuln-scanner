def detect_technologies(headers, body):

    technologies = []

    # Normalize headers
    normalized_headers = {
        str(key).lower(): str(value)
        for key, value in headers.items()
    }

    body_lower = body.lower()

    # ==========================================
    # WEB SERVERS
    # ==========================================

    server = normalized_headers.get(
        "server",
        ""
    ).lower()

    if "nginx" in server:
        technologies.append({
            "name": "Nginx",
            "confidence": "High",
            "source": "Server header"
        })

    elif "apache" in server:
        technologies.append({
            "name": "Apache",
            "confidence": "High",
            "source": "Server header"
        })

    elif "iis" in server:
        technologies.append({
            "name": "Microsoft IIS",
            "confidence": "High",
            "source": "Server header"
        })

    # ==========================================
    # PHP
    # ==========================================

    if "x-powered-by" in normalized_headers:

        powered_by = normalized_headers[
            "x-powered-by"
        ].lower()

        if "php" in powered_by:

            technologies.append({
                "name": "PHP",
                "confidence": "High",
                "source": "X-Powered-By header"
            })

        if "express" in powered_by:

            technologies.append({
                "name": "Express.js",
                "confidence": "High",
                "source": "X-Powered-By header"
            })

    # ==========================================
    # ASP.NET
    # ==========================================

    if (
        "x-aspnet-version" in normalized_headers
        or
        "x-aspnetmvc-version" in normalized_headers
    ):

        technologies.append({
            "name": "ASP.NET",
            "confidence": "High",
            "source": "ASP.NET response header"
        })

    # ==========================================
    # WORDPRESS
    # ==========================================

    if (
        "/wp-content/" in body_lower
        or
        "/wp-includes/" in body_lower
    ):

        technologies.append({
            "name": "WordPress",
            "confidence": "Medium",
            "source": "HTML content"
        })

    # ==========================================
    # REACT
    # ==========================================

    if (
        "react" in body_lower
        or
        "__react" in body_lower
        or
        "reactroot" in body_lower
    ):

        technologies.append({
            "name": "React",
            "confidence": "Medium",
            "source": "HTML content"
        })

    # ==========================================
    # VUE.JS
    # ==========================================

    if (
        "vue" in body_lower
        or
        "v-app" in body_lower
        or
        "__vue__" in body_lower
    ):

        technologies.append({
            "name": "Vue.js",
            "confidence": "Medium",
            "source": "HTML content"
        })

    # ==========================================
    # ANGULAR
    # ==========================================

    if (
        "ng-version" in body_lower
        or
        "angular" in body_lower
    ):

        technologies.append({
            "name": "Angular",
            "confidence": "Medium",
            "source": "HTML content"
        })

    # ==========================================
    # DJANGO
    # ==========================================

    if (
        "csrftoken" in body_lower
        or
        "django" in body_lower
    ):

        technologies.append({
            "name": "Django",
            "confidence": "Low",
            "source": "HTML content"
        })

    # ==========================================
    # FLASK
    # ==========================================

    if (
        "werkzeug" in body_lower
        or
        "flask" in body_lower
    ):

        technologies.append({
            "name": "Flask",
            "confidence": "Low",
            "source": "Response content"
        })

    # ==========================================
    # JAVASCRIPT
    # ==========================================

    if "<script" in body_lower:

        technologies.append({
            "name": "JavaScript",
            "confidence": "High",
            "source": "HTML script elements"
        })

    # ==========================================
    # REMOVE DUPLICATES
    # ==========================================

    unique = {}

    for technology in technologies:

        name = technology["name"]

        if name not in unique:

            unique[name] = technology

    return list(unique.values())