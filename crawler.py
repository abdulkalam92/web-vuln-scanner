import re

import requests

from bs4 import BeautifulSoup

from urllib.parse import (
    urljoin,
    urlparse,
    parse_qs
)


USER_AGENT = "Mini-Web-Vulnerability-Scanner/1.0"


def crawl(start_url, max_pages=20):

    start_url = start_url.split("#")[0]

    visited = set()
    queue = [start_url]

    base_domain = urlparse(start_url).netloc

    while queue and len(visited) < max_pages:

        url = queue.pop(0)

        if url in visited:
            continue

        try:

            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                headers={
                    "User-Agent": USER_AGENT
                }
            )

        except requests.RequestException as error:

            print(
                f"[-] Could not access {url}: {error}"
            )

            continue

        final_url = response.url.split("#")[0]

        if final_url not in visited:

            visited.add(final_url)

        print(f"[+] Crawled: {final_url}")

        content_type = response.headers.get(
            "Content-Type",
            ""
        ).lower()

        if "text/html" not in content_type:

            continue

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        # ----------------------------------
        # Find links
        # ----------------------------------

        for link in soup.find_all(
            "a",
            href=True
        ):

            new_url = urljoin(
                final_url,
                link["href"]
            )

            parsed = urlparse(new_url)

            if parsed.scheme not in (
                "http",
                "https"
            ):
                continue

            if parsed.netloc != base_domain:
                continue

            clean_url = new_url.split("#")[0]

            if clean_url not in visited:
                queue.append(clean_url)

        # ----------------------------------
        # Find form actions
        # ----------------------------------

        for form in soup.find_all("form"):

            action = form.get("action")

            if not action:
                continue

            form_url = urljoin(
                final_url,
                action
            )

            parsed = urlparse(form_url)

            if parsed.netloc != base_domain:
                continue

            form_url = form_url.split("#")[0]

            if form_url not in visited:
                queue.append(form_url)

    return sorted(visited)


def find_parameters(pages):

    parameters = []

    seen = set()

    for page in pages:

        parsed = urlparse(page)

        query_parameters = parse_qs(
            parsed.query
        )

        for parameter in query_parameters:

            key = (
                page,
                parameter
            )

            if key in seen:
                continue

            seen.add(key)

            parameters.append({
                "url": page,
                "parameter": parameter
            })

    return parameters


def find_javascript_files(pages):

    js_files = set()

    for page in pages:

        try:

            response = requests.get(
                page,
                timeout=10,
                headers={
                    "User-Agent": USER_AGENT
                }
            )

        except requests.RequestException:

            continue

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        for script in soup.find_all(
            "script",
            src=True
        ):

            js_url = urljoin(
                page,
                script["src"]
            )

            parsed = urlparse(js_url)

            if parsed.scheme in (
                "http",
                "https"
            ):

                js_files.add(js_url)

    return sorted(js_files)


def find_api_endpoints(js_files):

    endpoints = set()

    endpoint_pattern = re.compile(
        r"""["']((?:/api/|/rest/|/v[0-9]+/)[^"'?#\s]*)["']"""
    )

    for js_url in js_files:

        try:

            response = requests.get(
                js_url,
                timeout=10,
                headers={
                    "User-Agent": USER_AGENT
                }
            )

        except requests.RequestException:

            continue

        matches = endpoint_pattern.findall(
            response.text
        )

        for endpoint in matches:
            endpoints.add(endpoint)

    return sorted(endpoints)