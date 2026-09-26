# Web Vulnerability Scanner

A Python-based web security scanning tool designed to collect information about a target web application and identify common security-related indicators. The scanner performs basic target analysis, technology detection, HTTP response inspection, and cookie security checks.

> **Note:** This project is intended for educational purposes and authorized security testing only.

## Features

* URL scanning
* HTTP and HTTPS support
* Automatic redirect detection
* HTTP status code detection
* Response header analysis
* Web server detection
* Technology detection
* Cloudflare detection
* Framework detection
* Cookie analysis
* Secure cookie detection
* HttpOnly cookie detection
* SameSite cookie inspection
* JSON scan result export
* Command-line interface
* Error handling for failed requests

## Technology Detection

The scanner can attempt to identify several technologies used by a web application, including:

* Nginx
* Apache
* Microsoft IIS
* Cloudflare
* Express.js
* PHP
* ASP.NET
* React
* Angular
* Vue.js
* WordPress
* Bootstrap
* jQuery
* Next.js
* Django
* Flask
* Java / Spring

Technology detection is based on HTTP response headers and HTML content.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/abdulkalam92/web-vuln-scanner.git
```

### 2. Navigate to the project directory

```bash
cd web-vuln-scanner
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the virtual environment

**Windows PowerShell:**

```powershell
.\.venv\Scripts\Activate.ps1
```

**Windows Command Prompt:**

```cmd
.venv\Scripts\activate
```

### 5. Install the required dependencies

```bash
pip install -r requirements.txt
```

## Usage

Run the scanner using:

```bash
python scanner.py
```

The program will ask you to enter a target URL:

```text
Enter the URL to scan:
```

Enter a URL you own or have explicit permission to test.

Example:

```text
https://example.com
```

You can also provide the URL directly from the command line:

```bash
python scanner.py https://example.com
```

## Example Output

The scanner can display information such as:

```text
=======================================================
       MINI WEB VULNERABILITY SCANNER
=======================================================

Scanning: https://example.com
Please wait...

SCAN COMPLETE
-------------------------------------------------------

Original URL : https://example.com
Final URL    : https://example.com
Status Code  : 200
Server       : Example Server

Technologies Detected:
  - Example Technology

Cookies Found:
  No cookies found
```

The exact results depend on the target website.

## Scan Results

After a successful scan, results can be saved in:

```text
scan_result.json
```

The JSON file may contain information such as:

* Original target URL
* Final URL after redirects
* HTTP status code
* HTTP response headers
* Web server information
* Detected technologies
* Cookie information
* Secure cookie settings
* HttpOnly cookie settings
* SameSite attributes
* Scan errors

## Project Structure

```text
web-vuln-scanner/
│
├── scanner.py
├── vulnerability_checks.py
├── technology.py
├── risk_scoring.py
├── requirements.txt
├── test_scanner.py
├── test_crawler.py
├── scan_history.json
└── README.md
```

### File Description

**scanner.py**

The main scanner module. It sends HTTP requests to the target, collects response information, detects technologies, and analyzes cookies.

**vulnerability_checks.py**

Contains functionality related to security and vulnerability checks.

**technology.py**

Contains functionality for identifying technologies used by the target web application.

**risk_scoring.py**

Contains logic for calculating or organizing security findings based on risk or severity.

**requirements.txt**

Contains the Python packages required to run the project.

**test_scanner.py**

Contains tests related to the scanner functionality.

**test_crawler.py**

Contains tests related to crawling functionality.

## Requirements

* Python 3.8 or later
* Internet connection
* Required Python packages listed in `requirements.txt`

## HTTP Response Analysis

The scanner analyzes information returned by the target server, including:

* HTTP status code
* Response headers
* Server information
* Redirected URL
* Cookies

This information can help provide an overview of the target's web technology and security configuration.

## Cookie Security Analysis

The scanner collects cookie information and checks available security-related attributes, including:

* Cookie name
* Secure flag
* HttpOnly flag
* SameSite attribute
* Domain
* Path
* Expiration information

These attributes are useful when reviewing how a web application handles browser cookies.

## Disclaimer

This project is created for **educational purposes and authorized security testing only**.

Do not use this tool to scan, test, attack, or disrupt websites, applications, or systems without explicit permission from the owner.

The author is not responsible for misuse of this software.



## Author

**Shaik Abdul Kalam**

GitHub: `abdul1818-web`

## License

This project is currently intended for educational and learning purposes. A license may be added in a future release.

