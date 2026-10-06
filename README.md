# 🛡️ CyberSentinel: Web Security Audit Tool in Python 🛡️

CyberSentinel is a Python-based web vulnerability-assessment tool. It scans a
target web application for a range of common security issues and generates a
detailed HTML report with findings and recommended fixes, covering everything
from cross-site scripting (XSS) to insecure cookies and missing security
headers.

> ⚠️ **Authorized use only.** Only scan systems you own or have explicit,
> written permission to test. The tool asks you to confirm authorization
> before every scan.

## 🌐 Key Features

- Crawl a single page or an entire site (same-host, depth-limited)
- Passive technology fingerprinting from headers and HTML
- Detection checks for:
  - Reflected cross-site scripting (XSS)
  - SQL injection (error-based indicators)
  - HTTP Parameter Pollution (HPP)
  - Cross-Site Request Forgery (missing anti-CSRF tokens)
  - CRLF / HTTP response splitting
  - Local File Inclusion / path traversal
  - Directory listing
  - Missing security headers (HSTS, CSP, X-Content-Type-Options)
  - Clickjacking (missing framing protection)
  - Insecure cookies (Secure / HttpOnly / SameSite)
- Clean, severity-ranked HTML report saved to the `reports/` folder

## 🗂️ Project Structure

```
CyberSentinel/
├── main.py                 # Interactive CLI entry point
├── requirements.txt
├── smoke_test.py           # Offline self-test against a local server
└── cyber_sentinel/
    ├── client.py           # HTTP client + Page model
    ├── crawler.py          # Same-host crawler
    ├── app_detect.py       # Technology fingerprinting
    ├── attacks.py          # Detection checks
    ├── logger.py           # Findings + HTML report
    └── utils.py            # URL / config helpers
```

## 🛠️ Usage

1. Clone the repository and enter the folder:
   ```
   git clone https://github.com/AbdulMoeezMukadam/CyberSentinel.git
   cd CyberSentinel
   ```
2. Install the dependencies:
   ```
   pip install -r requirements.txt
   ```
   (On Windows, use `python -m pip install -r requirements.txt` or
   `py -m pip install -r requirements.txt`.)
3. Run the tool:
   ```
   python3 main.py
   ```
   (or `py main.py` on Windows)
4. Choose **1** to run, enter the target URL, confirm authorization, choose
   whether to crawl all pages, and pick an attack type (**1** runs all checks).
5. Open the generated report in the `reports/` folder.

### Quick self-test (no internet required)

```
python3 smoke_test.py
```

This starts a local, deliberately-weak server, scans it, and writes a sample
report. It should report 6 findings.

## 🔗 Dependencies

`requests`, `beautifulsoup4`, `lxml`, `tldextract`, `jinja2`

---

#cybersecurity #ethicalhacking #python #websecurity
