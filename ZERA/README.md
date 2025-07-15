# ZERA - Web Vulnerability Scanner CLI Tool

ZERA is a command-line tool written in Python to scan websites for common web vulnerabilities such as:

- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Open Redirect vulnerabilities
- Missing Security Headers

---

## Features

- Crawls the target website to gather URLs
- Tests URL parameters for XSS and SQLi
- Detects open redirect issues
- Checks for missing important HTTP security headers
- Scans forms for XSS and SQLi vulnerabilities
- Generates an HTML report summarizing findings

---

## Installation

Make sure you have Python 3.6+ installed.

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/zera-scanner.git
   cd zera-scanner

