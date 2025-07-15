import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import sys

# ---------------- BANNER SECTION ---------------- #
def print_banner():
    ascii_logo = r"""
      ______
   .-'      '-.
  /            \
 |              |
 |,  .-.  .-.  ,|
 | )(_o/  \o_)( |
 |/     /\     \|
 (_     ^^     _)
  \__|IIIIII|__/
   | \IIIIII/ |
   \          /
    `--------`
    """

    tool_name = "Z E R A"

    print("\033[91m")  # Start red text
    print("╔" + "═" * 20 + "╗")
    print(f"║      {tool_name.center(10)}      ║")
    print("╚" + "═" * 20 + "╝")
    print(" " + "─" * 22)
    print("\033[1m" + "Created by Abhinav - Cyber Security Analyst".center(24) + "\033[0m")
    print("\033[0m")  # Reset color
    print(ascii_logo)

# ---------------- SCANNER VARIABLES ---------------- #
xss_results = []
sqli_results = []
open_redirect_results = []
security_headers_results = []

REPORT_FILE = "scan_report.txt"

OPEN_REDIRECT_TEST_URL = "http://evil.com"
SECURITY_HEADERS = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

# ---------------- UTILITY FUNCTIONS ---------------- #
def write_report_line(line):
    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def clear_report():
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("Web Vulnerability Scan Report\n")
        f.write("=============================\n\n")

# ---------------- SCANNER FUNCTIONS ---------------- #
def crawl_site(url):
    visited = set()
    to_visit = [url]

    while to_visit:
        current_url = to_visit.pop()
        if current_url in visited:
            continue
        visited.add(current_url)

        print(f"[+] Crawling: {current_url}")
        write_report_line(f"[+] Crawling: {current_url}")

        try:
            response = requests.get(current_url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', href=True):
                full_link = urljoin(current_url, link['href'])
                if full_link.startswith(url):
                    to_visit.append(full_link)
        except Exception as e:
            error_msg = f"[-] Failed: {current_url} - {str(e)}"
            print(error_msg)
            write_report_line(error_msg)

    return visited

def test_open_redirect(url):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)

    for param in params:
        if param.lower() in ["redirect", "url", "next", "dest"]:
            injected_params = params.copy()
            injected_params[param] = [OPEN_REDIRECT_TEST_URL]
            injected_query = "&".join(f"{k}={v[0]}" for k,v in injected_params.items())
            test_url = parsed_url._replace(query=injected_query).geturl()

            try:
                res = requests.get(test_url, allow_redirects=False, timeout=5)
                if res.status_code in [301, 302, 303, 307, 308]:
                    location = res.headers.get("Location", "")
                    if OPEN_REDIRECT_TEST_URL in location:
                        msg = f"[Open Redirect] Vulnerability found at {test_url}"
                        print(msg)
                        write_report_line(msg)
                        open_redirect_results.append(test_url)
            except Exception as e:
                error_msg = f"[-] Error testing open redirect at {test_url}: {e}"
                print(error_msg)
                write_report_line(error_msg)

def check_security_headers(url):
    try:
        res = requests.get(url, timeout=5)
        missing = [header for header in SECURITY_HEADERS if header not in res.headers]
        if missing:
            msg = f"[Security Headers] Missing {', '.join(missing)} in response from {url}"
            print(msg)
            write_report_line(msg)
            security_headers_results.append((url, missing))
    except Exception as e:
        error_msg = f"[-] Error checking security headers at {url} - {str(e)}"
        print(error_msg)
        write_report_line(error_msg)

def test_vulnerabilities(urls):
    xss_payload = "<script>alert('XSS')</script>"
    sqli_payload = "' OR '1'='1"

    print("\n[★] Testing URL Parameters for Vulnerabilities...")
    write_report_line("\n[★] Testing URL Parameters for Vulnerabilities...")

    for url in urls:
        if "=" in url:
            test_xss = url.replace("=", "=" + xss_payload)
            test_sql = url.replace("=", "=" + sqli_payload)

            try:
                xss_res = requests.get(test_xss)
                if xss_payload in xss_res.text:
                    msg = f"[XSS] Found at {test_xss}"
                    print(msg)
                    write_report_line(msg)
                    xss_results.append(test_xss)

                sql_res = requests.get(test_sql)
                if "sql" in sql_res.text.lower() or "error" in sql_res.text.lower():
                    msg = f"[SQLi] Found at {test_sql}"
                    print(msg)
                    write_report_line(msg)
                    sqli_results.append(test_sql)
            except Exception as e:
                err_msg = f"[-] Error testing URL: {url} - {str(e)}"
                print(err_msg)
                write_report_line(err_msg)

            test_open_redirect(url)

        check_security_headers(url)

def scan_forms_for_vulnerabilities(url):
    xss_payload = "<script>alert('XSS')</script>"

    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            form_url = urljoin(url, action)
            data = {input.get("name"): xss_payload for input in inputs if input.get("name")}

            print(f"[+] Testing form at: {form_url} (method: {method.upper()})")
            write_report_line(f"[+] Testing form at: {form_url} (method: {method.upper()})")

            if method == "post":
                response = requests.post(form_url, data=data)
            else:
                response = requests.get(form_url, params=data)

            if xss_payload in response.text:
                msg = f"[XSS] Found in form at {form_url}"
                print(msg)
                write_report_line(msg)
                xss_results.append(form_url)
            elif "sql" in response.text.lower() or "error" in response.text.lower():
                msg = f"[SQLi] Found in form at {form_url}"
                print(msg)
                write_report_line(msg)
                sqli_results.append(form_url)

    except Exception as e:
        error_msg = f"[-] Error testing forms at {url} - {str(e)}"
        print(error_msg)
        write_report_line(error_msg)

def generate_html_report():
    def table(items, cls):
        if not items:
            return "<p>None</p>"
        rows = "".join(f"<tr><td>{item}</td></tr>" for item in items)
        return f'<table class="{cls}"><tr><th>URL</th></tr>{rows}</table>'

    def header_table(items):
        if not items:
            return "<p>None</p>"
        rows = "".join(f"<tr><td>{url}</td><td>{', '.join(headers)}</td></tr>" for url, headers in items)
        return f'<table class="missingheaders"><tr><th>URL</th><th>Missing Headers</th></tr>{rows}</table>'

    html = f"""
    <html><head><title>WebScan Report</title>
    <style>
    body {{ font-family:sans-serif; }}
    th {{ background:#333;color:white; }}
    td {{ border:1px solid #ddd;padding:5px; }}
    table {{ border-collapse:collapse;width:100%;margin-bottom:20px; }}
    </style></head><body>
    <h1>Web Vulnerability Scan Report</h1>
    <h2>XSS Found ({len(xss_results)})</h2>{table(xss_results, "xss")}
    <h2>SQLi Found ({len(sqli_results)})</h2>{table(sqli_results, "sqli")}
    <h2>Open Redirects ({len(open_redirect_results)})</h2>{table(open_redirect_results, "openredirect")}
    <h2>Missing Security Headers ({len(security_headers_results)})</h2>{header_table(security_headers_results)}
    </body></html>
    """
    with open("scan_report.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("[✓] HTML report generated: scan_report.html")

# ------------------ MAIN ENTRY ------------------ #
if __name__ == "__main__":
    print_banner()
    clear_report()

    print("[INFO] Starting the scanner...\n")
    sys.stdout.flush()

    target_url = input("Enter a website URL (e.g., http://example.com): ").strip()
    if not target_url:
        target_url = "http://example.com"
        print(f"[INFO] Using default URL: {target_url}")

    links = crawl_site(target_url)

    print("\n[✓] Crawled Links:")
    for link in links:
        print(link)
        write_report_line(link)

    test_vulnerabilities(links)

    print("\n[★] Scanning Forms for Vulnerabilities...\n")
    for link in links:
        scan_forms_for_vulnerabilities(link)

    # Summary
    print("\n🔍 SCAN SUMMARY")
    print("======================")
    print(f"XSS Found: {len(xss_results)}")
    print(f"SQLi Found: {len(sqli_results)}")
    print(f"Open Redirects: {len(open_redirect_results)}")
    print(f"Missing Headers: {len(security_headers_results)}")

    generate_html_report()

