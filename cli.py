#rename yatim asu
import argparse
from scanner import *

def run_scan(url, verbose=False):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    print(f"🔍 Scanning: {url}\n")

    status = get_http_status(url)
    print(f"[+] HTTP Status: {status}")

    headers = get_http_headers(url)
    if verbose and isinstance(headers, dict):
        print("[+] HTTP Headers:")
        for k, v in headers.items():
            print(f"    {k}: {v}")

    ssl_info = ssl_certificate_info(domain)
    print(f"[+] SSL Certificate:")
    if isinstance(ssl_info, dict):
        for k, v in ssl_info.items():
            print(f"    {k}: {v}")
    else:
        print(f"    {ssl_info}")

    ports = port_scan(domain)
    print(f"[+] Open Ports: {ports}")

    try:
        html = requests.get(url, timeout=10).text
        emails = extract_emails(html)
        print(f"[+] Emails Found: {emails if emails else 'None'}")
    except Exception as e:
        print(f"[!] Email Extraction Error: {e}")

    # XSS Test (basic)
    xss_result = test_xss(url)
    print(f"[+] XSS Scan Result: {xss_result}")

def parse_args():
    parser = argparse.ArgumentParser(description="Website Scanner CLI Tool")
    parser.add_argument('--url', required=True, help='Target website URL')
    parser.add_argument('--verbose', action='store_true', help='Show full headers')
    return parser.parse_args()
