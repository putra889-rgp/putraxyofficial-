#tools by putraxyofficial ketauan rename gue viralin
import requests
import socket
import ssl
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def get_http_status(url):
    try:
        response = requests.get(url, timeout=10)
        return response.status_code
    except requests.RequestException as e:
        return f"Error: {e}"

def get_http_headers(url):
    try:
        response = requests.get(url, timeout=10)
        return response.headers
    except requests.RequestException as e:
        return f"Error: {e}"

def extract_emails(html):
    return list(set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', html)))

def ssl_certificate_info(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'valid_from': cert['notBefore'],
                    'valid_until': cert['notAfter'],
                }
    except Exception as e:
        return f"SSL Error: {e}"

def port_scan(domain, ports=None):
    if ports is None:
        ports = [21, 22, 80, 443, 8080]
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((domain, port)) == 0:
                    open_ports.append(port)
        except Exception:
            continue
    return open_ports

def test_xss(url, payload='<script>alert("xss_test")</script>'):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)

    if not query:
        return "No query parameters to test for XSS."

    vulnerable = []

    for param in query:
        test_params = query.copy()
        test_params[param] = payload
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))

        try:
            res = requests.get(test_url, timeout=10)
            if payload in res.text:
                vulnerable.append(param)
        except Exception:
            continue

    if vulnerable:
        return f"Potential XSS vulnerability in parameters: {', '.join(vulnerable)}"
    return "No XSS vulnerability detected (basic test)."
