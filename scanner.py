import requests
import socket
from urllib.parse import urlparse

def scan_website(url):
    result = {}
    risk_score = 0
    vulnerabilities = []

    try:
        if not url.startswith("http"):
            url = "http://" + url

        response = requests.get(url, timeout=5)
        headers = response.headers
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        # ---------------- HTTPS CHECK ----------------
        if not url.startswith("https"):
            vulnerabilities.append({
                "name": "Missing HTTPS",
                "severity": "High",
                "owasp": "A02: Cryptographic Failures"
            })
            risk_score += 30

        # ---------------- SECURITY HEADERS ----------------
        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-Content-Type-Options"
        ]

        for header in security_headers:
            if header not in headers:
                vulnerabilities.append({
                    "name": f"Missing Header: {header}",
                    "severity": "Medium",
                    "owasp": "A05: Security Misconfiguration"
                })
                risk_score += 10

        # ---------------- OPEN PORT CHECK ----------------
        common_ports = [21, 22, 23, 25, 80, 443, 3306]
        open_ports = []

        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((hostname, port)) == 0:
                open_ports.append(port)
            sock.close()

        if len(open_ports) > 2:
            vulnerabilities.append({
                "name": "Multiple Open Ports Detected",
                "severity": "Medium",
                "owasp": "A05: Security Misconfiguration"
            })
            risk_score += 15

        # ---------------- SERVER INFO ----------------
        server = headers.get("Server")
        if server:
            vulnerabilities.append({
                "name": "Server Information Exposure",
                "severity": "Low",
                "owasp": "A05: Security Misconfiguration"
            })
            risk_score += 5

        # ---------------- SQL INJECTION TEST ----------------
        sqli_payload = "' OR '1'='1"
        test_url = url + "?test=" + sqli_payload
        sqli_response = requests.get(test_url)

        if "sql" in sqli_response.text.lower():
            vulnerabilities.append({
                "name": "Possible SQL Injection",
                "severity": "Critical",
                "owasp": "A03: Injection"
            })
            risk_score += 40

        # ---------------- XSS TEST ----------------
        xss_payload = "<script>alert(1)</script>"
        test_url = url + "?test=" + xss_payload
        xss_response = requests.get(test_url)

        if xss_payload in xss_response.text:
            vulnerabilities.append({
                "name": "Possible Cross-Site Scripting (XSS)",
                "severity": "High",
                "owasp": "A03: Injection"
            })
            risk_score += 30

        # ---------------- RISK LEVEL ----------------
        if risk_score >= 80:
            risk_level = "Critical"
        elif risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 25:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        result["vulnerabilities"] = vulnerabilities
        result["risk_score"] = risk_score
        result["risk_level"] = risk_level
        result["open_ports"] = open_ports

    except:
        result["error"] = "Website not reachable"

    return result
