import requests

def scan_website(url):

    results = []

    try:
        response = requests.get("http://" + url)

        results.append(f"Website Status Code: {response.status_code}")

        headers = response.headers

        # Security Header Checks
        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "Strict-Transport-Security",
            "X-Content-Type-Options"
        ]

        for header in security_headers:

            if header in headers:
                results.append(f"[✔] {header} Found")
            else:
                results.append(f"[✘] {header} Missing")

        # Server Info
        if "Server" in headers:
            results.append(f"Server Info: {headers['Server']}")

    except Exception as e:
        results.append(f"Error: {str(e)}")

    return results