# app.py

from flask import Flask, render_template, request, redirect
import requests

app = Flask(__name__)

scan_result = {}

# ---------------------------------
# CHECK SECURITY HEADERS
# ---------------------------------

def check_security_headers(headers):

    results = []

    security_headers = {

        "Content-Security-Policy":
        "Protects against XSS attacks",

        "Strict-Transport-Security":
        "Forces HTTPS",

        "X-Frame-Options":
        "Prevents clickjacking",

        "X-Content-Type-Options":
        "Stops MIME sniffing",

        "Referrer-Policy":
        "Controls referrer information"
    }

    for header, description in security_headers.items():

        if header in headers:

            results.append({

                "header": header,
                "status": "Present",
                "message": description
            })

        else:

            results.append({

                "header": header,
                "status": "Missing",
                "message": f"{header} header missing"
            })

    return results

# ---------------------------------
# HOME
# ---------------------------------

@app.route('/')
def home():

    return render_template('index.html')

# ---------------------------------
# SCAN
# ---------------------------------

@app.route('/scan', methods=['POST'])
def scan():

    global scan_result

    url = request.form['url']

    if not url.startswith("http://") and not url.startswith("https://"):

        url = "https://" + url

    try:

        response = requests.get(url, timeout=5)

        headers = response.headers

        security_results = check_security_headers(headers)

        scan_result = {

            "website": url,

            "status_code": response.status_code,

            "secure_connection":
            "HTTPS" if url.startswith("https") else "HTTP",

            "headers": security_results
        }

    except Exception as e:

        scan_result = {

            "website": url,

            "status_code": "Error",

            "secure_connection": "Unknown",

            "headers": [

                {

                    "header": "Scan Failed",

                    "status": "Missing",

                    "message": str(e)
                }

            ]
        }

    return render_template('loading.html')

# ---------------------------------
# RESULT
# ---------------------------------

@app.route('/result')
def result():

    return render_template(

        'result.html',

        result=scan_result
    )

# ---------------------------------
# RUN
# ---------------------------------

if __name__ == '__main__':

    app.run(debug=True)