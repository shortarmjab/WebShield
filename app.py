# app.py

from flask import Flask, render_template, request
from flask import redirect, session
from flask import make_response

import requests

from io import BytesIO

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import (
    getSampleStyleSheet
)

from reportlab.lib.pagesizes import letter

import firebase_admin

from firebase_admin import credentials
from firebase_admin import firestore

import pyrebase

# ---------------------------------
# FLASK
# ---------------------------------

app = Flask(__name__)

app.secret_key = "webshield_secret_key"

scan_result = {}

# ---------------------------------
# FIREBASE ADMIN
# ---------------------------------

cred = credentials.Certificate(
    "firebase_key.json"
)

firebase_admin.initialize_app(cred)

firestore_db = firestore.client()

# ---------------------------------
# FIREBASE CONFIG
# ---------------------------------

firebaseConfig = {

    "apiKey": "AIzaSyAODBnXu4DSgA3nfhX2pM4_u25mzoczUJU",

    "authDomain": "webshield18.firebaseapp.com",

    "databaseURL": "https://webshield18-default-rtdb.firebaseio.com",

    "projectId": "webshield18",

    "storageBucket": "webshield18.firebasestorage.app",

    "messagingSenderId": "186716325727",

    "appId": "1:186716325727:web:c7dee3e04ff8221fea18ea"
}

firebase = pyrebase.initialize_app(
    firebaseConfig
)

auth = firebase.auth()

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
# LOGIN PAGE
# ---------------------------------

@app.route('/login')
def login_page():

    return render_template('login.html')

# ---------------------------------
# SIGNUP PAGE
# ---------------------------------

@app.route('/signup')
def signup_page():

    return render_template('signup.html')

# ---------------------------------
# REGISTER USER
# ---------------------------------

@app.route('/register', methods=['POST'])
def register():

    username = request.form['username']

    email = request.form['email']

    password = request.form['password']

    try:

        auth.create_user_with_email_and_password(
            email,
            password
        )

        firestore_db.collection('users').add({

            'username': username,

            'email': email
        })

        return redirect('/login')

    except Exception as e:

        print(e)

        return redirect('/signup')

# ---------------------------------
# LOGIN USER
# ---------------------------------

@app.route('/login-user', methods=['POST'])
def login_user():

    email = request.form['email']

    password = request.form['password']

    try:

        auth.sign_in_with_email_and_password(
            email,
            password
        )

        session['user'] = email

        return redirect('/')

    except Exception as e:

        print(e)

        return redirect('/login')

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

        # SAVE SCAN HISTORY

        if 'user' in session:

            firestore_db.collection(
                'scan_history'
            ).add({

                'user': session['user'],

                'website': url,

                'status_code': response.status_code,

                'connection': "HTTPS"
            })

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
# LOGOUT
# ---------------------------------

@app.route('/logout')
def logout():

    session.pop('user', None)

    return redirect('/')

# ---------------------------------
# DOWNLOAD REPORT
# ---------------------------------

@app.route('/download-report')
def download_report():

    buffer = BytesIO()

    doc = SimpleDocTemplate(

        buffer,

        pagesize=letter
    )

    styles = getSampleStyleSheet()

    elements = []

    elements.append(

        Paragraph(
            "WebShield Vulnerability Report",
            styles['Title']
        )
    )

    elements.append(Spacer(1, 20))

    elements.append(

        Paragraph(
            f"<b>Target Website:</b> {scan_result['website']}",
            styles['BodyText']
        )
    )

    elements.append(

        Paragraph(
            f"<b>Status Code:</b> {scan_result['status_code']}",
            styles['BodyText']
        )
    )

    elements.append(

        Paragraph(
            f"<b>Connection:</b> {scan_result['secure_connection']}",
            styles['BodyText']
        )
    )

    elements.append(Spacer(1, 20))

    elements.append(

        Paragraph(
            "Security Findings",
            styles['Heading2']
        )
    )

    elements.append(Spacer(1, 10))

    for item in scan_result['headers']:

        text = f"""

        <b>{item['header']}</b><br/>

        Status: {item['status']}<br/>

        Description: {item['message']}<br/><br/>

        """

        elements.append(

            Paragraph(
                text,
                styles['BodyText']
            )
        )

    doc.build(elements)

    pdf = buffer.getvalue()

    buffer.close()

    response = make_response(pdf)

    response.headers['Content-Type'] = 'application/pdf'

    response.headers['Content-Disposition'] = (

        'attachment; filename=WebShield_Report.pdf'
    )

    return response

# ---------------------------------
# RUN
# ---------------------------------

if __name__ == '__main__':

    app.run(debug=True)