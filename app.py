from flask import Flask, render_template, request
from scanner import scan_website

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"]
        results = scan_website(url)
        return render_template("result.html", results=results)
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
