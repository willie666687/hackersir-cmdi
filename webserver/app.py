from flask import Flask, request, render_template
import subprocess
import os

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    host = ""

    default_password = os.getenv("CMDI_PASSWORD", "admin123")
    password = request.args.get("password", "")
    if password != default_password:
        error = "Invalid password or missing password parameter."
        return render_template("error.html", error=error)
    if request.method == "POST":
        host = request.form.get("host", "")
        try:
            proc = subprocess.run(f"ping -c 3 {host}", shell=True, capture_output=True, text=True, timeout=8)
            result = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired:
            result = "Ping timeout."
    return render_template("index.html", host=host, result=result, password=password)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)