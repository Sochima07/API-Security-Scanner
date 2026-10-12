from flask import Flask, request, jsonify, render_template, send_from_directory
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import requests
import json
import csv

app = Flask(__name__)

# Ensure the reports folder exists
os.makedirs('reports', exist_ok=True)

# Timeout for outbound requests (seconds)
REQUEST_TIMEOUT = 10

# Home Route
@app.route("/")
def home():
    return render_template("app.html")

# Vulnerability Scanning Route
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url") if data else None

    # Validate input
    if not url or not url.strip():
        return jsonify({"error": "A valid URL is required."}), 400

    url = url.strip()

    results = {}

    # SQL Injection
    sql_result = check_sql_injection(url)
    results["SQL Injection"] = sql_result["vulnerability"]

    # XSS
    xss_result = check_xss(url)
    results["XSS"] = xss_result["vulnerability"]

    # CSRF
    csrf_result = check_csrf(url)
    results["CSRF"] = csrf_result["vulnerability"]

    # Command Injection
    cmd_injection_result = check_command_injection(url)
    results["Command Injection"] = cmd_injection_result["vulnerability"]

    # Log scan result
    log_scan_result(url, results, file_type="json")

    # Generate PDF report
    pdf_file_path = generate_pdf_report(url, results)

    return jsonify({
        "results": results,
        "pdf_report": f"/reports/{os.path.basename(pdf_file_path)}"
    })

# PDF Report Generation
def generate_pdf_report(url, results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    full_filename = f"reports/scan_report_{timestamp}.pdf"

    c = canvas.Canvas(full_filename, pagesize=A4)
    width, height = A4

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(width / 2, height - 50, "API Vulnerability Scan Report")

    # Scanned URL
    c.setFont("Helvetica", 12)
    c.drawString(50, height - 80, f"Scanned URL: {url}")

    # Scan timestamp
    c.setFont("Helvetica", 10)
    readable_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.drawString(50, height - 100, f"Scan Date: {readable_time}")

    # Results
    c.setFont("Helvetica", 11)
    y = height - 140
    for vuln_type, vuln_status in results.items():
        # Color-code: red for detected, green for clean
        if "detected" in vuln_status.lower():
            c.setFillColorRGB(0.8, 0, 0)
        elif "no " in vuln_status.lower():
            c.setFillColorRGB(0, 0.5, 0)
        else:
            c.setFillColorRGB(0.4, 0.4, 0.4)

        c.drawString(50, y, f"{vuln_type}: {vuln_status}")
        c.setFillColorRGB(0, 0, 0)  # Reset to black
        y -= 25

    c.save()
    return full_filename

# Route to serve PDF reports
@app.route('/reports/<filename>')
def download_report(filename):
    return send_from_directory('reports', filename, as_attachment=True, mimetype='application/pdf')

# SQL Injection Scanner
def check_sql_injection(url):
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "\" OR \"1\"=\"1\"",
        "1; DROP TABLE users--",
    ]
    # Common SQL error signatures from real databases
    sql_error_patterns = [
        "sql syntax",
        "mysql_fetch",
        "unclosed quotation mark",
        "microsoft ole db",
        "odbc drivers",
        "postgresql",
        "sqlite3.operationalerror",
        "ora-01756",
        "quoted string not properly terminated",
        "you have an error in your sql syntax",
        "warning: mysql",
        "pg_query",
        "supplied argument is not a valid",
    ]
    try:
        for payload in payloads:
            response = requests.post(
                url,
                json={"username": payload, "password": payload},
                timeout=REQUEST_TIMEOUT,
            )
            response_lower = response.text.lower()
            if any(pattern in response_lower for pattern in sql_error_patterns):
                return {"vulnerability": f"Possible SQL Injection detected! (payload: {payload})"}
    except requests.exceptions.Timeout:
        return {"vulnerability": "Error testing SQL Injection: request timed out."}
    except Exception as e:
        return {"vulnerability": f"Error testing SQL Injection: {str(e)}"}
    return {"vulnerability": "No SQL Injection vulnerability detected."}

# XSS Scanner
def check_xss(url):
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "\"><script>alert('XSS')</script>",
    ]
    try:
        for payload in payloads:
            response = requests.post(
                url,
                data={"input": payload},
                timeout=REQUEST_TIMEOUT,
            )
            if payload in response.text:
                return {"vulnerability": f"Possible XSS vulnerability detected! (payload reflected in response)"}
    except requests.exceptions.Timeout:
        return {"vulnerability": "Error testing XSS: request timed out."}
    except Exception as e:
        return {"vulnerability": f"Error testing XSS: {str(e)}"}
    return {"vulnerability": "No XSS vulnerability detected."}

# CSRF Scanner
def check_csrf(url):
    try:
        headers = {"Content-Type": "application/json"}
        payload = {"test": "csrf_test"}
        response = requests.post(url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT)

        if response.status_code in [200, 201]:
            # Check response body for CSRF token references
            body_has_csrf = "csrf" in response.text.lower()

            # Check response headers for common CSRF protection headers
            response_headers_lower = {k.lower(): v for k, v in response.headers.items()}
            has_csrf_header = any(
                key in response_headers_lower
                for key in ["x-csrf-token", "x-xsrf-token"]
            )

            # Check cookies for CSRF tokens
            has_csrf_cookie = any(
                "csrf" in cookie.name.lower() or "xsrf" in cookie.name.lower()
                for cookie in response.cookies
            )

            if not body_has_csrf and not has_csrf_header and not has_csrf_cookie:
                return {"vulnerability": "Possible CSRF vulnerability detected! (no CSRF token found in response, headers, or cookies)"}
    except requests.exceptions.Timeout:
        return {"vulnerability": "Error testing CSRF: request timed out."}
    except Exception as e:
        return {"vulnerability": f"Error testing CSRF: {str(e)}"}
    return {"vulnerability": "No CSRF vulnerability detected."}

# Command Injection Scanner
def check_command_injection(url):
    test_cases = [
        {"payload": "test; id", "signatures": ["uid=", "gid=", "groups="]},
        {"payload": "test && cat /etc/passwd", "signatures": ["root:x:0:", "root:*:0:", "daemon:x:", "/bin/bash", "/bin/sh"]},
        {"payload": "test | uname -a", "signatures": ["Linux", "Darwin", "GNU/Linux", "x86_64"]},
    ]
    try:
        for test in test_cases:
            payload = test["payload"]
            response = requests.post(
                url,
                json={"input": payload},
                timeout=REQUEST_TIMEOUT,
            )
            # Make sure match is not just echoing the input payload key
            response_body = response.text
            for sig in test["signatures"]:
                if sig.lower() in response_body.lower() and sig.lower() not in payload.lower():
                    return {"vulnerability": f"Possible Command Injection detected! (signature '{sig}' observed for payload: {payload})"}
    except requests.exceptions.Timeout:
        return {"vulnerability": "Error testing Command Injection: request timed out."}
    except Exception as e:
        return {"vulnerability": f"Error testing Command Injection: {str(e)}"}
    return {"vulnerability": "No Command Injection vulnerability detected."}

# Function to log scan results
def log_scan_result(url, results, file_type="json"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "timestamp": timestamp,
        "url": url,
        "results": results
    }

    if file_type == "json":
        filename = "scan_logs.json"
        filepath = os.path.join("reports", filename)

        # If file exists, load and append; else create new
        if os.path.exists(filepath):
            with open(filepath, "r") as file:
                try:
                    data = json.load(file)
                except json.JSONDecodeError:
                    data = []
        else:
            data = []

        data.append(log_entry)

        with open(filepath, "w") as file:
            json.dump(data, file, indent=4)

    elif file_type == "csv":
        filename = "scan_logs.csv"
        filepath = os.path.join("reports", filename)
        file_exists = os.path.isfile(filepath)

        with open(filepath, "a", newline="") as csvfile:
            fieldnames = ["timestamp", "url"] + list(results.keys())
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            if not file_exists:
                writer.writeheader()

            row = {"timestamp": timestamp, "url": url}
            row.update(results)
            writer.writerow(row)

# Run the Flask app
if __name__ == "__main__":
    app.run(debug=True)