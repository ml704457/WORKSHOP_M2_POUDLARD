# app.py
import os
import sqlite3
import csv
from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template, flash, send_file, abort, Response
from functools import wraps
import io

# Optional: for xlsx export
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except Exception:
    PANDAS_AVAILABLE = False

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "submissions.db")
CSV_PATH = os.path.join(APP_DIR, "submissions.csv")

# Admin credentials (set these env vars in production)
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "changeme")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-me-for-prod")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        firstname TEXT,
        lastname TEXT,
        token TEXT,
        ip TEXT,
        user_agent TEXT,
        timestamp TEXT
    )
    """)
    conn.commit()
    conn.close()

def save_submission(firstname, lastname, token, ip, ua):
    ts = datetime.utcnow().isoformat() + "Z"
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO submissions (firstname, lastname, token, ip, user_agent, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
              (firstname, lastname, token, ip, ua, ts))
    conn.commit()
    conn.close()
    new_file = not os.path.exists(CSV_PATH)
    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["firstname","lastname","token","ip","user_agent","timestamp"])
        writer.writerow([firstname, lastname, token, ip, ua, ts])

def check_auth(username, password):
    return username == ADMIN_USER and password == ADMIN_PASS

def authenticate():
    return Response('Authentication required', 401, {'WWW-Authenticate': 'Basic realm="Admin Area"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route("/", methods=["GET", "POST"])
def index():
    # optional token param used to correlate with canary hits (if any)
    token = request.args.get("token", "")
    if request.method == "POST":
        firstname = (request.form.get("firstname") or "").strip()
        lastname = (request.form.get("lastname") or "").strip()
        consent = request.form.get("consent") == "on"
        token_hidden = request.form.get("token_hidden", "")
        if not consent:
            flash("Le consentement est requis pour envoyer vos données.", "error")
            return redirect(url_for("index", token=token_hidden or token))
        if not firstname or not lastname:
            flash("Prénom et nom requis.", "error")
            return redirect(url_for("index", token=token_hidden or token))
        # Capture IP and UA
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        ua = request.headers.get("User-Agent", "")
        save_submission(firstname, lastname, token_hidden or token, ip, ua)
        flash("Merci — vos données ont bien été enregistrées.", "success")
        return redirect(url_for("index"))
    return render_template("index.html", token=token)

@app.route("/admin/list")
@requires_auth
def admin_list():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT firstname, lastname, token, ip, user_agent, timestamp FROM submissions ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return render_template("admin.html", rows=rows)

@app.route("/admin/export_csv")
@requires_auth
def export_csv():
    if not os.path.exists(CSV_PATH):
        return "No submissions."
    return send_file(CSV_PATH, as_attachment=True, download_name="submissions.csv")

@app.route("/admin/export_xlsx")
@requires_auth
def export_xlsx():
    if not PANDAS_AVAILABLE:
        return "Pandas not installed on server. Install pandas and openpyxl to enable XLSX export."
    if not os.path.exists(CSV_PATH):
        return "No submissions."
    df = pd.read_csv(CSV_PATH, encoding="utf-8")
    buf = io.BytesIO()
    df.to_excel(buf, index=False)
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name="submissions.xlsx", mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

@app.route("/admin/purge", methods=["POST"])
@requires_auth
def admin_purge():
    # Purge all stored data (DB + CSV)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    if os.path.exists(CSV_PATH):
        os.remove(CSV_PATH)
    init_db()
    return "Data purged."

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
