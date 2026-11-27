import os
import json
import time
import secrets
import sqlite3
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

app = FastAPI()

HIBP_API_KEY = os.getenv("HIBP_API_KEY")
BASE_URL = "http://127.0.0.1:8000"
DB_FILE = "breachalert.db"
CACHE_HOURS = 24
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
MAIL_FROM = os.getenv("MAIL_FROM", SMTP_USER)
HIBP_DELAY_SECONDS = 1.6  # pause between real API calls (rate limit)

SAMPLE_BREACHES = [
    {"Name": "ExampleSite", "BreachDate": "2019-05-01",
     "DataClasses": ["Email addresses", "Passwords"]},
    {"Name": "DemoShop", "BreachDate": "2021-08-12",
     "DataClasses": ["Email addresses", "Phone numbers", "Credit cards"]},
]


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS monitored_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            token TEXT NOT NULL,
            verified INTEGER NOT NULL DEFAULT 0)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS scan_cache (
            email TEXT PRIMARY KEY,
            result TEXT NOT NULL,
            scanned_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS seen_breaches (
            email TEXT NOT NULL,
            breach_name TEXT NOT NULL,
            PRIMARY KEY (email, breach_name))""")


init_db()


class EmailIn(BaseModel):
    email: str


def send_confirmation_email(email, token):
    link = f"{BASE_URL}/confirm/{token}"
    # Later we replace this print with SendGrid or Mailgun
    print(f"\n[EMAIL to {email}] Confirm your subscription: {link}\n")

def send_alert_email(email, new_breaches):
    names = ", ".join(b["Name"] for b in new_breaches)
    subject = f"BreachAlert: {len(new_breaches)} new breach(es) found"
    body = f"Your email {email} appeared in: {names}.\nChange your password on those sites."
    host = os.getenv("SMTP_HOST")
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    if not (host and user and password):
        print(f"\n[EMAIL to {email}] {subject}\n{body}\n")
        return
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = email
    msg.set_content(body)
    with smtplib.SMTP_SSL(host, 465) as server:
        server.login(user, password)
        server.send_message(msg)


def get_advice(breaches):
    leaked = set()
    for b in breaches:
        leaked.update(b["DataClasses"])
    advice = []
    if "Passwords" in leaked:
        advice.append("Change the password on affected sites and use a password manager so every site has a unique password.")
    if "Credit cards" in leaked:
        advice.append("Contact your bank, watch your statements, and consider freezing your credit.")
    if "Phone numbers" in leaked:
        advice.append("Be careful with unexpected calls and texts, as they may be scams.")
    if "Email addresses" in leaked:
        advice.append("Watch for phishing emails and turn on two-factor authentication.")
    return advice


def fetch_breaches(email):
    """Ask HIBP (or use sample data when there is no API key)."""
    if not HIBP_API_KEY:
        return "sample data", SAMPLE_BREACHES

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {"hibp-api-key": HIBP_API_KEY, "user-agent": "BreachAlert"}
    response = httpx.get(url, headers=headers, timeout=10)

    if response.status_code == 404:
        return "hibp", []
    if response.status_code == 429:
        raise HTTPException(status_code=429, detail="Rate limited, try again later")
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="HIBP error")

    breaches = [
        {"Name": b["Name"], "BreachDate": b["BreachDate"], "DataClasses": b["DataClasses"]}
        for b in response.json()
    ]
    return "hibp", breaches


def lookup(email, force=False):
    """Return breach results, using the 24-hour cache unless force=True."""
    now = datetime.now(timezone.utc)
    if not force:
        with get_db() as conn:
            row = conn.execute(
                "SELECT result, scanned_at FROM scan_cache WHERE email = ?", (email,)
            ).fetchone()
        if row:
            age = now - datetime.fromisoformat(row["scanned_at"])
            if age < timedelta(hours=CACHE_HOURS):
                result = json.loads(row["result"])
                result["cached"] = True
                return result

    source, breaches = fetch_breaches(email)
    result = {"email": email, "source": source, "breaches": breaches,
              "advice": get_advice(breaches), "cached": False}
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scan_cache (email, result, scanned_at) VALUES (?, ?, ?)",
            (email, json.dumps(result), now.isoformat()))
    return result


def scan_all():
    """Nightly job: rescan every verified email and report NEW breaches."""
    print("\n[SCAN] Starting scan of all verified emails")
    with get_db() as conn:
        emails = [r["email"] for r in conn.execute(
            "SELECT email FROM monitored_emails WHERE verified = 1")]

    for i, email in enumerate(emails):
        try:
            result = lookup(email, force=True)
        except HTTPException as e:
            print(f"[SCAN] {email}: skipped ({e.detail})")
            continue

        with get_db() as conn:
            seen = {r["breach_name"] for r in conn.execute(
                "SELECT breach_name FROM seen_breaches WHERE email = ?", (email,))}
            new = [b for b in result["breaches"] if b["Name"] not in seen]
            for b in new:
                conn.execute(
                    "INSERT OR IGNORE INTO seen_breaches (email, breach_name) VALUES (?, ?)",
                    (email, b["Name"]))

        if new:
            names = ", ".join(b["Name"] for b in new)
            print(f"[ALERT] {email}: {len(new)} new breach(es): {names}")
            try:
                send_alert_email(email, new)
            except Exception as e:
                print(f"[ALERT] could not send email to {email}: {e}")

        if HIBP_API_KEY and i < len(emails) - 1:
            time.sleep(HIBP_DELAY_SECONDS)

    print("[SCAN] Done\n")
    return len(emails)


scheduler = BackgroundScheduler()
scheduler.add_job(scan_all, "cron", hour=2, minute=0)
scheduler.start()


@app.get("/")
def home():
    return FileResponse(Path(__file__).parent / "index.html")


@app.post("/emails")
def add_email(data: EmailIn):
    email = data.email.strip().lower()
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")
    token = secrets.token_urlsafe(24)
    with get_db() as conn:
        row = conn.execute(
            "SELECT verified FROM monitored_emails WHERE email = ?", (email,)
        ).fetchone()
        if row and row["verified"]:
            return {"message": "Email already verified"}
        if row:
            conn.execute("UPDATE monitored_emails SET token = ? WHERE email = ?",
                         (token, email))
        else:
            conn.execute("INSERT INTO monitored_emails (email, token) VALUES (?, ?)",
                         (email, token))
    send_confirmation_email(email, token)
    return {"message": "Confirmation email sent. Please check your inbox."}


@app.get("/confirm/{token}")
def confirm(token: str):
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE monitored_emails SET verified = 1 WHERE token = ?", (token,))
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Invalid or expired link")
    return {"message": "Email confirmed. Monitoring is now active."}


@app.get("/check/{email}")
def check_email(email: str):
    email = email.strip().lower()
    with get_db() as conn:
        row = conn.execute(
            "SELECT verified FROM monitored_emails WHERE email = ?", (email,)
        ).fetchone()
    if not row or not row["verified"]:
        raise HTTPException(status_code=403, detail="Email not verified")
    return lookup(email)


# TESTING ONLY: lets you run the nightly scan on demand.
# We will protect or remove this in Week 4 (security).
@app.post("/scan-now")
def scan_now():
    count = scan_all()
    return {"message": f"Scanned {count} verified email(s). See the terminal."}