import json
import hmac
import os
import re
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import requests
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("VOID_SECRET_KEY", "CHANGE-ME-IN-PRODUCTION")
DB = os.environ.get("VOID_DB", "vault.db")
SESSION_MINUTES = int(os.environ.get("SESSION_MINUTES", "15"))

FERNET_KEY = os.environ.get("VOID_FERNET_KEY")
if not FERNET_KEY:
    # MVP convenience. For production, persist this as a protected secret.
    FERNET_KEY = Fernet.generate_key().decode()
    print("WARNING: Generated a temporary VOID_FERNET_KEY.")
    print("Set VOID_FERNET_KEY in .env and keep it backed up securely.")
fernet = Fernet(FERNET_KEY.encode())


@app.post("/telegram/webhook")
def telegram_webhook():

    secret = os.environ.get(
        "TELEGRAM_WEBHOOK_SECRET",
        ""
    )

    incoming_secret = request.headers.get(
        "X-Telegram-Bot-Api-Secret-Token",
        ""
    )

    if not secret or not hmac.compare_digest(
        incoming_secret,
        secret
    ):
        return {"ok": False}, 403

    update = request.get_json(
        silent=True
    ) or {}

    message = update.get("message", {})

    chat = message.get("chat", {})

    chat_id = chat.get("id")

    text = message.get("text", "").strip()

    if not chat_id:
        return {"ok": True}

    if text == "/start":

        telegram_api(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": (
                    "🔐 VOID connected.\n\n"
                    "Telegram is configured for "
                    "vault notifications.\n\n"
                    "Passwords are never sent "
                    "through Telegram."
                )
            }
        )

    elif text == "/help":

        telegram_api(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": (
                    "VOID Bot\n\n"
                    "/start - check connection\n"
                    "/help - show help\n\n"
                    "Credential retrieval happens "
                    "inside the secure VOID web vault."
                )
            }
        )

    else:

        telegram_api(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": (
                    "VOID received your message.\n\n"
                    "Open the VOID web vault for "
                    "credential access."
                )
            }
        )

    return {"ok": True}

# temp webhook

@app.get("/telegram/setup")
def telegram_setup():

    base_url = os.environ.get(
        "VOID_BASE_URL",
        ""
    ).rstrip("/")

    secret = os.environ.get(
        "TELEGRAM_WEBHOOK_SECRET",
        ""
    )

    if not base_url:
        return {
            "ok": False,
            "error": "VOID_BASE_URL missing"
        }, 400

    if not secret:
        return {
            "ok": False,
            "error": "TELEGRAM_WEBHOOK_SECRET missing"
        }, 400

    webhook_url = (
        f"{base_url}/telegram/webhook"
    )

    result = telegram_api(
        "setWebhook",
        {
            "url": webhook_url,
            "secret_token": secret,
            "drop_pending_updates": True
        }
    )

    return result or {
        "ok": False,
        "error": "Telegram API unavailable"
    }

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        master_hash TEXT NOT NULL,
        question TEXT NOT NULL,
        answer_hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        website TEXT NOT NULL,
        username_enc BLOB,
        password_enc BLOB NOT NULL,
        notes_enc BLOB,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)
    conn.commit()
    conn.close()


def setup_complete():
    conn = db()
    row = conn.execute("SELECT id FROM settings WHERE id=1").fetchone()
    conn.close()
    return row is not None


def encrypt(value):
    return fernet.encrypt((value or "").encode()).decode()


def decrypt(value):
    return fernet.decrypt(value.encode()).decode()


def send_telegram(message):

    chat_id = os.environ.get(
        "TELEGRAM_CHAT_ID",
        ""
    ).strip()

    if not chat_id:
        print("TELEGRAM_CHAT_ID is missing")
        return False

    result = telegram_api(
        "sendMessage",
        {
            "chat_id": chat_id,
            "text": message
        }
    )

    if result and result.get("ok"):
        print("Telegram notification sent")
        return True

    print("Telegram notification failed:", result)

    return False

def telegram_api(method, payload=None):

    token = os.environ.get(
        "TELEGRAM_BOT_TOKEN",
        ""
    ).strip()

    if not token:
        return None

    url = (
        "https://api.telegram.org/"
        f"bot{token}/{method}"
    )

    try:

        response = requests.post(
            url,
            json=payload or {},
            timeout=15
        )

        response.raise_for_status()

        return response.json()

    except Exception as exc:

        print("Telegram API error:", exc)

        return None




def extract_secret_candidates(text):
    """
    Local extraction of likely password/secret values.

    IMPORTANT:
    This function runs locally. The full password is NOT sent to Gemini.
    """
    candidates = []

    patterns = [
        r"(?i)(?:password|pass|pwd|pw)\s*[:=\-]\s*([^\s]+)",
        r"(?i)(?:secret|token|key)\s*[:=\-]\s*([^\s]+)",
    ]

    for pattern in patterns:
        for match in re.finditer(pattern, text):
            value = match.group(1).strip().strip('"\'')
            if value:
                candidates.append(value)

    return candidates


def redact_secrets(text):
    """
    Remove obvious password/secret values before sending text to Gemini.
    """
    patterns = [
        r"(?i)((?:password|pass|pwd|pw)\s*[:=\-]\s*)([^\s]+)",
        r"(?i)((?:secret|token|key)\s*[:=\-]\s*)([^\s]+)",
    ]

    redacted = text

    for pattern in patterns:
        redacted = re.sub(
            pattern,
            lambda m: m.group(1) + "[REDACTED]",
            redacted
        )

    return redacted


def gemini_parse(text):
    """
    Uses Gemini only for understanding the structure of the text.

    Password values are redacted before the request leaves VOID.
    """

    api_key = os.environ.get("GEMINI_API_KEY", "").strip()

    if not api_key:
        return None

    model = os.environ.get(
        "GEMINI_MODEL",
        "gemini-3.5-flash-lite"
    )

    safe_text = redact_secrets(text)

    prompt = f"""
You are the credential organization engine inside a private password vault.

Analyze the following user text and identify:

- website
- username
- email
- notes

DO NOT try to recover or invent passwords.
Anything marked [REDACTED] is a secret and must remain [REDACTED].

The user may write information in any order and may use casual language.

Return ONLY JSON.

Input:

{safe_text}
"""

    schema = {
        "type": "object",
        "properties": {
            "website": {"type": "string"},
            "username": {"type": "string"},
            "email": {"type": "string"},
            "notes": {"type": "string"}
        },
        "required": [
            "website",
            "username",
            "email",
            "notes"
        ]
    }

    url = (
        "https://generativelanguage.googleapis.com/v1beta/"
        f"models/{model}:generateContent"
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": prompt
                    }
                ]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "responseSchema": schema,
            "temperature": 0
        }
    }

    try:
        response = requests.post(
            url,
            params={"key": api_key},
            json=payload,
            timeout=20
        )

        response.raise_for_status()

        data = response.json()

        text_result = (
            data["candidates"][0]
            ["content"]["parts"][0]["text"]
        )

        return json.loads(text_result)

    except Exception as exc:
        print("Gemini parser error:", exc)
        return None


def parse_messy(text):

    # First: local secret extraction
    passwords = extract_secret_candidates(text)

    # Second: AI understands the non-secret structure
    ai_result = gemini_parse(text)

    if ai_result:

        website = ai_result.get("website", "").strip()
        username = ai_result.get("username", "").strip()
        email = ai_result.get("email", "").strip()
        notes = ai_result.get("notes", "").strip()

        if not username:
            username = email

        password = passwords[0] if passwords else ""

        return {
            "website": website,
            "username": username,
            "password": password,
            "notes": notes
        }

    # Fallback if Gemini is unavailable
    return local_parse_fallback(text)

def local_parse_fallback(text):

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    website = ""
    username = ""
    password = ""
    notes = []

    for line in lines:

        lower = line.lower()

        if re.match(
            r"^(password|pass|pwd|pw)\s*[:=\-]",
            lower
        ):
            match = re.split(
                r"[:=\-]",
                line,
                maxsplit=1
            )

            if len(match) == 2:
                password = match[1].strip()

            continue

        if re.match(
            r"^(username|user|email|mail|login)\s*[:=\-]",
            lower
        ):
            match = re.split(
                r"[:=\-]",
                line,
                maxsplit=1
            )

            if len(match) == 2:
                username = match[1].strip()

            continue

        if re.match(
            r"^(website|site|url|service|app)\s*[:=\-]",
            lower
        ):
            match = re.split(
                r"[:=\-]",
                line,
                maxsplit=1
            )

            if len(match) == 2:
                website = match[1].strip()

            continue

        email_match = re.search(
            r"[\w.+-]+@[\w-]+\.[\w.-]+",
            line
        )

        if email_match and not username:
            username = email_match.group(0)

        url_match = re.search(
            r"(https?://[^\s]+|"
            r"(?:www\.)?[a-zA-Z0-9-]+\."
            r"(?:com|in|org|net|io|dev|ai|co))",
            line
        )

        if url_match and not website:
            website = url_match.group(1)

        if not email_match and not url_match:
            notes.append(line)

    if not website and lines:
        website = lines[0]

    return {
        "website": website,
        "username": username,
        "password": password,
        "notes": "\n".join(notes)
    }

def logged_in():
    if not session.get("unlocked"):
        return False
    expires = session.get("expires_at", 0)
    if datetime.utcnow().timestamp() > expires:
        session.clear()
        return False
    return True


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not logged_in():
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def refresh_or_expire():
    if request.endpoint and request.endpoint not in {"static", "setup", "login", "verify"}:
        if session.get("unlocked"):
            if not logged_in():
                return redirect(url_for("login"))
            session["expires_at"] = (datetime.utcnow() + timedelta(minutes=SESSION_MINUTES)).timestamp()


@app.route("/")
def index():
    if not setup_complete():
        return redirect(url_for("setup"))
    if not logged_in():
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if setup_complete():
        return redirect(url_for("login"))
    if request.method == "POST":
        master = request.form.get("master_password", "")
        confirm = request.form.get("confirm_password", "")
        question = request.form.get("question", "").strip()
        answer = request.form.get("answer", "")
        if len(master) < 10:
            flash("Use a master password of at least 10 characters.", "error")
        elif master != confirm:
            flash("Master passwords do not match.", "error")
        elif not question or not answer:
            flash("Add a verification question and answer.", "error")
        else:
            conn = db()
            conn.execute(
                "INSERT INTO settings(id, master_hash, question, answer_hash) VALUES(1,?,?,?)",
                (generate_password_hash(master), question, generate_password_hash(answer.lower().strip())),
            )
            conn.commit()
            conn.close()
            flash("VOID vault created. Log in with your master password.", "success")
            return redirect(url_for("login"))
    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if not setup_complete():
        return redirect(url_for("setup"))
    if request.method == "POST":
        master = request.form.get("master_password", "")
        conn = db()
        row = conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
        conn.close()
        if row and check_password_hash(row["master_hash"], master):
            session["unlocked"] = True
            session["expires_at"] = (datetime.utcnow() + timedelta(minutes=SESSION_MINUTES)).timestamp()
            return redirect(url_for("dashboard"))
        session["wrong_master"] = True
        return redirect(url_for("verify"))
    return render_template("login.html")


@app.route("/verify", methods=["GET", "POST"])
def verify():
    if not setup_complete():
        return redirect(url_for("setup"))
    conn = db()
    row = conn.execute("SELECT question, answer_hash FROM settings WHERE id=1").fetchone()
    conn.close()
    if request.method == "POST":
        answer = request.form.get("answer", "")
        if row and check_password_hash(row["answer_hash"], answer.lower().strip()):
            # Per the requested recovery concept, a correct answer unlocks the vault.
            session["unlocked"] = True
            session["expires_at"] = (datetime.utcnow() + timedelta(minutes=SESSION_MINUTES)).timestamp()
            return redirect(url_for("dashboard"))
        flash("Verification failed. Vault remains locked.", "error")
    return render_template("verify.html", question=row["question"] if row else "")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    q = request.args.get("q", "").strip().lower()
    conn = db()
    rows = conn.execute("SELECT * FROM credentials ORDER BY website COLLATE NOCASE").fetchall()
    conn.close()

    creds = []
    for r in rows:
        item = {
            "id": r["id"],
            "website": r["website"],
            "username": decrypt(r["username_enc"]),
            "password": decrypt(r["password_enc"]),
            "notes": decrypt(r["notes_enc"]),
            "updated_at": r["updated_at"],
        }
        if q and q not in (item["website"] + " " + item["username"] + " " + item["notes"]).lower():
            continue
        creds.append(item)

    return render_template("dashboard.html", credentials=creds, query=q)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    parsed = {"website": "", "username": "", "password": "", "notes": ""}
    raw = ""
    if request.method == "POST":
        raw = request.form.get("raw", "")
        parsed = parse_messy(raw)
        if request.form.get("confirm_save") == "1":
            website = request.form.get("website", "").strip()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            notes = request.form.get("notes", "")
            if not website or not password:
                flash("Website and password are required.", "error")
            else:
                now = datetime.utcnow().isoformat(timespec="seconds")
                conn = db()
                conn.execute(
                    "INSERT INTO credentials(website, username_enc, password_enc, notes_enc, created_at, updated_at) VALUES(?,?,?,?,?,?)",
                    (website, encrypt(username), encrypt(password), encrypt(notes), now, now),
                )
                conn.commit()
                conn.close()
                send_telegram(f"VOID notification: a new credential was added for {website}. Open your VOID vault to view it.")
                flash("Credential encrypted and saved.", "success")
                return redirect(url_for("dashboard"))
    return render_template("add.html", parsed=parsed, raw=raw)


@app.route("/edit/<int:credential_id>", methods=["GET", "POST"])
@login_required
def edit(credential_id):
    conn = db()
    row = conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone()
    conn.close()
    if not row:
        return redirect(url_for("dashboard"))

    item = {
        "id": row["id"],
        "website": row["website"],
        "username": decrypt(row["username_enc"]),
        "password": decrypt(row["password_enc"]),
        "notes": decrypt(row["notes_enc"]),
    }

    if request.method == "POST":
        item["website"] = request.form.get("website", "").strip()
        item["username"] = request.form.get("username", "").strip()
        item["password"] = request.form.get("password", "")
        item["notes"] = request.form.get("notes", "")
        if not item["website"] or not item["password"]:
            flash("Website and password are required.", "error")
        else:
            conn = db()
            conn.execute(
                "UPDATE credentials SET website=?, username_enc=?, password_enc=?, notes_enc=?, updated_at=? WHERE id=?",
                (item["website"], encrypt(item["username"]), encrypt(item["password"]), encrypt(item["notes"]),
                 datetime.utcnow().isoformat(timespec="seconds"), credential_id),
            )
            conn.commit()
            conn.close()
            flash("Credential updated.", "success")
            return redirect(url_for("dashboard"))
    return render_template("edit.html", item=item)


@app.post("/delete/<int:credential_id>")
@login_required
def delete(credential_id):
    conn = db()
    conn.execute("DELETE FROM credentials WHERE id=?", (credential_id,))
    conn.commit()
    conn.close()
    flash("Credential deleted.", "success")
    return redirect(url_for("dashboard"))


@app.post("/lock")
def lock():
    session.clear()
    return redirect(url_for("login"))


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
