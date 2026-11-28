"""
app.py - Hardened Flask API for Sysmon/Wazuh triage (v2-secure)
"""
import logging
import os
import secrets
import sqlite3
import tempfile

import mlflow.sklearn
import pandas as pd
from flask import Flask, jsonify, request
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

MODEL_DIR = os.getenv("MODEL_DIR", "model")
INPUT_FIELD = os.getenv("INPUT_FIELD", "rule_description")
THRESHOLD = float(os.getenv("THRESHOLD", "0.5"))
DEFAULT_DB = os.path.join(tempfile.gettempdir(), "incidents.db")
DB_PATH = os.getenv("DB_PATH", DEFAULT_DB)
MAX_LENGTH = 5000

# FIX FAILLE 3 : secret injecte via variable d'environnement (jamais en dur)
SECRET_KEY = os.getenv("API_SECRET_KEY") or secrets.token_hex(32)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("sysmon-api")

app = Flask(__name__)
serializer = URLSafeTimedSerializer(SECRET_KEY)

model = mlflow.sklearn.load_model(MODEL_DIR)
log.info("Model loaded from %s", MODEL_DIR)


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db():
    conn = get_db()

    try:
        with conn:
            # Verrouiller l'?criture avant de v?rifier les utilisateurs.
            conn.execute("BEGIN IMMEDIATE")

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_id INTEGER NOT NULL,
                    alert_text TEXT NOT NULL,
                    prediction INTEGER NOT NULL,
                    probability REAL NOT NULL,
                    sensitive_note TEXT NOT NULL
                )
                """
            )

            default_users = [
                ("analyst", os.getenv("DEMO_ANALYST_PASS", "analyst123"), "analyst"),
                ("admin", os.getenv("DEMO_ADMIN_PASS", "admin123"), "admin"),
            ]

            for username, password, role in default_users:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO users
                    (username, password_hash, role)
                    VALUES (?, ?, ?)
                    """,
                    (username, generate_password_hash(password), role),
                )

            analyst = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                ("analyst",),
            ).fetchone()

            admin = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                ("admin",),
            ).fetchone()

            if not conn.execute(
                "SELECT 1 FROM incidents LIMIT 1"
            ).fetchone():
                conn.execute(
                    """
                    INSERT INTO incidents
                    (owner_id, alert_text, prediction, probability, sensitive_note)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        analyst["id"],
                        "Normal Windows login event",
                        0,
                        0.02,
                        "Workstation LAB-PC-01 (fictif)",
                    ),
                )

                conn.execute(
                    """
                    INSERT INTO incidents
                    (owner_id, alert_text, prediction, probability, sensitive_note)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        admin["id"],
                        "PowerShell encoded command detected",
                        1,
                        0.91,
                        "CONFIDENTIAL-ADMIN-NOTE: Ticket #999 (fictif)",
                    ),
                )

    finally:
        conn.close()


init_db()


# FIX FAILLE 4 : ajout des en-tetes de securite HTTP
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


def get_current_user():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1]
    try:
        return serializer.loads(token, max_age=3600)
    except BadSignature:
        return None


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/login")
def login():
    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username", ""))
    password = str(payload.get("password", ""))
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        log.warning("SECURITY_EVENT failed_login user=%s", username)
        return jsonify(error="Invalid credentials"), 401
    token = serializer.dumps(
        {"id": user["id"], "username": user["username"], "role": user["role"]}
    )
    log.info("Successful login user=%s role=%s", user["username"], user["role"])
    return jsonify(token=token, role=user["role"])


@app.post("/predict")
def predict():
    user = get_current_user()
    if not user:
        return jsonify(error="Authentication required"), 401

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Body must be a JSON object"), 400

    text = payload.get(INPUT_FIELD)
    if not isinstance(text, str) or not text.strip():
        msg = f"'{INPUT_FIELD}' is required and must be a non-empty string"
        return jsonify(error=msg), 400

    if len(text) > MAX_LENGTH:
        msg = f"'{INPUT_FIELD}' is too long (max {MAX_LENGTH} characters)"
        return jsonify(error=msg), 400

    score = float(model.predict_proba(pd.Series([text]))[0, 1])
    prediction = int(score >= THRESHOLD)

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO incidents
            (owner_id, alert_text, prediction, probability, sensitive_note)
            VALUES (?, ?, ?, ?, 'Auto-triaged alert (fictif)')
            """,
            (user["id"], text, prediction, round(score, 4)),
        )

    log.info(
        "prediction=%d probability=%.3f input_length=%d user=%s",
        prediction, score, len(text), user["username"],
    )

    return jsonify(
        prediction=prediction,
        probability=round(score, 4),
    )


@app.get("/incidents/<int:incident_id>")
def get_incident(incident_id):
    user = get_current_user()
    if not user:
        return jsonify(error="Authentication required"), 401
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
    if not row:
        return jsonify(error="Incident not found"), 404
    # FIX FAILLE 2 (IDOR) : verification stricte du proprietaire ou role admin
    if user["role"] != "admin" and row["owner_id"] != user["id"]:
        log.warning(
            "SECURITY_EVENT idor_blocked user=%s incident_id=%d",
            user["username"],
            incident_id,
        )
        return jsonify(error="Forbidden: access denied"), 403
    return jsonify(dict(row))


@app.get("/incidents/search")
def search_incidents():
    user = get_current_user()
    if not user:
        return jsonify(error="Authentication required"), 401
    q = request.args.get("q", "")
    # Detection dans les journaux d'une tentative d'injection SQL
    lowered = q.lower()
    if "'" in q or "--" in q or " or " in lowered or "union" in lowered:
        log.warning(
            "SECURITY_EVENT sqli_attempt_blocked user=%s query_len=%d",
            user["username"],
            len(q),
        )
    # FIX FAILLE 1 (SQLi) : requete parametree + isolation par proprietaire
    pattern = f"%{q}%"
    with get_db() as conn:
        if user["role"] == "admin":
            rows = conn.execute(
                "SELECT id, alert_text, prediction, probability "
                "FROM incidents WHERE alert_text LIKE ?",
                (pattern,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, alert_text, prediction, probability "
                "FROM incidents WHERE owner_id = ? AND alert_text LIKE ?",
                (user["id"], pattern),
            ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/admin/incidents")
def admin_incidents():
    user = get_current_user()
    if not user:
        return jsonify(error="Authentication required"), 401
    if user["role"] != "admin":
        log.warning(
            "SECURITY_EVENT unauthorized_admin_access user=%s",
            user["username"],
        )
        return jsonify(error="Admin role required"), 403
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM incidents").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
