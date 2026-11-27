"""
app.py - Flask API for Sysmon/Wazuh triage (v1-vulnerable for DevSecOps demo)
"""
import logging
import os
import sqlite3

import mlflow.sklearn
import pandas as pd
from flask import Flask, jsonify, request
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

MODEL_DIR = os.getenv("MODEL_DIR", "model")
INPUT_FIELD = os.getenv("INPUT_FIELD", "rule_description")
THRESHOLD = float(os.getenv("THRESHOLD", "0.5"))
DB_PATH = os.getenv("DB_PATH", "/tmp/incidents.db" if os.name != "nt" else "incidents.db")
MAX_LENGTH = 5000

# FAILLE 3 (volontaire pour v1-vulnerable) : secret fictif en dur
SECRET_KEY = "FAKE_DEVSECOPS_JWT_SECRET_DO_NOT_USE_12345"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sysmon-api")

app = Flask(__name__)
serializer = URLSafeTimedSerializer(SECRET_KEY)

model = mlflow.sklearn.load_model(MODEL_DIR)
log.info("Model loaded from %s", MODEL_DIR)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
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
        # Comptes fictifs pour la démonstration (2 rôles : analyst et admin)
        if not conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("analyst", generate_password_hash("analyst123"), "analyst"),
            )
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", generate_password_hash("admin123"), "admin"),
            )
            # Données sensibles fictives
            conn.execute(
                """
                INSERT INTO incidents (owner_id, alert_text, prediction, probability, sensitive_note)
                VALUES (1, 'Normal Windows login event', 0, 0.02, 'Workstation LAB-PC-01 (fictif)')
                """
            )
            conn.execute(
                """
                INSERT INTO incidents (owner_id, alert_text, prediction, probability, sensitive_note)
                VALUES (2, 'PowerShell encoded command detected', 1, 0.91, 'CONFIDENTIAL-ADMIN-NOTE: Ticket #999 (fictif)')
                """
            )


init_db()


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
    username = payload.get("username", "")
    password = payload.get("password", "")
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        log.warning("Failed login attempt for user=%s", username)
        return jsonify(error="Invalid credentials"), 401
    token = serializer.dumps({"id": user["id"], "username": user["username"], "role": user["role"]})
    log.info("Successful login user=%s role=%s", user["username"], user["role"])
    return jsonify(token=token, role=user["role"])


@app.post("/predict")
def predict():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Body must be a JSON object"), 400

    text = payload.get(INPUT_FIELD)
    if not isinstance(text, str) or not text.strip():
        return jsonify(error=f"'{INPUT_FIELD}' is required and must be a non-empty string"), 400
    if len(text) > MAX_LENGTH:
        return jsonify(error=f"'{INPUT_FIELD}' is too long (max {MAX_LENGTH} characters)"), 400

    score = float(model.predict_proba(pd.Series([text]))[0, 1])
    prediction = int(score >= THRESHOLD)

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO incidents (owner_id, alert_text, prediction, probability, sensitive_note)
            VALUES (1, ?, ?, ?, 'Auto-triaged alert (fictif)')
            """,
            (text, prediction, round(score, 4)),
        )

    log.info("prediction=%d probability=%.3f input_length=%d", prediction, score, len(text))
    return jsonify(prediction=prediction, probability=round(score, 4))


@app.get("/incidents/<int:incident_id>")
def get_incident(incident_id):
    user = get_current_user()
    if not user:
        return jsonify(error="Authentication required"), 401
    # FAILLE 2 (volontaire — IDOR) : ne vérifie pas si owner_id == user['id']
    with get_db() as conn:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not row:
        return jsonify(error="Incident not found"), 404
    return jsonify(dict(row))


@app.get("/incidents/search")
def search_incidents():
    user = get_current_user()
    if not user:
        return jsonify(error="Authentication required"), 401
    q = request.args.get("q", "")
    # FAILLE 1 (volontaire — SQL Injection) : concaténation directe de q
    query = f"SELECT id, alert_text, prediction, probability FROM incidents WHERE alert_text LIKE '%{q}%'"
    with get_db() as conn:
        rows = conn.execute(query).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/admin/incidents")
def admin_incidents():
    user = get_current_user()
    if not user:
        return jsonify(error="Authentication required"), 401
    if user["role"] != "admin":
        log.warning("Unauthorized admin access attempt by user=%s", user["username"])
        return jsonify(error="Admin role required"), 403
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM incidents").fetchall()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)


"""
app.py - Flask API that serves the trained Sysmon/Wazuh classifier

Endpoints:
    GET  /health   -> {"status": "ok"}            (used by Docker health check)
    POST /predict  -> {"prediction": 0|1, "probability": 0.xx}

Example request body:
    {"rule_description": "PowerShell executed an encoded command"}

import logging
import os

import mlflow.sklearn
import pandas as pd
from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# Settings (can be overridden with environment variables, e.g. in docker-compose)
# ---------------------------------------------------------------------------
MODEL_DIR = os.getenv("MODEL_DIR", "model")             # folder made by export_model.py
INPUT_FIELD = os.getenv("INPUT_FIELD", "rule_description")  # JSON field the model reads
THRESHOLD = float(os.getenv("THRESHOLD", "0.5"))        # probability above which = malicious
MAX_LENGTH = 5000                                       # reject absurdly long inputs

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("sysmon-api")

app = Flask(__name__)

# Load the model ONCE at startup, not on every request (much faster)
model = mlflow.sklearn.load_model(MODEL_DIR)
log.info("Model loaded from %s", MODEL_DIR)


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/predict")
def predict():
    # 1. Input validation: reject anything unexpected with HTTP 400
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Body must be a JSON object"), 400

    text = payload.get(INPUT_FIELD)
    if not isinstance(text, str) or not text.strip():
        return jsonify(error=f"'{INPUT_FIELD}' is required and must be a non-empty string"), 400
    if len(text) > MAX_LENGTH:
        return jsonify(error=f"'{INPUT_FIELD}' is too long (max {MAX_LENGTH} characters)"), 400

    # 2. The pipeline was trained on a column of strings, so we give it a Series
    score = float(model.predict_proba(pd.Series([text]))[0, 1])
    prediction = int(score >= THRESHOLD)

    # 3. Log only the result, never the raw event content (privacy)
    log.info("prediction=%d probability=%.3f input_length=%d", prediction, score, len(text))
    return jsonify(prediction=prediction, probability=round(score, 4))


if __name__ == "__main__":
    # Local development only. In Docker we use gunicorn instead.
    app.run(host="127.0.0.1", port=5000)
"""