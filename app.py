"""
app.py - Flask API that serves the trained Sysmon/Wazuh classifier

Endpoints:
    GET  /health   -> {"status": "ok"}            (used by Docker health check)
    POST /predict  -> {"prediction": 0|1, "probability": 0.xx}

Example request body:
    {"rule_description": "PowerShell executed an encoded command"}
"""
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
