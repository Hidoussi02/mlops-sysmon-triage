# Wazuh Alert Triage Pipeline (MLOps + DevSecOps)

A small, reproducible pipeline that scores Wazuh alerts with a machine-learning model
and raises a **second, higher-level Wazuh alert** when an alert looks like attack activity.

> **Scope:** this is an *alert triage* tool. It does not replace Wazuh's detection.
> It ranks alerts so analysts can look at the likely dangerous ones first.
> Wazuh integrations cannot change or hide the original alert, so the pipeline **adds** a new one.

## Architecture

```
 labeled dataset (DVC) --> train.py --> MLflow (runs + registry)
                                              |
                                       export_model.py
                                              |
                                           model/  (not in Git)
                                              |
 Wazuh alert --> custom-mlops-triage.py --> Flask API (Docker) --> prediction 0 / 1
                                                                         |
                                               if 1: new event -> rule 100901 (level 12)
```

| Component | Tool |
|---|---|
| Data versioning | DVC (local remote) |
| Experiment tracking, model registry | MLflow (SQLite backend) |
| Model | TF-IDF (character n-grams) + XGBoost, with a Logistic Regression baseline |
| Serving | Flask + gunicorn in Docker |
| CI/CD | GitHub Actions: flake8, Bandit, pytest, container smoke test |
| SIEM integration | Wazuh custom integration + custom rules |

## Repository layout

```
train.py                 training, evaluation, MLflow logging and model registration
export_model.py          copies the latest registered model to ./model (portable folder)
app.py                   Flask API: GET /health, POST /predict
Dockerfile, docker-compose.yml
ci/make_dummy_model.py   tiny fake model used by CI (no real data in CI)
tests/                   API tests
wazuh/                   integration script, wrapper, ossec.conf snippet, custom rules, test alert
label_dataset.py         how the labels were produced (time windows around attacks)
```

## Quick start

```bash
pip install -r requirements.txt -r requirements-dev.txt
dvc pull                          # works where the DVC remote folder exists
python train.py                   # SPLIT_MODE=stratified (env var) for a random stratified split
python export_model.py            # creates ./model
docker compose up --build         # API on 127.0.0.1:5000
```

```bash
curl http://127.0.0.1:5000/health
curl -X POST http://127.0.0.1:5000/predict -H "Content-Type: application/json" \
     -d '{"rule_description":"Logon Failure - Unknown user or bad password"}'
```

Run the tests: `pytest`. Browse experiments: `mlflow ui --backend-store-uri sqlite:///mlflow.db`.

## Wazuh integration

Files in `wazuh/`. On the Wazuh Manager:

1. Copy `custom-mlops-triage` and `custom-mlops-triage.py` to `/var/ossec/integrations/`
   (`chmod 750`, `chown root:wazuh`). The wrapper must keep **LF** line endings.
2. Add `ossec_integration_snippet.xml` to `/var/ossec/etc/ossec.conf`.
3. Add `local_rules_snippet.xml` to `/var/ossec/etc/rules/local_rules.xml`.
4. Restart: `sudo systemctl restart wazuh-manager`.

If the API is unreachable, the script logs the problem to `/var/ossec/logs/integrations.log` and
leaves the alert untouched. Alerts created by the integration itself are skipped (no loops).

## Security measures

- Container runs as a non-root user, with a read-only filesystem, all Linux capabilities dropped
  and `no-new-privileges`. The API port is published on loopback only.
- Input validation on `/predict` (HTTP 400 on bad input, length limit). Raw alert text is never logged.
- Usernames are anonymized before training.
- Raw data, models and MLflow files are **not** stored in Git. CI uses a synthetic model.
- Pipeline permissions are read-only. Bandit scans the Python code on every push.
- Dependencies are pinned. Runtime and development requirements are separated.


Limitations to state plainly:

- Labels are **weak**: an alert is marked malicious if it occurs within a few minutes of an attack
  (`label_dataset.py`). The same alert text appears in both classes, so precision is limited.
- Only a few attack techniques are present (brute force and network scanning from Kali).
- Many alerts share the same text, so scores are indicative, not a measure of real-world detection.
- The DVC remote is a local folder, so `dvc pull` works only on the machine that has it.

Possible improvements: more attack runs and techniques, human-verified labels, additional features
(source IP, alert rate per minute), a shared DVC remote, and drift monitoring.


