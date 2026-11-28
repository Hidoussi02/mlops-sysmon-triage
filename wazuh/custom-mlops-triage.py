#!/usr/bin/env python3
"""Authenticated HTTPS integration between Wazuh and MLOps API."""

import json
import ssl
import sys
import time
from socket import AF_UNIX, SOCK_DGRAM, socket
from urllib import error, parse, request

LOG_FILE = "/var/ossec/logs/integrations.log"
SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
ENV_FILE = "/var/ossec/etc/mlops-api.env"
CA_FILE = "/var/ossec/etc/mlops-api-ca.crt"

DEFAULT_URL = "https://192.168.100.166:5000/predict"
TIMEOUT_SECONDS = 10
MAX_LENGTH = 5000
INTEGRATION = "mlops_triage"


def log(message):
    line = (
        f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
        f"{INTEGRATION}: {message}\n"
    )
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        sys.stderr.write(line)


def load_credentials():
    values = {}

    with open(ENV_FILE, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()

    username = values.get("MLOPS_API_USERNAME")
    password = values.get("MLOPS_API_PASSWORD")

    if not username or not password:
        raise ValueError("API credentials are missing")

    return username, password


def find_api_url(argv):
    for arg in argv[1:]:
        if arg.startswith("https://"):
            return arg
    return DEFAULT_URL


def post_json(url, payload, context, token=None):
    headers = {"Content-Type": "application/json"}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )

    with request.urlopen(
        req, context=context, timeout=TIMEOUT_SECONDS
    ) as response:
        return json.loads(response.read().decode("utf-8"))


def authenticate(api_url, context):
    parsed = parse.urlsplit(api_url)

    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("HTTPS API URL required")

    login_path = parsed.path.rsplit("/", 1)[0] + "/login"
    login_url = parse.urlunsplit(
        (parsed.scheme, parsed.netloc, login_path, "", "")
    )

    username, password = load_credentials()

    result = post_json(
        login_url,
        {"username": username, "password": password},
        context,
    )

    token = result.get("token")

    if not token:
        raise ValueError("Login response contains no token")

    if result.get("role") != "analyst":
        raise ValueError("API account must have analyst role")

    return token


def classify(api_url, description, context):
    token = authenticate(api_url, context)

    result = post_json(
        api_url,
        {"rule_description": description[:MAX_LENGTH]},
        context,
        token,
    )

    prediction = int(result["prediction"])

    if prediction not in (0, 1):
        raise ValueError("Invalid prediction value")

    return result


def send_to_wazuh(event, agent):
    message = json.dumps(event)

    if not agent or agent.get("id") == "000":
        payload = f"1:{INTEGRATION}:{message}"
    else:
        location = (
            f"[{agent.get('id')}] ({agent.get('name')}) "
            f"{agent.get('ip', 'any')}"
        )
        location = location.replace("|", "||").replace(":", "|:")
        payload = f"1:{location}->{INTEGRATION}:{message}"

    sock = socket(AF_UNIX, SOCK_DGRAM)

    try:
        sock.connect(SOCKET_ADDR)
        sock.send(payload.encode("utf-8"))
    finally:
        sock.close()


def is_own_event(alert):
    data = alert.get("data")
    if not isinstance(data, dict):
        data = {}

    groups = alert.get("rule", {}).get("groups", [])
    if not isinstance(groups, list):
        groups = []

    return (
        alert.get("integration") == INTEGRATION
        or INTEGRATION in alert
        or data.get("integration") == INTEGRATION
        or INTEGRATION in data
        or "mlops" in groups
    )


def main():
    if len(sys.argv) < 2:
        log("no alert file given")
        return

    try:
        with open(sys.argv[1], encoding="utf-8") as handle:
            alert = json.load(handle)
    except (OSError, ValueError) as exc:
        log(f"cannot read alert file: {type(exc).__name__}")
        return

    if not isinstance(alert, dict) or is_own_event(alert):
        return

    rule = alert.get("rule", {})
    description = rule.get("description")

    if not isinstance(description, str) or not description.strip():
        log("alert has no valid rule.description")
        return

    try:
        context = ssl.create_default_context(cafile=CA_FILE)

        result = classify(
            find_api_url(sys.argv),
            description,
            context,
        )

        prediction = int(result["prediction"])
        probability = result.get("probability")

    except error.HTTPError as exc:
        log(f"API HTTP error: status={exc.code}")
        return
    except (
        error.URLError,
        TimeoutError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        log(f"API request failed: {type(exc).__name__}: {exc}")
        return

    log(
        f"rule {rule.get('id')} -> "
        f"prediction={prediction} probability={probability}"
    )

    if prediction == 1:
        event = {
            "integration": INTEGRATION,
            INTEGRATION: {
                "prediction": prediction,
                "probability": probability,
                "source_rule_id": rule.get("id"),
                "source_rule_level": rule.get("level"),
                "source_description": description,
            },
        }

        try:
            send_to_wazuh(event, alert.get("agent"))
        except OSError as exc:
            log(f"cannot write to Wazuh queue: {type(exc).__name__}")


if __name__ == "__main__":
    main()
