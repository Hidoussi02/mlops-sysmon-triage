"""Automated tests for the Flask API (run by CI on every push)."""


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_predict_returns_prediction_and_probability(client):
    response = client.post("/predict", json={"rule_description": "User logon event number 3"})
    body = response.get_json()
    assert response.status_code == 200
    assert body["prediction"] in (0, 1)
    assert 0.0 <= body["probability"] <= 1.0


def test_predict_flags_known_malicious_text(client):
    response = client.post(
        "/predict",
        json={"rule_description": "PowerShell executed an encoded command variant 7"})
    assert response.get_json()["prediction"] == 1


def test_missing_field_returns_400(client):
    assert client.post("/predict", json={"other": "x"}).status_code == 400


def test_empty_text_returns_400(client):
    assert client.post("/predict", json={"rule_description": "   "}).status_code == 400


def test_non_string_returns_400(client):
    assert client.post("/predict", json={"rule_description": 123}).status_code == 400


def test_non_json_body_returns_400(client):
    assert client.post("/predict", data="not json").status_code == 400


def test_too_long_text_returns_400(client):
    assert client.post("/predict", json={"rule_description": "a" * 6000}).status_code == 400
