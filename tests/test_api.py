"""Automated tests for the secured Flask API."""


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_predict_requires_authentication(client):
    response = client.post(
        "/predict",
        json={"rule_description": "Unauthenticated security test"},
    )
    assert response.status_code == 401


def test_predict_returns_prediction_and_probability(client, analyst_headers):
    response = client.post(
        "/predict",
        json={"rule_description": "User logon event number 3"},
        headers=analyst_headers,
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["prediction"] in (0, 1)
    assert 0.0 <= body["probability"] <= 1.0


def test_predict_flags_known_malicious_text(client, analyst_headers):
    response = client.post(
        "/predict",
        json={"rule_description": "PowerShell executed an encoded command variant 7"},
        headers=analyst_headers,
    )
    assert response.status_code == 200
    assert response.get_json()["prediction"] == 1


def test_missing_field_returns_400(client, analyst_headers):
    response = client.post(
        "/predict", json={"other": "x"}, headers=analyst_headers
    )
    assert response.status_code == 400


def test_empty_text_returns_400(client, analyst_headers):
    response = client.post(
        "/predict", json={"rule_description": "   "}, headers=analyst_headers
    )
    assert response.status_code == 400


def test_non_string_returns_400(client, analyst_headers):
    response = client.post(
        "/predict", json={"rule_description": 123}, headers=analyst_headers
    )
    assert response.status_code == 400


def test_non_json_body_returns_400(client, analyst_headers):
    response = client.post(
        "/predict", data="not json", headers=analyst_headers
    )
    assert response.status_code == 400


def test_too_long_text_returns_400(client, analyst_headers):
    response = client.post(
        "/predict",
        json={"rule_description": "a" * 6000},
        headers=analyst_headers,
    )
    assert response.status_code == 400


def test_analyst_cannot_access_admin_endpoint(client, analyst_headers):
    response = client.get(
        "/admin/incidents", headers=analyst_headers
    )
    assert response.status_code == 403


def test_analyst_cannot_access_admin_incident(
    client, analyst_headers, admin_headers
):
    import app as app_module

    admin_token = admin_headers["Authorization"].split(" ", 1)[1]
    admin_id = app_module.serializer.loads(admin_token)["id"]

    response = client.get(
        "/admin/incidents", headers=admin_headers
    )
    assert response.status_code == 200

    admin_incident = next(
        row for row in response.get_json()
        if row["owner_id"] == admin_id
    )

    response = client.get(
        f"/incidents/{admin_incident['id']}",
        headers=analyst_headers,
    )
    assert response.status_code == 403
