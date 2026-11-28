"""Shared test setup for the Flask API."""
import os

import pytest

from ci.make_dummy_model import build_dummy_model


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("api-tests")
    model_dir = workdir / "model"
    db_path = workdir / "test_incidents.sqlite"

    build_dummy_model(str(model_dir))

    os.environ["MODEL_DIR"] = str(model_dir)
    os.environ["DB_PATH"] = str(db_path)
    os.environ["API_SECRET_KEY"] = "pytest-only-signing-key"
    os.environ["DEMO_ANALYST_PASS"] = "test-analyst-password"
    os.environ["DEMO_ADMIN_PASS"] = "test-admin-password"

    import app as app_module

    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


@pytest.fixture
def analyst_headers(client):
    response = client.post(
        "/login",
        json={"username": "analyst", "password": "test-analyst-password"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.get_json()['token']}"}


@pytest.fixture
def admin_headers(client):
    response = client.post(
        "/login",
        json={"username": "admin", "password": "test-admin-password"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.get_json()['token']}"}
