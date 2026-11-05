"""Shared test setup: build a dummy model, point the API at it, return a test client."""
import os

import pytest

from ci.make_dummy_model import build_dummy_model


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    model_dir = tmp_path_factory.mktemp("dummy") / "model"
    build_dummy_model(str(model_dir))
    os.environ["MODEL_DIR"] = str(model_dir)   # must be set BEFORE importing app
    import app
    app.app.config["TESTING"] = True
    return app.app.test_client()