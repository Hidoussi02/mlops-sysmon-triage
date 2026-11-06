"""
export_model.py - Copy the latest registered model out of MLflow into ./model

Why? MLflow's database stores the model's location as an absolute path on THIS
computer. That path does not exist inside a Docker container. A plain folder
can simply be mounted into the container, so the API gets a portable copy.

Run it from the project root, after train.py:
    python export_model.py
"""
import shutil
import sys

import mlflow
import mlflow.sklearn
from mlflow.tracking import MlflowClient

TRACKING_URI = "sqlite:///mlflow.db"
MODEL_NAME = "sysmon-xgb-classifier"
OUTPUT_DIR = "model"


def main():
    mlflow.set_tracking_uri(TRACKING_URI)
    client = MlflowClient()

    # Find the highest version number of the registered model
    versions = client.search_model_versions(f"name='{MODEL_NAME}'")
    if not versions:
        sys.exit(f"ERROR: no registered model named '{MODEL_NAME}'. Run train.py first.")
    latest = max(versions, key=lambda v: int(v.version))
    print(f"Using {MODEL_NAME} version {latest.version}")

    # Load it from the registry, then save a portable copy
    model = mlflow.sklearn.load_model(f"models:/{MODEL_NAME}/{latest.version}")
    shutil.rmtree(OUTPUT_DIR, ignore_errors=True)   # start clean
    mlflow.sklearn.save_model(model, OUTPUT_DIR, serialization_format="cloudpickle")
    print(f"Model exported to ./{OUTPUT_DIR}")


if __name__ == "__main__":
    main()
