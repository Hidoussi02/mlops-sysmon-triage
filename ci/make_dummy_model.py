"""
make_dummy_model.py - Build a TINY fake model for CI tests

Why? The real model (model/) and the real dataset are not stored in GitHub
(they are in .gitignore). But app.py needs a model folder to start. So CI
trains a toy model on 40 invented sentences, using the same libraries and the
same pipeline shape (TF-IDF + XGBoost) as the real one.
No real data is involved.

Usage:  python ci/make_dummy_model.py model
"""
import sys

import mlflow.sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

BENIGN = [f"User logon event number {i}" for i in range(20)]
MALICIOUS = [f"PowerShell executed an encoded command variant {i}" for i in range(20)]


def build_dummy_model(output_dir):
    """Train the toy pipeline and save it in the same format as export_model.py."""
    texts = BENIGN + MALICIOUS
    labels = [0] * len(BENIGN) + [1] * len(MALICIOUS)
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5))),
        ("clf", XGBClassifier(n_estimators=20, max_depth=3,
                              eval_metric="logloss", random_state=0)),
    ])
    pipeline.fit(texts, labels)
    mlflow.sklearn.save_model(pipeline, output_dir, serialization_format="cloudpickle")


if __name__ == "__main__":
    build_dummy_model(sys.argv[1] if len(sys.argv) > 1 else "model")
    print("Dummy model created")