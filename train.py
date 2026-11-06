"""
train.py (v2) - Wazuh alert triage classifier (0 = normal, 1 = malicious)

What this script does, in order:
  1. Loads the labeled CSV                      (data/win10_dataset_labeled.csv)
  2. Anonymizes usernames                       (privacy)
  3. Splits into train / test so that:
        - both classes are present in the test set
        - all alerts of one attack technique stay on the same side
  4. Trains a BASELINE (Logistic Regression) and a CANDIDATE (XGBoost)
     on TF-IDF features extracted from the rule_description column
  5. Logs parameters, metrics and the model to MLflow
  6. Registers the XGBoost model in the MLflow Model Registry

Usage:
    python train.py                      # uses data/win10_dataset_labeled.csv
    python train.py path/to/other.csv    # uses another file
"""
import re
import sys
from pathlib import Path

import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix,
                             f1_score, precision_score, recall_score)
from sklearn.model_selection import StratifiedGroupKFold, train_test_split
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

# ----------------------------------------------------------------------------
# Settings - change these if your CSV uses other column names
# ----------------------------------------------------------------------------
CSV_PATH = sys.argv[1] if len(sys.argv) > 1 else "data/win10_dataset_labeled.csv"
TEXT_COL = "rule_description"          # the text the model learns from
LABEL_CANDIDATES = ["label", "is_malicious", "malicious", "target", "class"]
GROUP_CANDIDATES = ["technique_id", "technique", "run_id", "runid", "run"]
USER_COLS = ["User", "UserName", "user"]
SEED = 42
N_FOLDS = 4                            # one fold (~25%) becomes the test set
N_RANDOM_GROUPS = 40                   # normal alerts are spread over this many groups
MLFLOW_URI = "sqlite:///mlflow.db"     # local database, supports the Model Registry
EXPERIMENT = "sysmon-triage"
REGISTERED_NAME = "sysmon-xgb-classifier"


def find_col(df, candidates):
    """Return the real column name matching one of the candidates (case-insensitive)."""
    lower = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in lower:
            return lower[cand.lower()]
    return None


# ----------------------------------------------------------------------------
# 1. Load data
# ----------------------------------------------------------------------------
def load_data(path):
    df = pd.read_csv(path)
    print(f"Loaded {len(df)} rows. Columns: {df.columns.tolist()}")

    text_col = find_col(df, [TEXT_COL])
    label_col = find_col(df, LABEL_CANDIDATES)
    if text_col is None or label_col is None:
        sys.exit(
            f"\nERROR: could not find the text column ('{TEXT_COL}') or the label "
            f"column (tried {LABEL_CANDIDATES}).\nEdit TEXT_COL / LABEL_CANDIDATES "
            f"at the top of train.py to match your columns above."
        )

    # Make the label 0/1 even if it is stored as text
    positive_words = {"1", "1.0", "malicious", "attack", "suspicious", "true", "yes"}
    df["label"] = df[label_col].astype(str).str.strip().str.lower().isin(positive_words).astype(int)
    df["text"] = df[text_col].fillna("").astype(str)
    df = df[df["text"].str.len() > 0].reset_index(drop=True)   # drop empty rows

    print("Label counts (0 = normal, 1 = malicious):")
    print(df["label"].value_counts().to_string())
    print(f"Distinct texts: {df['text'].nunique()} (of {len(df)} rows)")
    if df["label"].nunique() < 2:
        sys.exit("ERROR: only one class found in the label column. Check the label values above.")
    return df


# ----------------------------------------------------------------------------
# 2. Anonymize usernames
# ----------------------------------------------------------------------------
USER_IN_PATH = re.compile(r"(?i)(users[\\/])[^\\/\s\"']+")


def anonymize(df):
    df["text"] = df["text"].str.replace(USER_IN_PATH, r"\1USER", regex=True)
    for col in USER_COLS:
        if col in df.columns:
            df[col] = "USER"
    return df


# ----------------------------------------------------------------------------
# 3. Split
# ----------------------------------------------------------------------------
def make_groups(df):
    """
    Build a group id for every row.
    - Rows that have a technique (attacks) keep it: one technique = one group,
      so the same attack never appears in both train and test.
    - Rows WITHOUT a technique (mostly normal activity) would all fall into one
      giant group, which makes the split lopsided. We spread them over
      N_RANDOM_GROUPS random groups instead.
    """
    rng = np.random.default_rng(SEED)
    col = find_col(df, GROUP_CANDIDATES)
    if col is None:
        return None, None
    raw = df[col].astype(str).str.strip()
    missing = df[col].isna() | raw.str.lower().isin(["", "nan", "none", "normal_activity"])
    groups = raw.copy()
    random_ids = rng.integers(0, N_RANDOM_GROUPS, size=len(df))
    groups[missing] = [f"unassigned_{df['label'].iat[i]}_{random_ids[i]}"
                       for i in np.flatnonzero(missing.to_numpy())]
    return groups, col


def split(df):
    groups, col = make_groups(df)
    if groups is not None:
        print(f"Splitting by '{col}' (an attack technique never appears in both sets).")
        sgkf = StratifiedGroupKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
        for train_idx, test_idx in sgkf.split(df, df["label"], groups=groups):
            train, test = df.iloc[train_idx], df.iloc[test_idx]
            # keep the first fold that has malicious rows on BOTH sides
            if test["label"].sum() > 0 and train["label"].sum() > 0:
                return train, test, f"stratified_group:{col}"
        print("WARNING: could not find a group split with attacks on both sides.")

    print("WARNING: using a random stratified split instead.\n"
          "         Similar alerts may sit in both train and test, so scores can be\n"
          "         optimistic. Mention this limitation in your report.")
    train, test = train_test_split(df, test_size=1 / N_FOLDS, random_state=SEED,
                                   stratify=df["label"])
    return train, test, "random_stratified"


# ----------------------------------------------------------------------------
# 4. Models
# ----------------------------------------------------------------------------
def make_tfidf():
    # Character n-grams are robust to small wording differences
    return TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                           max_features=20000, sublinear_tf=True)


def build_baseline():
    return Pipeline([
        ("tfidf", make_tfidf()),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])


def build_xgboost(y_train):
    neg, pos = (y_train == 0).sum(), (y_train == 1).sum()
    spw = float(neg / pos) if pos else 1.0      # compensates the class imbalance
    return Pipeline([
        ("tfidf", make_tfidf()),
        ("clf", XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                              scale_pos_weight=spw, eval_metric="logloss",
                              random_state=SEED, n_jobs=-1)),
    ])


# ----------------------------------------------------------------------------
# 5. Evaluate + log to MLflow
# ----------------------------------------------------------------------------
def dvc_hash(csv_path):
    """Read the dataset hash that DVC stored, so each run is tied to a data version."""
    dvc_file = Path(csv_path + ".dvc")
    if dvc_file.exists():
        m = re.search(r"md5:\s*([0-9a-f]+)", dvc_file.read_text())
        if m:
            return m.group(1)
    return "unknown"


def log_model(pipeline, register):
    # cloudpickle: newer MLflow versions block XGBoost types in their default format.
    # Safe here because we only ever load our own models.
    kwargs = {"serialization_format": "cloudpickle"}
    if register:
        kwargs["registered_model_name"] = REGISTERED_NAME
    try:                                   # newer MLflow versions
        mlflow.sklearn.log_model(pipeline, name="model", **kwargs)
    except TypeError:                      # older MLflow versions
        mlflow.sklearn.log_model(pipeline, artifact_path="model", **kwargs)


def run_experiment(run_name, pipeline, train, test, split_mode, overlap, register=False):
    with mlflow.start_run(run_name=run_name):
        pipeline.fit(train["text"], train["label"])
        y_pred = pipeline.predict(test["text"])
        y_score = pipeline.predict_proba(test["text"])[:, 1]

        metrics = {
            "precision": precision_score(test["label"], y_pred, zero_division=0),
            "recall": recall_score(test["label"], y_pred, zero_division=0),
            "f1": f1_score(test["label"], y_pred, zero_division=0),
        }
        if test["label"].nunique() == 2:
            metrics["pr_auc"] = average_precision_score(test["label"], y_score)

        mlflow.log_params({
            "model": run_name, "split": split_mode, "seed": SEED,
            "n_train": len(train), "n_test": len(test),
            "n_train_malicious": int(train["label"].sum()),
            "n_test_malicious": int(test["label"].sum()),
            "test_text_overlap_with_train": round(overlap, 3),
            "tfidf_ngrams": "char_wb 3-5", "text_column": TEXT_COL,
            "dataset": CSV_PATH, "dataset_dvc_md5": dvc_hash(CSV_PATH),
        })
        mlflow.log_metrics(metrics)
        log_model(pipeline, register)

        tn, fp, fn, tp = confusion_matrix(test["label"], y_pred, labels=[0, 1]).ravel()
        print(f"\n[{run_name}] " + "  ".join(f"{k}={v:.3f}" for k, v in metrics.items()))
        print(f"    confusion matrix: TP={tp} FN={fn} FP={fp} TN={tn}")


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main():
    df = anonymize(load_data(CSV_PATH))
    train, test, split_mode = split(df)

    # How many test texts also appear word-for-word in train?
    # High overlap = the model is mostly doing a lookup, so scores are optimistic.
    overlap = test["text"].isin(set(train["text"])).mean()

    print(f"\nTrain: {len(train)} rows ({int(train['label'].sum())} malicious)")
    print(f"Test : {len(test)} rows ({int(test['label'].sum())} malicious)")
    print(f"Test texts identical to a train text: {overlap:.0%}")

    mlflow.set_tracking_uri(MLFLOW_URI)
    mlflow.set_experiment(EXPERIMENT)

    run_experiment("baseline_logreg", build_baseline(), train, test, split_mode, overlap)
    run_experiment("xgboost", build_xgboost(train["label"]), train, test, split_mode,
                   overlap, register=True)

    print("\nDone. See the runs with:\n"
          f"    mlflow ui --backend-store-uri {MLFLOW_URI}\n"
          "then open http://127.0.0.1:5000")


if __name__ == "__main__":
    main()
