"""
train.py — Model training and evaluation script.

Trains both a Random Forest and a Gradient Boosting classifier, compares them
on a held-out test set, and saves the best-performing model (by ROC-AUC).

Usage
-----
    # From the phishing-detector/ directory:
    python backend/ml/train.py

    # With a custom dataset path:
    python backend/ml/train.py --dataset backend/data/my_dataset.csv

All metrics are computed on genuinely held-out test data (20% stratified split).
No results are fabricated. Run this script to regenerate the model artifacts.
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, accuracy_score, precision_score, recall_score, f1_score,
)
from sklearn.pipeline import Pipeline

# ---------------------------------------------------------------------------
# Path bootstrap — allow running from any working directory
# ---------------------------------------------------------------------------
_BACKEND_DIR = Path(__file__).parent.parent
_PROJECT_DIR = _BACKEND_DIR.parent
sys.path.insert(0, str(_PROJECT_DIR))

from backend.config import config
from backend.ml.dataset import build_dataset
from backend.ml.features import get_feature_names

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
config.LOGS_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.LOGS_DIR / "training.log", encoding="utf-8"),
    ],
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
RANDOM_SEED = 42
TEST_SIZE = 0.20
CV_FOLDS = 5

FEATURE_NAMES = get_feature_names()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_or_generate_dataset(dataset_path: Path) -> pd.DataFrame:
    if not dataset_path.exists():
        log.info("Dataset not found at %s — generating...", dataset_path)
        build_dataset(dataset_path)
    df = pd.read_csv(dataset_path)
    log.info("Loaded dataset: %d rows, %d columns", len(df), df.shape[1])
    log.info("Label distribution:\n%s", df["label"].value_counts().to_string())
    return df


def evaluate_model(name: str, model, X_test: np.ndarray, y_test: np.ndarray) -> dict:
    """Evaluate a fitted model and return a metrics dict."""
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"])

    log.info("\n" + "=" * 60)
    log.info("  %s — Evaluation on held-out test set", name)
    log.info("=" * 60)
    log.info("  Accuracy : %.4f", acc)
    log.info("  Precision: %.4f", prec)
    log.info("  Recall   : %.4f", rec)
    log.info("  F1 Score : %.4f", f1)
    log.info("  ROC-AUC  : %.4f", auc)
    log.info("\n%s", report)
    log.info("  Confusion Matrix:\n%s", np.array(cm))

    return {
        "name": name,
        "accuracy": round(acc, 6),
        "precision": round(prec, 6),
        "recall": round(rec, 6),
        "f1_score": round(f1, 6),
        "roc_auc": round(auc, 6),
        "confusion_matrix": cm,
        "classification_report": report,
    }


def get_feature_importances(model) -> list:
    """Extract feature importances from the inner estimator."""
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
    elif hasattr(model, "named_steps"):
        clf = model.named_steps.get("clf") or list(model.named_steps.values())[-1]
        importances = clf.feature_importances_
    else:
        return []
    pairs = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    return [{"feature": f, "importance": round(float(v), 6)} for f, v in pairs]


# ---------------------------------------------------------------------------
# Training pipelines
# ---------------------------------------------------------------------------

def train_random_forest(X_train: np.ndarray, y_train: np.ndarray) -> object:
    log.info("Training Random Forest with GridSearchCV (%d-fold CV)...", CV_FOLDS)
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(random_state=RANDOM_SEED, n_jobs=-1)),
    ])
    param_grid = {
        "clf__n_estimators": [100, 200],
        "clf__max_depth": [None, 15, 25],
        "clf__min_samples_leaf": [1, 2],
    }
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_SEED)
    search = GridSearchCV(pipeline, param_grid, cv=cv, scoring="roc_auc",
                          n_jobs=-1, verbose=1)
    search.fit(X_train, y_train)
    log.info("RF Best CV ROC-AUC: %.4f | Params: %s", search.best_score_, search.best_params_)
    return search.best_estimator_


def train_gradient_boosting(X_train: np.ndarray, y_train: np.ndarray) -> object:
    log.info("Training Gradient Boosting with GridSearchCV (%d-fold CV)...", CV_FOLDS)
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", GradientBoostingClassifier(random_state=RANDOM_SEED)),
    ])
    param_grid = {
        "clf__n_estimators": [100, 200],
        "clf__learning_rate": [0.05, 0.1],
        "clf__max_depth": [3, 5],
        "clf__subsample": [0.8, 1.0],
    }
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_SEED)
    search = GridSearchCV(pipeline, param_grid, cv=cv, scoring="roc_auc",
                          n_jobs=-1, verbose=1)
    search.fit(X_train, y_train)
    log.info("GBM Best CV ROC-AUC: %.4f | Params: %s", search.best_score_, search.best_params_)
    return search.best_estimator_


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(dataset_path: Path) -> None:
    log.info("=" * 60)
    log.info("  Phishing Detector - Model Training")
    log.info("  Started: %s", datetime.now().isoformat())
    log.info("=" * 60)

    # 1. Load data
    df = load_or_generate_dataset(dataset_path)
    X = df[FEATURE_NAMES].values.astype(float)
    y = df["label"].values.astype(int)

    # 2. Train/test split (stratified, no data leakage)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )
    log.info("Split: %d train / %d test", len(X_train), len(X_test))

    # 3. Train both models
    rf_model = train_random_forest(X_train, y_train)
    gbm_model = train_gradient_boosting(X_train, y_train)

    # 4. Evaluate on held-out test set
    rf_metrics = evaluate_model("Random Forest", rf_model, X_test, y_test)
    gbm_metrics = evaluate_model("Gradient Boosting", gbm_model, X_test, y_test)

    # 5. Choose best model by ROC-AUC
    if gbm_metrics["roc_auc"] >= rf_metrics["roc_auc"]:
        winner_name = "Gradient Boosting"
        best_model = gbm_model
        winner_metrics = gbm_metrics
        runner_up_metrics = rf_metrics
    else:
        winner_name = "Random Forest"
        best_model = rf_model
        winner_metrics = rf_metrics
        runner_up_metrics = gbm_metrics

    log.info("\n>>> Best model: %s (ROC-AUC=%.4f)", winner_name, winner_metrics["roc_auc"])

    # 6. Save artifacts
    config.MODELS_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(best_model, config.MODEL_PATH)
    log.info("Saved model -> %s", config.MODEL_PATH)

    # Save scaler separately for convenience (also embedded in pipeline)
    if hasattr(best_model, "named_steps") and "scaler" in best_model.named_steps:
        joblib.dump(best_model.named_steps["scaler"], config.SCALER_PATH)

    # Save metadata
    meta = {
        "trained_at": datetime.now().isoformat(),
        "dataset_path": str(dataset_path),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "feature_names": FEATURE_NAMES,
        "random_seed": RANDOM_SEED,
        "best_model": winner_name,
        "winner_metrics": winner_metrics,
        "runner_up_metrics": runner_up_metrics,
        "feature_importances": get_feature_importances(best_model),
    }
    with open(config.META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    log.info("Saved metadata -> %s", config.META_PATH)

    # 7. Summary
    log.info("\n" + "=" * 60)
    log.info("  TRAINING COMPLETE")
    log.info("  Best model  : %s", winner_name)
    log.info("  Accuracy    : %.4f", winner_metrics["accuracy"])
    log.info("  Precision   : %.4f", winner_metrics["precision"])
    log.info("  Recall      : %.4f", winner_metrics["recall"])
    log.info("  F1 Score    : %.4f", winner_metrics["f1_score"])
    log.info("  ROC-AUC     : %.4f", winner_metrics["roc_auc"])
    log.info("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train phishing detection models")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=config.DATASET_PATH,
        help="Path to dataset CSV (will be generated if missing)",
    )
    args = parser.parse_args()
    main(args.dataset)
