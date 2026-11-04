"""
conftest.py — Shared pytest fixtures for the phishing detector test suite.
"""

import sys
import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Make the project root importable
_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Flask test client
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def app(tmp_path_factory):
    """Create a Flask app configured for testing with a temp file database."""
    import os
    # Use a real temp file so every get_connection() call shares the same DB
    db_file = tmp_path_factory.mktemp("db") / "test_phishing.db"
    os.environ["DATABASE_PATH"] = str(db_file)
    os.environ.setdefault("FLASK_ENV", "testing")
    os.environ.setdefault("SECRET_KEY", "test-secret")

    from backend.app import create_app
    application = create_app()
    application.config["TESTING"] = True
    return application


@pytest.fixture(scope="session")
def client(app):
    """Return a test client for the Flask app."""
    return app.test_client()


# ---------------------------------------------------------------------------
# Mock model fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def mock_predict_result():
    """A sample prediction result dict."""
    return {
        "domain": "gtbank-secure-login.com",
        "label": 1,
        "label_text": "Phishing",
        "confidence": 0.9321,
        "phishing_probability": 0.9321,
        "explanation": "HIGH CONFIDENCE — strong phishing signals detected",
        "features": {
            "domain_length": 24,
            "hyphen_count": 2,
            "suspicious_keyword_count": 2,
        },
        "risk_indicators": [
            {"level": "HIGH", "text": "Bank brand combined with suspicious keyword"}
        ],
        "model_name": "Gradient Boosting",
        "disclaimer": "This prediction is probabilistic.",
    }


@pytest.fixture
def mock_model_artifacts(tmp_path, mock_predict_result):
    """
    Patch the predict module so it doesn't need real model files.
    """
    with patch("backend.ml.predict._model", MagicMock()) as mock_m, \
         patch("backend.ml.predict._meta", {
             "best_model": "Gradient Boosting",
             "trained_at": "2026-01-01T00:00:00",
             "n_train": 4000,
             "n_test": 1000,
             "feature_names": [],
             "winner_metrics": {
                 "name": "Gradient Boosting",
                 "accuracy": 0.97,
                 "precision": 0.96,
                 "recall": 0.98,
                 "f1_score": 0.97,
                 "roc_auc": 0.99,
                 "confusion_matrix": [[480, 20], [10, 490]],
             },
             "runner_up_metrics": {
                 "name": "Random Forest",
                 "accuracy": 0.95,
                 "precision": 0.94,
                 "recall": 0.96,
                 "f1_score": 0.95,
                 "roc_auc": 0.98,
                 "confusion_matrix": [[470, 30], [20, 480]],
             },
             "feature_importances": [
                 {"feature": "max_jaro_winkler", "importance": 0.15},
                 {"feature": "min_levenshtein",  "importance": 0.12},
             ],
         }):
        mock_m.predict.return_value = [1]
        mock_m.predict_proba.return_value = [[0.07, 0.93]]
        yield
