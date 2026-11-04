"""
predict.py — Prediction wrapper for the trained phishing detection model.

Loads model artifacts once at module import time and exposes a clean
`predict(domain)` function used by the Flask API routes.
"""

import json
import re
import logging
from pathlib import Path
from typing import Dict, Any, Optional

import joblib

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy-loaded singletons
# ---------------------------------------------------------------------------
_model = None
_meta: Optional[Dict] = None


def _load_artifacts() -> None:
    """Load model and metadata from disk (called once on first prediction)."""
    global _model, _meta

    # Import here to avoid circular imports at top-level
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from backend.config import config

    if not config.MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model file not found at {config.MODEL_PATH}. "
            "Run 'python backend/ml/train.py' to train the model first."
        )

    _model = joblib.load(config.MODEL_PATH)
    log.info("Loaded model from %s", config.MODEL_PATH)

    if config.META_PATH.exists():
        with open(config.META_PATH, "r", encoding="utf-8") as f:
            _meta = json.load(f)
        log.info("Loaded model metadata from %s", config.META_PATH)
    else:
        _meta = {}


def _ensure_loaded() -> None:
    if _model is None:
        _load_artifacts()


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

# RFC-compliant domain pattern (simplified but sufficient for validation)
_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"\.)+[a-zA-Z]{2,}$"
)

MAX_DOMAIN_LENGTH = 253


def validate_domain(domain: str) -> tuple[bool, str]:
    """
    Validate a domain string.

    Returns (is_valid, error_message). error_message is empty string if valid.
    """
    if not domain:
        return False, "Domain cannot be empty."
    if len(domain) > MAX_DOMAIN_LENGTH:
        return False, f"Domain exceeds maximum length of {MAX_DOMAIN_LENGTH} characters."

    # Strip scheme if accidentally included
    cleaned = re.sub(r"^https?://", "", domain.strip()).split("/")[0].split("?")[0]

    if not _DOMAIN_PATTERN.match(cleaned):
        # Also allow punycode (xn--) domains which are technically valid
        if not cleaned.startswith("xn--"):
            return False, f"'{domain}' does not appear to be a valid domain name."

    return True, ""


# ---------------------------------------------------------------------------
# Confidence thresholds
# ---------------------------------------------------------------------------

def _interpret_confidence(label: int, confidence: float) -> str:
    """Return a human-readable confidence tier."""
    if label == 1:  # Phishing
        if confidence >= 0.85:
            return "HIGH CONFIDENCE — strong phishing signals detected"
        elif confidence >= 0.65:
            return "MODERATE CONFIDENCE — several phishing indicators present"
        else:
            return "LOW CONFIDENCE — weak phishing signal, manual review advised"
    else:  # Legitimate
        if confidence >= 0.85:
            return "HIGH CONFIDENCE — domain profile consistent with legitimate banking sites"
        elif confidence >= 0.65:
            return "MODERATE CONFIDENCE — mostly legitimate characteristics"
        else:
            return "LOW CONFIDENCE — borderline result, treat with caution"


# ---------------------------------------------------------------------------
# Public prediction API
# ---------------------------------------------------------------------------

def predict(domain: str) -> Dict[str, Any]:
    """
    Predict whether a domain is phishing or legitimate.

    Parameters
    ----------
    domain : str
        The domain to analyse (e.g. 'gtbank-secure-login.com').

    Returns
    -------
    dict with keys:
        - domain: cleaned domain string
        - label: 0 (legitimate) or 1 (phishing)
        - label_text: 'Legitimate' | 'Phishing'
        - confidence: float 0.0–1.0 (probability of the predicted class)
        - phishing_probability: float 0.0–1.0 (always the phishing class prob)
        - explanation: human-readable interpretation
        - features: dict of all extracted feature values
        - risk_indicators: list of risk indicator dicts
        - model_name: name of the model that made the prediction
    """
    _ensure_loaded()

    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from backend.ml.features import extract_features, get_feature_names, get_risk_indicators

    # Clean and validate
    domain = re.sub(r"^https?://", "", domain.strip()).split("/")[0].split("?")[0].lower()

    # Extract features
    feature_names = get_feature_names()
    feats = extract_features(domain)
    X = [[float(feats[k]) for k in feature_names]]

    # Predict
    label = int(_model.predict(X)[0])
    proba = _model.predict_proba(X)[0]
    phishing_prob = float(proba[1])
    confidence = float(max(proba))

    # Risk indicators
    indicators = get_risk_indicators(domain)

    # Human-readable features (round floats)
    display_feats = {k: round(float(v), 4) if isinstance(v, float) else v for k, v in feats.items()}

    return {
        "domain": domain,
        "label": label,
        "label_text": "Phishing" if label == 1 else "Legitimate",
        "confidence": round(confidence, 4),
        "phishing_probability": round(phishing_prob, 4),
        "explanation": _interpret_confidence(label, confidence),
        "features": display_feats,
        "risk_indicators": indicators,
        "model_name": _meta.get("best_model", "Unknown") if _meta else "Unknown",
        "disclaimer": (
            "This prediction is based on domain-level lexical features only. "
            "It should NOT be treated as a guarantee of safety or malice. "
            "Always verify through official bank channels."
        ),
    }


def get_model_info() -> Dict[str, Any]:
    """Return model metadata for the /api/model-info endpoint."""
    _ensure_loaded()
    if not _meta:
        return {"error": "Model metadata not available."}
    # Return a safe subset (no large classification_report strings)
    winner = _meta.get("winner_metrics", {})
    runner_up = _meta.get("runner_up_metrics", {})
    return {
        "best_model": _meta.get("best_model"),
        "trained_at": _meta.get("trained_at"),
        "n_train": _meta.get("n_train"),
        "n_test": _meta.get("n_test"),
        "feature_count": len(_meta.get("feature_names", [])),
        "winner_metrics": {
            k: v for k, v in winner.items()
            if k not in ("classification_report",)
        },
        "runner_up_metrics": {
            k: v for k, v in runner_up.items()
            if k not in ("classification_report",)
        },
        "top_features": _meta.get("feature_importances", [])[:10],
    }


def is_model_loaded() -> bool:
    """Check whether the model has been loaded (for health checks)."""
    return _model is not None
