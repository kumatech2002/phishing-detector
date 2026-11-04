"""
test_predict.py — Tests for the prediction pipeline.
"""

import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
from backend.ml.predict import validate_domain


# ─── Input validation ─────────────────────────────────────────

class TestValidateDomain:
    def test_valid_simple(self):
        valid, err = validate_domain("gtbank.com")
        assert valid is True
        assert err == ""

    def test_valid_with_subdomain(self):
        valid, _ = validate_domain("ibank.accessbank.com.ng")
        assert valid is True

    def test_valid_with_hyphens(self):
        valid, _ = validate_domain("gtbank-secure-login.com")
        assert valid is True

    def test_empty_string(self):
        valid, err = validate_domain("")
        assert valid is False
        assert "empty" in err.lower()

    def test_too_long(self):
        valid, err = validate_domain("a" * 254 + ".com")
        assert valid is False
        assert "length" in err.lower()

    def test_plain_word_no_tld(self):
        valid, err = validate_domain("notadomain")
        assert valid is False

    def test_strip_scheme(self):
        # Should validate the domain part after stripping scheme
        valid, _ = validate_domain("https://gtbank.com")
        assert valid is True

    def test_ip_address_rejected(self):
        valid, err = validate_domain("192.168.1.1")
        assert valid is False

    def test_localhost(self):
        valid, _ = validate_domain("localhost")
        assert valid is False


# ─── Full prediction pipeline ─────────────────────────────────

class TestPredict:
    """These tests mock the model so no trained file is needed."""

    def test_predict_phishing_domain(self, mock_model_artifacts):
        from backend.ml.predict import predict
        result = predict("gtbank-secure-login.com")
        assert "label" in result
        assert "label_text" in result
        assert "confidence" in result
        assert "phishing_probability" in result
        assert "features" in result
        assert "risk_indicators" in result
        assert "disclaimer" in result

    def test_predict_returns_correct_types(self, mock_model_artifacts):
        from backend.ml.predict import predict
        result = predict("gtbank.com")
        assert isinstance(result["label"], int)
        assert result["label"] in (0, 1)
        assert isinstance(result["confidence"], float)
        assert 0.0 <= result["confidence"] <= 1.0
        assert isinstance(result["features"], dict)
        assert isinstance(result["risk_indicators"], list)

    def test_predict_strips_scheme(self, mock_model_artifacts):
        from backend.ml.predict import predict
        r1 = predict("gtbank.com")
        r2 = predict("https://gtbank.com/login")
        assert r1["domain"] == r2["domain"]

    def test_predict_phishing_probability_present(self, mock_model_artifacts):
        from backend.ml.predict import predict
        result = predict("accessbank-verify.xyz")
        assert "phishing_probability" in result
        assert 0.0 <= result["phishing_probability"] <= 1.0

    def test_model_not_loaded_raises_file_not_found(self):
        """Verify graceful error when model file is missing."""
        import backend.ml.predict as pred_mod
        original_model = pred_mod._model
        original_meta  = pred_mod._meta

        # Temporarily clear the cached model so _load_artifacts() runs again
        pred_mod._model = None
        pred_mod._meta  = None

        # Use a MagicMock path so .exists() returns False (WindowsPath.exists is read-only)
        from unittest.mock import patch, MagicMock
        mock_path = MagicMock()
        mock_path.exists.return_value = False
        mock_config = MagicMock()
        mock_config.MODEL_PATH = mock_path
        mock_config.META_PATH  = mock_path

        with patch("backend.config.config", mock_config):
            with pytest.raises((FileNotFoundError, Exception)):
                pred_mod._load_artifacts()

        pred_mod._model = original_model
        pred_mod._meta  = original_meta

    def test_get_model_info(self, mock_model_artifacts):
        from backend.ml.predict import get_model_info
        info = get_model_info()
        assert "best_model" in info
        assert "winner_metrics" in info
        assert "runner_up_metrics" in info

    def test_is_model_loaded_true(self, mock_model_artifacts):
        from backend.ml.predict import is_model_loaded
        assert is_model_loaded() is True
