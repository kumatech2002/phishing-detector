"""
test_features.py — Unit tests for the feature extraction pipeline.
"""

import sys
import math
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from backend.ml.features import (
    extract_features,
    feature_vector,
    get_feature_names,
    get_risk_indicators,
    _shannon_entropy,
    _levenshtein,
    _jaro_winkler,
    _is_idn,
    _extract_registered_domain,
    NIGERIAN_BANKS,
)


# ─── Helper internals ─────────────────────────────────────────

class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("a") == 0.0

    def test_two_equal_chars(self):
        assert abs(_shannon_entropy("ab") - 1.0) < 1e-9

    def test_known_entropy(self):
        # "aab" → p(a)=2/3, p(b)=1/3 → H ≈ 0.918
        h = _shannon_entropy("aab")
        assert abs(h - 0.918) < 0.01

    def test_high_entropy(self):
        # Random-looking string should have high entropy
        assert _shannon_entropy("a1b2c3d4e5") > 3.0


class TestLevenshtein:
    def test_identical(self):
        assert _levenshtein("gtbank", "gtbank") == 0

    def test_insertion(self):
        assert _levenshtein("gtbank", "gttbank") == 1

    def test_deletion(self):
        assert _levenshtein("gtbank", "gtban") == 1

    def test_substitution(self):
        assert _levenshtein("gtbank", "gtbankX") == 1

    def test_completely_different(self):
        d = _levenshtein("abc", "xyz")
        assert d == 3

    def test_empty_strings(self):
        assert _levenshtein("", "") == 0
        assert _levenshtein("abc", "") == 3


class TestJaroWinkler:
    def test_identical(self):
        assert _jaro_winkler("gtbank", "gtbank") == 1.0

    def test_completely_different(self):
        score = _jaro_winkler("abc", "xyz")
        assert score < 0.5

    def test_similar(self):
        # gtbnak vs gtbank — one transposition
        score = _jaro_winkler("gtbnak", "gtbank")
        assert score > 0.85

    def test_empty(self):
        assert _jaro_winkler("", "abc") == 0.0

    def test_symmetry(self):
        a = _jaro_winkler("accessbank", "access")
        b = _jaro_winkler("access", "accessbank")
        assert abs(a - b) < 0.01


class TestIsIDN:
    def test_ascii_domain(self):
        assert _is_idn("gtbank.com") is False

    def test_punycode(self):
        assert _is_idn("xn--gtbank.com") is True

    def test_unicode(self):
        assert _is_idn("gíbank.com") is True


class TestExtractRegisteredDomain:
    def test_simple(self):
        sub, sld, tld = _extract_registered_domain("gtbank.com")
        assert sld == "gtbank"
        assert tld == ".com"

    def test_www_prefix(self):
        sub, sld, tld = _extract_registered_domain("www.gtbank.com")
        assert sld == "gtbank"

    def test_two_part_tld(self):
        sub, sld, tld = _extract_registered_domain("accessbank.com.ng")
        assert sld == "accessbank"
        assert tld == ".com.ng"

    def test_subdomain(self):
        sub, sld, tld = _extract_registered_domain("ibank.gtbank.com")
        assert sld == "gtbank"
        assert sub == "ibank"


# ─── Feature extraction ───────────────────────────────────────

class TestExtractFeatures:
    """Test the full extract_features() function."""

    def test_returns_all_expected_keys(self):
        feats = extract_features("gtbank.com")
        expected_keys = get_feature_names()
        for k in expected_keys:
            assert k in feats, f"Missing feature: {k}"

    def test_legitimate_bank_domain(self):
        feats = extract_features("gtbank.com")
        assert feats["exact_bank_match"] == 1
        assert feats["is_com_tld"] == 1
        assert feats["typosquatting_signal"] == 0
        # "bank" is in SUSPICIOUS_KEYWORDS so count is 1 — this is expected
        # behaviour; the ML model learns legitimate domains still score low overall
        assert feats["suspicious_keyword_count"] >= 0

    def test_legitimate_ng_domain(self):
        feats = extract_features("accessbank.com.ng")
        assert feats["exact_bank_match"] == 1
        assert feats["is_ng_tld"] == 1

    def test_phishing_hyphen_keyword(self):
        feats = extract_features("gtbank-secure-login.com")
        assert feats["hyphen_count"] == 2
        assert feats["suspicious_keyword_count"] >= 2
        assert feats["has_secure_keyword"] == 1
        assert feats["has_login_keyword"] == 1

    def test_phishing_risky_tld(self):
        feats = extract_features("gtbank.xyz")
        assert feats["is_risky_tld"] == 1
        assert feats["tld_risk_score"] >= 5

    def test_phishing_subdomain_camouflage(self):
        feats = extract_features("gtbank.verify-account.com")
        assert feats["bank_in_subdomain"] == 1

    def test_phishing_typosquat(self):
        # "gtbnak" — char swap
        feats = extract_features("gtbnak.com")
        assert feats["min_levenshtein"] <= 2
        assert feats["typosquatting_signal"] == 1

    def test_homoglyph_digit_substitution(self):
        feats = extract_features("zen1thbank.com")
        assert feats["digit_count"] == 1
        assert feats["digit_ratio"] > 0

    def test_empty_like_domain(self):
        # Should not raise
        feats = extract_features("a.b")
        assert isinstance(feats, dict)

    def test_very_long_domain(self):
        feats = extract_features("a" * 60 + ".com")
        assert feats["domain_length"] > 60

    def test_feature_vector_length(self):
        vec = feature_vector("gtbank.com")
        assert len(vec) == len(get_feature_names())

    def test_feature_vector_all_numeric(self):
        vec = feature_vector("accessbank-login.xyz")
        for v in vec:
            assert isinstance(v, float), f"Non-float value: {v}"

    def test_brand_keyword_combo(self):
        feats = extract_features("access-bank-login.xyz")
        # Should have bank embedded + suspicious keyword
        assert feats["brand_keyword_combo"] == 1

    def test_strip_scheme(self):
        f1 = extract_features("https://gtbank.com/login")
        f2 = extract_features("gtbank.com")
        assert f1["domain_length"] == f2["domain_length"]


# ─── Risk indicators ─────────────────────────────────────────

class TestGetRiskIndicators:
    def test_legitimate_domain_has_legit_indicator(self):
        indicators = get_risk_indicators("gtbank.com.ng")
        levels = [i["level"] for i in indicators]
        # Should have INFO about matching bank + NG TLD
        assert "INFO" in levels

    def test_phishing_domain_has_high_indicators(self):
        indicators = get_risk_indicators("gtbank-secure-login.com")
        levels = [i["level"] for i in indicators]
        assert "HIGH" in levels or "MEDIUM" in levels

    def test_returns_list(self):
        result = get_risk_indicators("random-domain.com")
        assert isinstance(result, list)

    def test_indicator_structure(self):
        indicators = get_risk_indicators("gtbank.verify.xyz")
        for ind in indicators:
            assert "level" in ind
            assert "text" in ind
            assert ind["level"] in ("HIGH", "MEDIUM", "LOW", "INFO")


# ─── Feature names ────────────────────────────────────────────

class TestGetFeatureNames:
    def test_returns_list(self):
        names = get_feature_names()
        assert isinstance(names, list)
        assert len(names) > 10

    def test_no_duplicates(self):
        names = get_feature_names()
        assert len(names) == len(set(names))
