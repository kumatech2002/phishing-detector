"""
features.py — Domain feature extraction pipeline.

This module is the single source of truth for all features used both during
model training and live prediction. Any change here affects both pipelines.

All functions are pure (no network I/O, no side effects) so they can be
tested in isolation and are safe to run on untrusted input.
"""
import re
import math
import unicodedata
from typing import Dict, List, Any

# ---------------------------------------------------------------------------
# Target bank names (canonical lowercase spellings, no TLD)
# ---------------------------------------------------------------------------
NIGERIAN_BANKS: List[str] = [
    "accessbank",
    "gtbank",
    "firstbank",
    "uba",
    "zenithbank",
    "fidelitybank",
    "unionbank",
    "ecobank",
    "stanbicibtc",
    "polarisbank",
]

# Short aliases that might appear in domains
BANK_ALIASES: List[str] = [
    "access",
    "gtb",
    "firstb",
    "zenith",
    "fidelity",
    "union",
    "eco",
    "stanbic",
    "ibtc",
    "polaris",
    "uba",
]

# Suspicious keywords frequently found in phishing domains
SUSPICIOUS_KEYWORDS: List[str] = [
    "secure", "login", "verify", "account", "bank", "online",
    "pay", "update", "confirm", "alert", "support", "service",
    "customer", "portal", "mobile", "internet", "transfer",
    "reset", "activate", "unlock", "authenticate",
]

# Common legitimate TLDs for Nigerian banks
LEGITIMATE_TLDS: List[str] = [".ng", ".com", ".com.ng", ".bank"]

# TLDs that are higher-risk / cheaper to register (proxy for phishing)
RISKY_TLDS: List[str] = [
    ".xyz", ".top", ".club", ".info", ".biz", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".online", ".site", ".space", ".live",
    ".click", ".link", ".work", ".pw", ".cc",
]


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _levenshtein(s1: str, s2: str) -> int:
    """Classic DP Levenshtein distance."""
    if s1 == s2:
        return 0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1, 1):
        curr = [i]
        for j, c2 in enumerate(s2, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _jaro_winkler(s1: str, s2: str) -> float:
    """Jaro-Winkler similarity (0.0–1.0)."""
    if s1 == s2:
        return 1.0
    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0
    match_dist = max(len1, len2) // 2 - 1
    if match_dist < 0:
        match_dist = 0
    s1_matches = [False] * len1
    s2_matches = [False] * len2
    matches = 0
    transpositions = 0
    for i in range(len1):
        start = max(0, i - match_dist)
        end = min(i + match_dist + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break
    if matches == 0:
        return 0.0
    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1
    jaro = (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3
    # Winkler prefix bonus
    prefix = 0
    for i in range(min(4, len1, len2)):
        if s1[i] == s2[i]:
            prefix += 1
        else:
            break
    return jaro + prefix * 0.1 * (1 - jaro)


def _is_idn(domain: str) -> bool:
    """Return True if the domain contains punycode or non-ASCII characters."""
    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        return True
    return "xn--" in domain.lower()


def _extract_registered_domain(domain: str) -> tuple:
    """
    Very lightweight TLD / registered-domain splitter.
    Returns (subdomain_part, sld, tld) without external libraries.
    Handles .com.ng style two-part TLDs.
    """
    domain = domain.lower().strip().lstrip("www.").split("/")[0]
    # Strip port
    domain = domain.split(":")[0]
    parts = domain.split(".")
    if len(parts) < 2:
        return ("", domain, "")
    # Two-part TLD heuristic
    two_part_tlds = {("com", "ng"), ("co", "ng"), ("gov", "ng"), ("edu", "ng"), ("org", "ng")}
    if len(parts) >= 3 and (parts[-2], parts[-1]) in two_part_tlds:
        tld = "." + ".".join(parts[-2:])
        sld = parts[-3]
        subdomains = parts[:-3]
    else:
        tld = "." + parts[-1]
        sld = parts[-2]
        subdomains = parts[:-2]
    return (".".join(subdomains), sld, tld)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(domain: str) -> Dict[str, Any]:
    """
    Extract all features from a domain string.

    Parameters
    ----------
    domain : str
        Raw domain string (e.g. 'gtbank-secure-login.com').

    Returns
    -------
    dict
        Feature name → numeric value mapping.
        All values are float or int to allow direct use with sklearn.
    """
    domain = domain.strip().lower()
    # Strip scheme if accidentally included
    domain = re.sub(r"^https?://", "", domain).split("/")[0].split("?")[0]

    subdomain_part, sld, tld = _extract_registered_domain(domain)
    full_domain_no_tld = (subdomain_part + "." + sld).lstrip(".")
    sld_lower = sld.lower()

    # --- Structural features ---
    f: Dict[str, Any] = {}

    f["domain_length"] = len(domain)
    f["sld_length"] = len(sld_lower)
    f["subdomain_count"] = len(subdomain_part.split(".")) if subdomain_part else 0
    f["dot_count"] = domain.count(".")
    f["hyphen_count"] = domain.count("-")
    f["digit_count"] = sum(c.isdigit() for c in domain)
    f["digit_ratio"] = f["digit_count"] / max(len(domain), 1)

    # --- Lexical features ---
    f["entropy_full"] = _shannon_entropy(domain.replace(".", ""))
    f["entropy_sld"] = _shannon_entropy(sld_lower)
    words = re.split(r"[-_.]", full_domain_no_tld)
    f["word_count"] = len(words)
    f["longest_word_length"] = max((len(w) for w in words), default=0)
    f["avg_word_length"] = sum(len(w) for w in words) / max(len(words), 1)
    f["consonant_ratio"] = sum(c in "bcdfghjklmnpqrstvwxyz" for c in sld_lower) / max(len(sld_lower), 1)
    f["vowel_ratio"] = sum(c in "aeiou" for c in sld_lower) / max(len(sld_lower), 1)

    # --- TLD features ---
    f["is_ng_tld"] = int(tld in (".ng", ".com.ng"))
    f["is_com_tld"] = int(tld == ".com")
    f["is_risky_tld"] = int(tld in RISKY_TLDS)
    # Assign a numeric TLD risk score
    tld_risk_map = {".ng": 0, ".com.ng": 0, ".com": 1, ".net": 2, ".org": 2,
                    ".info": 3, ".biz": 3, ".xyz": 5, ".top": 5, ".tk": 5}
    f["tld_risk_score"] = tld_risk_map.get(tld, 4)

    # --- IDN / Punycode ---
    f["is_idn"] = int(_is_idn(domain))

    # --- Suspicious keyword features ---
    f["suspicious_keyword_count"] = sum(kw in full_domain_no_tld for kw in SUSPICIOUS_KEYWORDS)
    f["has_bank_keyword"] = int("bank" in full_domain_no_tld)
    f["has_secure_keyword"] = int("secure" in full_domain_no_tld)
    f["has_login_keyword"] = int("login" in full_domain_no_tld)
    f["has_verify_keyword"] = int("verify" in full_domain_no_tld)
    f["has_account_keyword"] = int("account" in full_domain_no_tld)
    f["has_online_keyword"] = int("online" in full_domain_no_tld)
    f["has_pay_keyword"] = int("pay" in full_domain_no_tld)
    f["has_update_keyword"] = int("update" in full_domain_no_tld)

    # --- Brand matching features ---
    # Exact SLD match to a known bank name
    f["exact_bank_match"] = int(sld_lower in NIGERIAN_BANKS or sld_lower in BANK_ALIASES)

    # Minimum Levenshtein distance from SLD to any bank name
    lev_distances = [_levenshtein(sld_lower, bank) for bank in NIGERIAN_BANKS]
    alias_lev = [_levenshtein(sld_lower, alias) for alias in BANK_ALIASES]
    all_lev = lev_distances + alias_lev
    f["min_levenshtein"] = min(all_lev)
    f["min_levenshtein_normalized"] = f["min_levenshtein"] / max(max(len(sld_lower), 1), 1)

    # Max Jaro-Winkler similarity to any bank name
    jw_scores = [_jaro_winkler(sld_lower, bank) for bank in NIGERIAN_BANKS]
    alias_jw = [_jaro_winkler(sld_lower, alias) for alias in BANK_ALIASES]
    f["max_jaro_winkler"] = max(jw_scores + alias_jw)

    # Bank name appears as a subdomain (camouflage)
    f["bank_in_subdomain"] = int(any(bank in subdomain_part for bank in NIGERIAN_BANKS + BANK_ALIASES))

    # Bank name embedded anywhere in full domain (but not as clean SLD)
    f["bank_name_embedded"] = int(
        any(bank in full_domain_no_tld for bank in NIGERIAN_BANKS + BANK_ALIASES)
        and not f["exact_bank_match"]
    )

    # SLD contains a bank name as substring (e.g. "accessbank-login")
    f["bank_in_sld_substring"] = int(any(bank in sld_lower for bank in NIGERIAN_BANKS + BANK_ALIASES))

    # Typosquatting signal: close but not exact
    f["typosquatting_signal"] = int(
        f["min_levenshtein"] <= 3
        and f["min_levenshtein"] > 0
        and len(sld_lower) > 3
    )

    # Combination risk: close to bank AND has suspicious keyword
    f["brand_keyword_combo"] = int(
        (f["typosquatting_signal"] or f["bank_name_embedded"]) and f["suspicious_keyword_count"] > 0
    )

    return f


def feature_vector(domain: str) -> List[float]:
    """Return features as an ordered list of floats (for sklearn)."""
    feats = extract_features(domain)
    return [float(feats[k]) for k in get_feature_names()]


def get_feature_names() -> List[str]:
    """Return the ordered list of feature names (stable ordering)."""
    return [
        "domain_length", "sld_length", "subdomain_count", "dot_count",
        "hyphen_count", "digit_count", "digit_ratio",
        "entropy_full", "entropy_sld",
        "word_count", "longest_word_length", "avg_word_length",
        "consonant_ratio", "vowel_ratio",
        "is_ng_tld", "is_com_tld", "is_risky_tld", "tld_risk_score",
        "is_idn",
        "suspicious_keyword_count", "has_bank_keyword", "has_secure_keyword",
        "has_login_keyword", "has_verify_keyword", "has_account_keyword",
        "has_online_keyword", "has_pay_keyword", "has_update_keyword",
        "exact_bank_match", "min_levenshtein", "min_levenshtein_normalized",
        "max_jaro_winkler", "bank_in_subdomain", "bank_name_embedded",
        "bank_in_sld_substring", "typosquatting_signal", "brand_keyword_combo",
    ]


def get_risk_indicators(domain: str) -> List[Dict[str, str]]:
    """
    Return a list of human-readable risk indicator dicts for a domain.
    Used to populate the frontend explanation panel.
    """
    feats = extract_features(domain)
    indicators = []

    if feats["is_idn"]:
        indicators.append({"level": "HIGH", "text": "Domain uses Punycode / IDN encoding — common in homoglyph attacks"})
    if feats["typosquatting_signal"]:
        indicators.append({"level": "HIGH", "text": f"Domain is very similar to a Nigerian bank name (Levenshtein distance: {feats['min_levenshtein']})"})
    if feats["bank_in_subdomain"]:
        indicators.append({"level": "HIGH", "text": "Legitimate bank name appears as a subdomain — classic camouflage technique"})
    if feats["brand_keyword_combo"]:
        indicators.append({"level": "HIGH", "text": "Bank brand combined with suspicious keyword — strong phishing signal"})
    if feats["is_risky_tld"]:
        indicators.append({"level": "MEDIUM", "text": f"TLD is associated with free/cheap registrations often used in phishing"})
    if feats["suspicious_keyword_count"] >= 2:
        indicators.append({"level": "MEDIUM", "text": f"Contains {int(feats['suspicious_keyword_count'])} suspicious keywords (e.g. secure, login, verify)"})
    elif feats["suspicious_keyword_count"] == 1:
        indicators.append({"level": "LOW", "text": "Contains 1 suspicious keyword — not conclusive alone"})
    if feats["hyphen_count"] >= 2:
        indicators.append({"level": "MEDIUM", "text": f"Domain has {int(feats['hyphen_count'])} hyphens — common in phishing URL construction"})
    if feats["digit_count"] > 0 and feats["bank_name_embedded"]:
        indicators.append({"level": "MEDIUM", "text": "Digits appear alongside a bank brand name — typical of random-suffix phishing"})
    if feats["bank_name_embedded"] and not feats["exact_bank_match"]:
        indicators.append({"level": "MEDIUM", "text": "Bank brand name embedded in domain but is not the registered domain itself"})
    if feats["exact_bank_match"] and feats["is_ng_tld"]:
        indicators.append({"level": "INFO", "text": "Domain exactly matches a known Nigerian bank name with an appropriate TLD — strong legitimacy signal"})
    if feats["max_jaro_winkler"] > 0.9 and not feats["exact_bank_match"]:
        indicators.append({"level": "HIGH", "text": f"Very high string similarity to a bank name (Jaro-Winkler: {feats['max_jaro_winkler']:.2f}) without being the exact domain"})
    if feats["entropy_full"] > 4.0:
        indicators.append({"level": "LOW", "text": f"High character entropy ({feats['entropy_full']:.2f}) — may indicate randomly generated domain"})
    if feats["subdomain_count"] > 2:
        indicators.append({"level": "MEDIUM", "text": f"Unusual subdomain depth ({int(feats['subdomain_count'])} levels) — often used to bury legitimate-looking labels"})

    return indicators
