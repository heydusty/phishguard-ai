"""
PhishGuard AI — Feature Extractor
Extracts 20+ lexical, structural, and statistical features from URLs.
No external APIs or network calls required.
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from collections import Counter


# Common phishing-targeted brands
TARGETED_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "linkedin", "twitter",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc",
    "dropbox", "adobe", "outlook", "office365", "icloud",
    "coinbase", "binance", "metamask", "blockchain",
]

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = [
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz",
    ".club", ".work", ".info", ".online", ".site", ".icu",
    ".cam", ".rest", ".monster", ".surf", ".bar",
]

# Known URL shortener domains
SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "tiny.cc", "rb.gy",
    "cutt.ly", "shorturl.at",
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def extract_features(url: str) -> dict:
    """
    Extract 20+ features from a URL string.
    
    Returns a dictionary of feature names and their values.
    All features are computed locally — no network calls.
    """
    features = {}
    
    # Parse URL
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except Exception:
        parsed = urlparse(f"http://{url}")
    
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""
    
    # ── Lexical Features ──────────────────────────────────
    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)
    
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_underscores"] = url.count("_")
    features["num_slashes"] = url.count("/")
    features["num_digits_in_url"] = sum(c.isdigit() for c in url)
    features["num_special_chars"] = sum(
        not c.isalnum() and c not in ":/.-_?" for c in url
    )
    
    # ── Structural Features ───────────────────────────────
    features["num_subdomains"] = max(0, hostname.count(".") - 1)
    features["path_depth"] = len([p for p in path.split("/") if p])
    features["num_query_params"] = len(parse_qs(query))
    features["has_fragment"] = int(bool(fragment))
    features["has_port"] = int(parsed.port is not None and parsed.port not in [80, 443])
    
    # ── Statistical Features ──────────────────────────────
    alpha_count = sum(c.isalpha() for c in url)
    digit_count = sum(c.isdigit() for c in url)
    
    features["digit_to_letter_ratio"] = round(
        digit_count / max(alpha_count, 1), 4
    )
    features["special_char_ratio"] = round(
        features["num_special_chars"] / max(len(url), 1), 4
    )
    features["entropy"] = round(calculate_entropy(url), 4)
    features["hostname_entropy"] = round(calculate_entropy(hostname), 4)
    
    vowels = sum(c.lower() in "aeiou" for c in hostname)
    consonants = sum(c.lower() in "bcdfghjklmnpqrstvwxyz" for c in hostname)
    features["vowel_consonant_ratio"] = round(
        vowels / max(consonants, 1), 4
    )
    
    # ── Heuristic / Boolean Features ──────────────────────
    features["uses_https"] = int(parsed.scheme == "https")
    
    # Check if hostname is an IP address
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    features["has_ip_address"] = int(bool(ip_pattern.match(hostname)))
    
    features["has_at_symbol"] = int("@" in url)
    
    # URL shortener detection
    features["is_shortened"] = int(
        any(shortener in url.lower() for shortener in SHORTENERS)
    )
    
    # Suspicious TLD
    features["suspicious_tld"] = int(
        any(hostname.lower().endswith(tld) for tld in SUSPICIOUS_TLDS)
    )
    
    # Brand impersonation (brand name in subdomain/path but not actual domain)
    url_lower = url.lower()
    features["brand_impersonation"] = int(
        any(
            brand in url_lower and brand not in hostname.lower().split(".")[-2:-1]
            for brand in TARGETED_BRANDS
        )
    )
    
    # Excessive length flags
    features["is_long_url"] = int(len(url) > 75)
    features["is_long_hostname"] = int(len(hostname) > 30)
    
    # Contains double slashes in path (common obfuscation)
    features["has_double_slash_redirect"] = int("//" in path)
    
    # Hex/encoded characters in URL
    features["has_hex_chars"] = int(bool(re.search(r"%[0-9a-fA-F]{2}", url)))
    
    return features


def get_feature_names() -> list:
    """Return ordered list of feature names for model training."""
    sample = extract_features("https://example.com")
    return sorted(sample.keys())


def features_to_vector(features: dict) -> list:
    """Convert feature dict to ordered list for model input."""
    return [features[key] for key in sorted(features.keys())]


def get_risk_flags(features: dict) -> list:
    """Return human-readable risk flags for a feature set."""
    flags = []
    
    if features.get("suspicious_tld"):
        flags.append("⚠ Suspicious TLD")
    if features.get("has_ip_address"):
        flags.append("⚠ Uses raw IP address instead of domain")
    if features.get("brand_impersonation"):
        flags.append("⚠ Brand impersonation detected")
    if features.get("is_shortened"):
        flags.append("⚠ URL shortener detected")
    if features.get("has_at_symbol"):
        flags.append("⚠ Contains @ symbol (redirect trick)")
    if features.get("is_long_url"):
        flags.append(f"⚠ URL length abnormally high ({features['url_length']} chars)")
    if features.get("num_subdomains", 0) >= 3:
        flags.append(f"⚠ Excessive subdomains ({features['num_subdomains']})")
    if not features.get("uses_https"):
        flags.append("⚠ No HTTPS encryption")
    if features.get("has_double_slash_redirect"):
        flags.append("⚠ Double-slash redirect in path")
    if features.get("entropy", 0) > 4.5:
        flags.append(f"⚠ High entropy ({features['entropy']}) — possibly randomized")
    if features.get("has_hex_chars"):
        flags.append("⚠ Hex-encoded characters detected")
    if features.get("has_port"):
        flags.append("⚠ Non-standard port used")
    
    return flags


if __name__ == "__main__":
    # Quick demo
    test_urls = [
        "https://www.google.com/search?q=hello",
        "http://192.168.1.1/admin/login.php",
        "http://secure-paypa1.account-verify.xyz/login?id=12345",
        "https://bit.ly/3xK9mN2",
    ]
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"URL: {url}")
        print(f"{'='*60}")
        feats = extract_features(url)
        for name, val in sorted(feats.items()):
            print(f"  {name:30s} = {val}")
        flags = get_risk_flags(feats)
        if flags:
            print("\n  Risk Flags:")
            for flag in flags:
                print(f"    {flag}")
