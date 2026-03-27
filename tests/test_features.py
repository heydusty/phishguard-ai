"""
PhishGuard AI — Unit Tests
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.feature_extractor import (
    extract_features,
    features_to_vector,
    get_feature_names,
    get_risk_flags,
    calculate_entropy,
)


class TestFeatureExtractor(unittest.TestCase):
    
    def test_basic_extraction(self):
        features = extract_features("https://www.google.com/search?q=test")
        self.assertIsInstance(features, dict)
        self.assertGreater(len(features), 15)
    
    def test_https_detection(self):
        f1 = extract_features("https://example.com")
        f2 = extract_features("http://example.com")
        self.assertEqual(f1["uses_https"], 1)
        self.assertEqual(f2["uses_https"], 0)
    
    def test_ip_address_detection(self):
        f = extract_features("http://192.168.1.1/login")
        self.assertEqual(f["has_ip_address"], 1)
    
    def test_legitimate_url_no_ip(self):
        f = extract_features("https://google.com")
        self.assertEqual(f["has_ip_address"], 0)
    
    def test_suspicious_tld(self):
        f = extract_features("http://phishing-site.xyz/login")
        self.assertEqual(f["suspicious_tld"], 1)
    
    def test_normal_tld(self):
        f = extract_features("https://google.com")
        self.assertEqual(f["suspicious_tld"], 0)
    
    def test_at_symbol(self):
        f = extract_features("http://legitimate.com@evil.com/login")
        self.assertEqual(f["has_at_symbol"], 1)
    
    def test_subdomain_count(self):
        f = extract_features("http://a.b.c.example.com")
        self.assertGreaterEqual(f["num_subdomains"], 3)
    
    def test_url_shortener_detection(self):
        f = extract_features("https://bit.ly/abc123")
        self.assertEqual(f["is_shortened"], 1)
    
    def test_brand_impersonation(self):
        f = extract_features("http://secure-paypal-verify.evil.xyz/login")
        self.assertEqual(f["brand_impersonation"], 1)
    
    def test_entropy_calculation(self):
        e1 = calculate_entropy("aaaa")
        e2 = calculate_entropy("abcd")
        self.assertLess(e1, e2)  # Uniform string has lower entropy
    
    def test_entropy_empty(self):
        self.assertEqual(calculate_entropy(""), 0.0)
    
    def test_feature_vector_ordering(self):
        features = extract_features("https://example.com")
        vector = features_to_vector(features)
        names = get_feature_names()
        self.assertEqual(len(vector), len(names))
    
    def test_feature_names_consistent(self):
        names1 = get_feature_names()
        names2 = get_feature_names()
        self.assertEqual(names1, names2)
    
    def test_risk_flags_phishing(self):
        features = extract_features("http://192.168.1.1:8080/paypal-verify.xyz")
        flags = get_risk_flags(features)
        self.assertIsInstance(flags, list)
        self.assertGreater(len(flags), 0)
    
    def test_risk_flags_legit(self):
        features = extract_features("https://www.google.com")
        flags = get_risk_flags(features)
        self.assertIsInstance(flags, list)
    
    def test_long_url_flag(self):
        long_url = "http://example.com/" + "a" * 100
        f = extract_features(long_url)
        self.assertEqual(f["is_long_url"], 1)
    
    def test_hex_chars_detection(self):
        f = extract_features("http://example.com/%2F%2Fevil.com")
        self.assertEqual(f["has_hex_chars"], 1)
    
    def test_query_param_count(self):
        f = extract_features("http://example.com?a=1&b=2&c=3")
        self.assertEqual(f["num_query_params"], 3)


class TestEdgeCases(unittest.TestCase):
    
    def test_empty_string(self):
        features = extract_features("")
        self.assertIsInstance(features, dict)
    
    def test_no_scheme(self):
        features = extract_features("example.com/path")
        self.assertIsInstance(features, dict)
    
    def test_unicode_url(self):
        features = extract_features("http://例え.jp/テスト")
        self.assertIsInstance(features, dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
