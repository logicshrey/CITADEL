from __future__ import annotations

import unittest

from intelligence.sensitive_detector import detect_sensitive_data


class SensitiveDetectorTests(unittest.TestCase):
    def test_detects_pan_correctly(self) -> None:
        result = detect_sensitive_data("Employee PAN leaked as ABCDE1234F in a dump.")
        self.assertIn("PAN", result.sensitive_types)
        self.assertTrue(any(item.finding_type == "PAN" for item in result.matched_samples))
        self.assertTrue(all(item.masked_value != "ABCDE1234F" for item in result.matched_samples))

    def test_detects_aadhaar_correctly(self) -> None:
        result = detect_sensitive_data("KYC export contains Aadhaar 1234 5678 9123 for an employee.")
        self.assertIn("Aadhaar", result.sensitive_types)

    def test_detects_jwt_correctly(self) -> None:
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIzNDU2"
        result = detect_sensitive_data(f"Leaked bearer token {token}")
        self.assertIn("JWT Token", result.sensitive_types)

    def test_detects_aws_access_key(self) -> None:
        result = detect_sensitive_data("Compromised AWS key AKIAIOSFODNN7EXAMPLE discovered in logs.")
        self.assertIn("AWS Access Key", result.sensitive_types)

    def test_detects_credit_card_only_when_luhn_valid(self) -> None:
        result = detect_sensitive_data("Payment card 4111 1111 1111 1111 was present in the breach.")
        self.assertIn("Credit Card", result.sensitive_types)

        invalid = detect_sensitive_data("Random digits 4111 1111 1111 1112 should not be treated as a valid card.")
        self.assertNotIn("Credit Card", invalid.sensitive_types)

    def test_never_stores_raw_full_values(self) -> None:
        raw = "password=Sup3rS3cret! stripe_key=test_key_placeholder_value"
        result = detect_sensitive_data(raw)
        for finding in result.matched_samples:
            self.assertNotIn("Sup3rS3cret!", finding.masked_value)
            self.assertNotEqual(finding.masked_value, "test_key_placeholder_value")


if __name__ == "__main__":
    unittest.main()
