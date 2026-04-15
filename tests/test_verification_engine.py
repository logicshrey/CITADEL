from __future__ import annotations

import unittest

from intelligence.verification_engine import compute_verification_status


class VerificationEngineTests(unittest.TestCase):
    def test_verified_when_relevance_evidence_and_sensitive_high(self) -> None:
        result = compute_verification_status(
            {
                "relevance_score": 91,
                "confidence_score": 89,
                "severity_score": 88,
                "evidence_count": 2,
                "verified_org_match": True,
                "sensitive_data_types": ["Credential Pair", "JWT Token"],
                "sources": [{"trust_score": 0.91}],
            }
        )
        self.assertEqual(result.verification_badge, "VERIFIED")
        self.assertGreaterEqual(result.verification_score, 86)

    def test_weak_when_keyword_only_match(self) -> None:
        result = compute_verification_status(
            {
                "relevance_score": 28,
                "confidence_score": 41,
                "severity_score": 35,
                "evidence_count": 1,
                "verified_org_match": False,
                "sensitive_data_types": [],
                "sources": [{"trust_score": 0.2}],
                "suppressed_noise": True,
            }
        )
        self.assertEqual(result.verification_badge, "WEAK_SIGNAL")

    def test_likely_for_medium_confidence(self) -> None:
        result = compute_verification_status(
            {
                "relevance_score": 72,
                "confidence_score": 69,
                "severity_score": 58,
                "evidence_count": 1,
                "verified_org_match": True,
                "sensitive_data_types": ["PAN"],
                "sources": [{"trust_score": 0.55}],
            }
        )
        self.assertEqual(result.verification_badge, "LIKELY")


if __name__ == "__main__":
    unittest.main()
