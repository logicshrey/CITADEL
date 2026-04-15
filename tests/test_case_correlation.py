from __future__ import annotations

import unittest

from intelligence.correlation import assess_correlation
from intelligence.scoring import score_case


class CaseCorrelationTests(unittest.TestCase):
    def test_strong_domain_and_credentials_signal_creates_case(self) -> None:
        result = {
            "input_text": "Credential leak for admin@acme.com with password hash and combo access.",
            "source": "Dehashed",
            "entities": [
                {
                    "text": "admin@acme.com",
                    "label": "EMAIL",
                    "entity_type": "EMAIL",
                    "confidence": 0.99,
                    "validation_reason": "Validated email with domain acme.com.",
                },
                {
                    "text": "acme.com",
                    "label": "DOMAIN",
                    "entity_type": "DOMAIN",
                    "confidence": 0.97,
                    "validation_reason": "Validated domain structure and rejected file-like suffixes.",
                },
            ],
            "patterns": {"passwords": ["password=Spring2026!"]},
            "external_intelligence": {
                "source": "Dehashed",
                "source_trust": 0.85,
                "source_locations": ["dataset:acme-breach"],
                "data_types": ["credentials", "email addresses"],
            },
            "relevance_assessment": {
                "relevance_score": 92,
                "verified_org_match": True,
                "suppressed_noise": False,
                "matched_indicators": ["acme.com", "admin@acme.com"],
                "verified_asset_count": 2,
                "suppression_reasons": [],
                "relevance_reasons": ["Official domain and org email were verified."],
            },
            "confidence_assessment": {"source_trust": 0.85},
            "threat_type": "Credential Leak",
        }

        assessment = assess_correlation(query="acme.com", result=result)
        case_score = score_case(result, assessment.to_dict())

        self.assertTrue(assessment.should_create_case)
        self.assertGreaterEqual(assessment.correlation_score, 55)
        self.assertEqual(case_score.severity, "Critical")

    def test_weak_org_mention_without_validated_assets_is_rejected(self) -> None:
        result = {
            "input_text": "Discussion about major bank brands and generic phishing trends on public forums.",
            "source": "Telegram",
            "entities": [],
            "patterns": {},
            "external_intelligence": {
                "source": "Telegram",
                "source_trust": 0.2,
                "source_locations": [],
                "data_types": ["undetermined"],
            },
            "relevance_assessment": {
                "relevance_score": 18,
                "verified_org_match": True,
                "suppressed_noise": True,
                "matched_indicators": [],
                "verified_asset_count": 0,
                "suppression_reasons": ["No verified organization-owned domains, emails, IPs, usernames, or tokens were retained."],
                "relevance_reasons": ["Evidence contains an explicit organization identifier but no verified organization-owned assets."],
            },
            "confidence_assessment": {"source_trust": 0.2},
            "threat_type": "Phishing",
        }

        assessment = assess_correlation(query="Acme Bank", result=result)
        self.assertFalse(assessment.should_create_case)
        self.assertLessEqual(assessment.relevance_score, 40)
        case_score = score_case(result, assessment.to_dict())
        self.assertLessEqual(case_score.confidence_score, 40)
        self.assertIn(case_score.severity, {"Low", "Medium"})


if __name__ == "__main__":
    unittest.main()
