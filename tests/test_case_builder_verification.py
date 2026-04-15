from __future__ import annotations

import unittest

from utils.nlp_engine import ThreatIntelligenceEngine


class CaseBuilderVerificationTests(unittest.TestCase):
    def test_case_builder_includes_verification_and_sensitive_fields(self) -> None:
        engine = ThreatIntelligenceEngine.__new__(ThreatIntelligenceEngine)
        result = {
            "timestamp": "2026-04-15T00:00:00+00:00",
            "input_text": "Credential dump for admin@acme.com password=Sup3rSecret! PAN ABCDE1234F and token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signature123",
            "threat_type": "Credential Leak",
            "risk_level": "HIGH",
            "external_intelligence": {
                "source": "Dehashed",
                "organization": "acme.com",
                "matched_indicators": ["acme.com", "admin@acme.com"],
                "affected_assets": ["acme.com", "admin@acme.com"],
                "data_types": ["credentials", "email addresses"],
                "confidence_reasons": ["Direct monitored domain match."],
                "summary": "Credential dump affecting acme.com administrators.",
                "estimated_records": "120 records",
                "estimated_record_count": 120,
                "source_locations": ["dataset:acme-breach"],
                "source_trust": 0.91,
                "related_sources": [],
                "data_breakdown": [{"label": "credentials", "count": 120}],
                "volume": 1,
            },
            "relevance_assessment": {
                "relevance_score": 92,
                "relevance_reasons": ["Official domain and email indicators were verified."],
                "verified_org_match": True,
                "verification_status": "YES",
                "suppressed_noise": False,
                "suppression_reasons": [],
            },
            "correlation_assessment": {
                "correlation_score": 88,
                "reasoning": ["Source and indicators strongly align to the monitored organization."],
                "matched_watchlist_entities": ["acme.com", "admin@acme.com"],
                "validated_entity_count": 2,
                "source_trust": 0.91,
            },
            "confidence_assessment": {"reasons": ["Direct monitored domain match."]},
            "patterns": {"passwords": ["password=Sup3rSecret!"]},
            "entities": [{"entity_type": "TOKEN", "text": "masked"}],
        }

        case_payload = engine._build_exposure_case("acme.com", result, watchlist=None)

        self.assertIn("verification_badge", case_payload)
        self.assertIn("verification_score", case_payload)
        self.assertIn("verification_reasons", case_payload)
        self.assertIn("sensitive_data_types", case_payload)
        self.assertIn("sensitive_findings", case_payload)
        self.assertIn("sensitive_risk_score", case_payload)
        self.assertTrue(case_payload["verification_reasons"])
        self.assertTrue(case_payload["sensitive_data_types"])
        self.assertTrue(case_payload["sensitive_findings"])


if __name__ == "__main__":
    unittest.main()
