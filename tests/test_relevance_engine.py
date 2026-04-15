from __future__ import annotations

import unittest

from intelligence.relevance_engine import OrganizationProfile, assess_organization_relevance
from intelligence.validators.email_validator import validate_semantic_email


class RelevanceEngineTests(unittest.TestCase):
    def test_semantic_email_validator_rejects_service_email(self) -> None:
        result = validate_semantic_email("modprobe@fuse.service", official_domains=["sbi.co.in"])
        self.assertFalse(result.is_valid_email)
        self.assertIn("service", result.rejection_reason.lower())

    def test_semantic_email_validator_accepts_org_email(self) -> None:
        result = validate_semantic_email("employee@sbi.co.in", official_domains=["sbi.co.in"])
        self.assertTrue(result.is_valid_email)
        self.assertTrue(result.is_org_relevant)

    def test_relevance_engine_retains_only_org_relevant_assets(self) -> None:
        profile = OrganizationProfile(
            org_name="State Bank of India",
            org_keywords=["state", "bank", "india", "sbi"],
            official_domains=["sbi.co.in", "onlinesbi.com"],
            email_patterns=["*@sbi.co.in"],
            known_ips=[],
            known_brands=["SBI Bank"],
            trusted_assets=["sbi.co.in"],
        )
        assessment = assess_organization_relevance(
            profile=profile,
            extracted_entities=[
                {"text": "employee@sbi.co.in", "label": "EMAIL"},
                {"text": "modprobe@fuse.service", "label": "EMAIL"},
                {"text": "sbi.co.in", "label": "DOMAIN"},
                {"text": "robots.txt", "label": "DOMAIN"},
                {"text": "sbi-co-in_ops", "label": "USERNAME"},
                {"text": "sessionbroker_demo", "label": "USERNAME"},
            ],
            raw_evidence_snippet="Credential dump for State Bank of India employee@sbi.co.in from the SBI Bank portal.",
            source_metadata={"source": "Dehashed"},
        )
        self.assertEqual(assessment.matched_assets["emails"], ["employee@sbi.co.in"])
        self.assertEqual(assessment.matched_assets["domains"], ["sbi.co.in"])
        self.assertEqual(assessment.matched_assets["usernames"], ["sbi-co-in_ops"])
        self.assertGreaterEqual(assessment.relevance_score, 45)
        self.assertFalse(assessment.suppressed_noise)


if __name__ == "__main__":
    unittest.main()
