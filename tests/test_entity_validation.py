from __future__ import annotations

import unittest

from intelligence.validators import filter_pattern_matches, validate_entity
from intelligence.validators.email_validator import validate_semantic_email
from utils.source_intel_service import ExternalIntelligenceService, RawSourceHit


class EntityValidationTests(unittest.TestCase):
    def test_strict_email_validation_rejects_filelike_domain(self) -> None:
        self.assertIsNone(validate_entity("Bremsanlage@2x.png", "EMAIL"))

    def test_strict_email_validation_accepts_real_email(self) -> None:
        result = validate_entity("security@acme.com", "EMAIL")
        self.assertIsNotNone(result)
        self.assertEqual(result["entity_type"], "EMAIL")
        self.assertGreaterEqual(result["confidence"], 0.95)
        self.assertIn("Validated email", result["validation_reason"])

    def test_strict_email_validation_rejects_service_domain_email(self) -> None:
        self.assertIsNone(validate_entity("sshd@sshd-keygen.service", "EMAIL"))

    def test_semantic_email_validation_marks_org_relevance(self) -> None:
        result = validate_semantic_email("employee@sbi.co.in", official_domains=["sbi.co.in"])
        self.assertTrue(result.is_valid_email)
        self.assertTrue(result.is_org_relevant)

    def test_domain_validation_rejects_common_file_artifacts(self) -> None:
        self.assertIsNone(validate_entity("robots.txt", "DOMAIN"))
        self.assertIsNone(validate_entity("index.php", "DOMAIN"))
        self.assertIsNone(validate_entity("https://acme.com/login", "DOMAIN"))

    def test_ip_validation_rejects_invalid_and_accepts_valid(self) -> None:
        self.assertIsNone(validate_entity("999.10.10.10", "IP"))
        result = validate_entity("2001:db8::1", "IP")
        self.assertIsNotNone(result)
        self.assertEqual(result["text"], "2001:db8::1")

    def test_token_validation_requires_entropy_and_length(self) -> None:
        self.assertIsNone(validate_entity("aaaaaaaaaaaaaaaaaaaa", "TOKEN"))
        result = validate_entity("token_demo_4f9K2qA7LmN8pR3tV6xY1zW0", "TOKEN")
        self.assertIsNotNone(result)
        self.assertEqual(result["entity_type"], "TOKEN")

    def test_pattern_filtering_removes_invalid_email_domain_and_ip(self) -> None:
        filtered = filter_pattern_matches(
            {
                "emails": ["Bremsanlage@2x.png", "security@acme.com"],
                "domains": ["robots.txt", "acme.com"],
                "ips": ["10.10.10.999", "10.10.10.10"],
            }
        )
        self.assertEqual(filtered["emails"], ["security@acme.com"])
        self.assertEqual(filtered["domains"], ["acme.com"])
        self.assertEqual(filtered["ips"], ["10.10.10.10"])

    def test_external_service_extractors_use_validators(self) -> None:
        hit = RawSourceHit(
            source="GitHub",
            text=(
                "Credential leak markers for security@acme.com and Bremsanlage@2x.png "
                "plus domains acme.com robots.txt and IPs 10.10.10.10 999.1.1.1"
            ),
            date_found="2026-04-15",
            metadata={},
        )
        service = ExternalIntelligenceService()
        self.assertEqual(service._extract_emails([hit]), ["security@acme.com"])
        self.assertEqual(service._extract_domains([hit]), ["acme.com"])
        self.assertEqual(service._extract_ip_addresses([hit]), ["10.10.10.10"])


if __name__ == "__main__":
    unittest.main()
