from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from utils.intel_enrichment import correlate_alerts
from utils.reporting import generate_pdf_report


class ReportingTests(unittest.TestCase):
    def test_correlation_uses_event_signature_and_shared_indicators(self) -> None:
        candidate = {
            "event_signature": "shared-event-1",
            "threat_type": "Credential Leak",
            "entities": [{"text": "admin@acme.com", "label": "EMAIL"}],
            "enriched_entities": [{"text": "acme.com", "label": "DOMAIN"}],
            "slang_decoder": {"decoded_terms": []},
            "external_intelligence": {"source_locations": ["channel:12345"]},
        }
        recent = [
            {
                "results": {
                    "event_signature": "shared-event-1",
                    "threat_type": "Credential Leak",
                    "timestamp": "2026-04-15T00:00:00+00:00",
                    "entities": [{"text": "admin@acme.com", "label": "EMAIL"}],
                    "enriched_entities": [{"text": "acme.com", "label": "DOMAIN"}],
                    "slang_decoder": {"decoded_terms": []},
                    "external_intelligence": {"source_locations": ["channel:12345"]},
                }
            }
        ]
        correlation = correlate_alerts(candidate, recent)
        self.assertEqual(correlation["correlated_alerts_count"], 1)
        self.assertGreaterEqual(correlation["campaign_score"], 50)

    def test_pdf_report_is_generated(self) -> None:
        case = {
            "id": "case_demo_1",
            "case_id": "case_demo_1",
            "org_id": "acme.com",
            "organization": "acme.com",
            "title": "Acme exposure detected via Dehashed",
            "category": "Credential Leak",
            "severity": "High",
            "confidence_score": 88,
            "risk_score": 83,
            "affected_assets": {
                "domains": ["acme.com"],
                "emails": ["admin@acme.com"],
                "ips": [],
                "usernames": ["acme_admin"],
                "tokens": [],
                "wallets": [],
            },
            "sources": [{"source": "Dehashed", "source_locations": ["dataset:acme-breach"]}],
            "evidence": [
                {
                    "evidence_id": "e1",
                    "source_platform": "Dehashed",
                    "cleaned_snippet": "Credential dump includes admin@acme.com and password hashes.",
                    "timestamp": "2026-04-15T00:00:00+00:00",
                }
            ],
            "matched_indicators": ["acme.com", "admin@acme.com"],
            "why_this_was_flagged": ["Direct monitored domain or indicator match."],
            "recommended_actions": ["Reset credentials and review MFA."],
            "exposure_summary": "A credential leak affecting Acme requires review.",
            "technical_summary": "Dehashed-style breach evidence exposed an Acme administrator account.",
            "created_at": "2026-04-15T00:00:00+00:00",
            "updated_at": "2026-04-15T00:00:00+00:00",
            "first_seen": "2026-04-15T00:00:00+00:00",
            "last_seen": "2026-04-15T00:00:00+00:00",
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            original_tempdir = tempfile.tempdir
            tempfile.tempdir = temp_dir
            try:
                pdf_path = generate_pdf_report([case], org_id="acme.com")
                self.assertTrue(Path(pdf_path).exists())
                self.assertEqual(Path(pdf_path).suffix.lower(), ".pdf")
                self.assertGreater(Path(pdf_path).stat().st_size, 1000)
            finally:
                tempfile.tempdir = original_tempdir


if __name__ == "__main__":
    unittest.main()
