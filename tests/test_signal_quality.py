from __future__ import annotations

import unittest

from utils.signal_quality import build_event_signature, score_confidence
from utils.source_intel_service import ExternalIntelligenceService, RawSourceHit


class SignalQualityTests(unittest.TestCase):
    def test_event_signature_is_stable_for_same_event(self) -> None:
        signature_one = build_event_signature(
            query="acme.com",
            source="Telegram",
            title="Credential Leak",
            text="Selling admin@acme.com combo with password and session data",
            matched_indicators=["admin@acme.com", "acme.com"],
            source_locations=["channel:12345"],
            channel_hint="channel:12345",
        )
        signature_two = build_event_signature(
            query="acme.com",
            source="Telegram",
            title="Credential Leak",
            text="Selling admin@acme.com combo with password and session data",
            matched_indicators=["acme.com", "admin@acme.com"],
            source_locations=["channel:12345"],
            channel_hint="channel:12345",
        )
        self.assertEqual(signature_one, signature_two)

    def test_confidence_scoring_rewards_direct_matches_and_penalizes_generic_noise(self) -> None:
        strong = score_confidence(
            query="acme.com",
            text="Credential leak for admin@acme.com with password hashes and login combo",
            source="Dehashed",
            matched_indicators=["admin@acme.com", "acme.com"],
            data_types=["credentials", "email addresses"],
            source_locations=["dataset:acme-breach"],
            evidence_count=3,
            metadata={"dataset": "acme-breach"},
        )
        weak = score_confidence(
            query="gmail.com",
            text="gmail.com password dump tutorial notes and allowlist references",
            source="GitHub",
            matched_indicators=["gmail.com"],
            data_types=[],
            source_locations=["training/repo:notes.md"],
            evidence_count=1,
            metadata={"search_type": "code", "path": "notes.md"},
        )
        self.assertGreaterEqual(strong.score, 70)
        self.assertLess(weak.score, 45)
        self.assertTrue(any("Direct monitored domain" in reason for reason in strong.reasons))

    def test_github_training_content_is_rejected_as_relevant_hit(self) -> None:
        hit = RawSourceHit(
            source="GitHub",
            text="notes.md tutorial about CORS policies and sbi.com in an example paragraph",
            date_found="2026-04-15",
            metadata={
                "search_type": "code",
                "repository": "training/example",
                "path": "notes.md",
                "html_url": "https://github.com/training/example/blob/main/notes.md",
            },
        )
        self.assertFalse(ExternalIntelligenceService._is_relevant_hit("sbi.com", hit))


if __name__ == "__main__":
    unittest.main()
