from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from utils.local_store import LocalMonitoringStore


class LocalStoreTests(unittest.TestCase):
    def test_similar_cases_merge_into_single_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = LocalMonitoringStore(Path(temp_dir) / "monitoring_state.json")
            base_case = {
                "organization": "acme.com",
                "org_id": "acme.com",
                "query": "acme.com",
                "category": "Credential Leak",
                "threat_type": "Credential Leak",
                "priority": "HIGH",
                "priority_score": 80,
                "risk_level": "HIGH",
                "risk_score": 0.86,
                "confidence_score": 0.91,
                "summary": "Credential leak for admin@acme.com with password dump.",
                "exposure_summary": "A credential leak affects Acme.",
                "why_this_was_flagged": ["Direct monitored domain or indicator match."],
                "affected_assets": ["acme.com", "admin@acme.com"],
                "matched_indicators": ["acme.com", "admin@acme.com"],
                "sources": [
                    {
                        "source": "Telegram",
                        "first_seen": "2026-04-15T00:00:00+00:00",
                        "last_seen": "2026-04-15T00:00:00+00:00",
                        "evidence_count": 1,
                        "source_locations": ["channel:12345"],
                    }
                ],
                "evidence": [
                    {
                        "evidence_id": "e1",
                        "timestamp": "2026-04-15T00:00:00+00:00",
                        "source_platform": "Telegram",
                        "cleaned_snippet": "Credential leak for admin@acme.com with password dump.",
                        "matched_entities": ["admin@acme.com", "acme.com"],
                    }
                ],
                "first_seen": "2026-04-15T00:00:00+00:00",
                "last_seen": "2026-04-15T00:00:00+00:00",
            }
            near_duplicate = {
                **base_case,
                "summary": "Credential leak for admin@acme.com with password dump and reused session data.",
                "evidence": [
                    {
                        "evidence_id": "e2",
                        "timestamp": "2026-04-15T12:00:00+00:00",
                        "source_platform": "Pastebin",
                        "cleaned_snippet": "Credential leak for admin@acme.com with password dump and reused session data.",
                        "matched_entities": ["admin@acme.com", "acme.com"],
                    }
                ],
                "sources": [
                    {
                        "source": "Pastebin",
                        "first_seen": "2026-04-15T12:00:00+00:00",
                        "last_seen": "2026-04-15T12:00:00+00:00",
                        "evidence_count": 1,
                        "source_locations": ["paste:abc123"],
                    }
                ],
                "last_seen": "2026-04-15T12:00:00+00:00",
            }

            first_case, first_action = store.save_case(base_case)
            second_case, second_action = store.save_case(near_duplicate)

            self.assertEqual(first_action, "created")
            self.assertEqual(second_action, "updated")
            self.assertEqual(first_case["id"], second_case["id"])
            self.assertEqual(len(store.list_cases(limit=10)), 1)
            self.assertEqual(second_case["evidence_count"], 2)


if __name__ == "__main__":
    unittest.main()
