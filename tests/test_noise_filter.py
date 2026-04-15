from __future__ import annotations

import unittest

from intelligence.noise_filter import assess_noise, build_canonical_event_signature


class NoiseFilterTests(unittest.TestCase):
    def test_junk_file_listing_is_flagged_as_noise(self) -> None:
        text = "\n".join(
            [
                "robots.txt",
                "index.php",
                "db.php",
                "readme.md",
                "sitemap.xml",
                "status: 200",
            ]
        )
        result = assess_noise(text, source="GitHub")
        self.assertTrue(result.likely_noise)
        self.assertGreaterEqual(result.score, 25)

    def test_real_leak_text_with_matched_asset_is_not_flagged_as_noise(self) -> None:
        text = "Credential leak for admin@acme.com with password hash and combo access."
        result = assess_noise(text, source="Dehashed", matched_assets=["acme.com", "admin@acme.com"])
        self.assertFalse(result.likely_noise)

    def test_event_signature_ignores_timestamps_and_random_ids(self) -> None:
        signature_one = build_canonical_event_signature(
            query="acme.com",
            source="Telegram",
            title="Credential Leak",
            text="2026-04-15T10:00:00Z event_id=abcdef123456 Selling admin@acme.com combo with password hash",
            matched_indicators=["admin@acme.com", "acme.com"],
            source_locations=["channel:12345"],
        )
        signature_two = build_canonical_event_signature(
            query="acme.com",
            source="Telegram",
            title="Credential Leak",
            text="2026-04-16T11:45:00Z event_id=fedcba654321 Selling admin@acme.com combo with password hash",
            matched_indicators=["acme.com", "admin@acme.com"],
            source_locations=["channel:12345"],
        )
        self.assertEqual(signature_one, signature_two)


if __name__ == "__main__":
    unittest.main()
