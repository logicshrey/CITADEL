from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from reportlab.platypus import Paragraph, Table

from utils.intel_enrichment import correlate_alerts
from utils.reporting import _build_report_story, filter_cases, generate_pdf_report


def make_case(
    *,
    org_id: str = "acme.com",
    title: str = "Acme exposure detected via Dehashed",
    summary: str = "A credential leak affecting Acme requires review.",
    domains: list[str] | None = None,
    emails: list[str] | None = None,
) -> dict[str, object]:
    return {
        "id": f"case_{org_id}_{title[:10].replace(' ', '_')}",
        "case_id": f"case_{org_id}_{title[:10].replace(' ', '_')}",
        "org_id": org_id,
        "organization": org_id,
        "title": title,
        "category": "Credential Leak",
        "severity": "High",
        "confidence_score": 88,
        "risk_score": 83,
        "affected_assets": {
            "domains": domains or [org_id],
            "emails": emails or [f"admin@{org_id}"],
            "ips": [],
            "usernames": [f"{org_id.split('.')[0]}_admin"],
            "tokens": [],
            "wallets": [],
        },
        "sources": [{"source": "Dehashed", "source_locations": [f"dataset:{org_id}-breach"]}],
        "evidence": [
            {
                "evidence_id": "e1",
                "source_platform": "Dehashed",
                "cleaned_snippet": f"Credential dump includes admin@{org_id} and password hashes.",
                "timestamp": "2026-04-15T00:00:00+00:00",
            }
        ],
        "matched_indicators": [org_id, f"admin@{org_id}"],
        "why_this_was_flagged": ["Direct monitored domain or indicator match."],
        "recommended_actions": ["Reset credentials and review MFA."],
        "exposure_summary": summary,
        "technical_summary": f"Dehashed-style breach evidence exposed an {org_id} administrator account.",
        "created_at": "2026-04-15T00:00:00+00:00",
        "updated_at": "2026-04-15T00:00:00+00:00",
        "first_seen": "2026-04-15T00:00:00+00:00",
        "last_seen": "2026-04-15T00:00:00+00:00",
    }


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
        case = make_case()

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

    def test_report_story_uses_requested_org_on_cover_page(self) -> None:
        story = _build_report_story(cases=[make_case()], start_date=None, end_date=None, org_id="acme.com")
        cover_line = next(
            block.getPlainText()
            for block in story
            if isinstance(block, Paragraph) and block.getPlainText().startswith("Organization:")
        )
        self.assertEqual(cover_line, "Organization: acme.com")

    def test_multi_org_story_labels_cover_as_multiple_organizations(self) -> None:
        story = _build_report_story(
            cases=[make_case(org_id="acme.com"), make_case(org_id="globex.com")],
            start_date=None,
            end_date=None,
            org_id=None,
        )
        cover_line = next(
            block.getPlainText()
            for block in story
            if isinstance(block, Paragraph) and block.getPlainText().startswith("Organization:")
        )
        self.assertEqual(cover_line, "Organization: Multiple organizations (2)")

    def test_filter_cases_excludes_legacy_noise_cases(self) -> None:
        noisy_case = make_case(
            org_id="claude",
            title="Apache Server Status",
            summary="Apache server status page shows server uptime and worker details.",
            domains=[],
            emails=[],
        )
        noisy_case["affected_assets"] = {
            "domains": [],
            "emails": [],
            "ips": [],
            "usernames": ["claude"],
            "tokens": [],
            "wallets": [],
        }
        filtered = filter_cases([noisy_case, make_case(org_id="acme.com")])
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["org_id"], "acme.com")

    def test_filter_cases_excludes_suppressed_cases(self) -> None:
        weak_case = make_case(org_id="sbi.co.in")
        weak_case["suppressed_noise"] = True
        weak_case["suppression_reasons"] = ["No verified organization-owned assets were retained."]
        filtered = filter_cases([weak_case, make_case(org_id="acme.com")])
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["org_id"], "acme.com")

    def test_case_summary_table_uses_wrapped_cells_and_fixed_widths(self) -> None:
        long_case = make_case(
            title="Acme exposure detected in a very long dataset title that should wrap inside the summary table",
            summary="A very long summary exists so the generated report must wrap table cells rather than clipping content.",
            domains=["portal.acme.com", "identity.acme.com", "partner.acme.com"],
            emails=["security.operations.team@acme.com", "incident.response.team@acme.com"],
        )
        story = _build_report_story(cases=[long_case], start_date=None, end_date=None, org_id="acme.com")
        summary_table = next(
            block
            for block in story
            if isinstance(block, Table)
            and isinstance(block._cellvalues[0][0], Paragraph)
            and block._cellvalues[0][0].getPlainText() == "Case"
        )
        self.assertEqual(len(summary_table._colWidths), 5)
        self.assertTrue(all(width > 0 for width in summary_table._colWidths))
        self.assertIsInstance(summary_table._cellvalues[1][0], Paragraph)

    def test_report_story_includes_verification_and_sensitive_sections(self) -> None:
        case = make_case()
        case["verification_badge"] = "VERIFIED"
        case["verification_score"] = 93
        case["verification_reasons"] = ["High-confidence credentials and verified organization assets support this case."]
        case["sensitive_data_types"] = ["Credential Pair", "PAN"]
        case["sensitive_findings"] = [
            {"finding_type": "Credential Pair", "masked_value": "Sup3********ret!", "source_evidence_id": "e1", "source_index": 0},
            {"finding_type": "PAN", "masked_value": "ABCD***34F", "source_evidence_id": "e1", "source_index": 0},
        ]
        case["sensitive_risk_score"] = 24

        story = _build_report_story(cases=[case], start_date=None, end_date=None, org_id="acme.com")
        paragraph_text = [block.getPlainText() for block in story if isinstance(block, Paragraph)]

        self.assertIn("Sensitive Data Detected", paragraph_text)
        self.assertIn("Verification Status", paragraph_text)

    def test_report_story_includes_authenticity_section_when_verification_details_exist(self) -> None:
        story = _build_report_story(
            cases=[make_case()],
            start_date=None,
            end_date=None,
            org_id="acme.com",
            verification_details={
                "signed": True,
                "report_id": "report-123",
                "generated_at": "2026-04-16T00:00:00+00:00",
                "pdf_sha256_short": "abcd1234",
                "signature_short": "sig1234",
                "verification_url": "http://127.0.0.1:8001/verify/report-123",
                "signing_algorithm": "Ed25519",
                "public_key_fingerprint_short": "fingerprint1234",
            },
        )
        paragraph_text = [block.getPlainText() for block in story if isinstance(block, Paragraph)]
        self.assertIn("Report Authenticity Verification", paragraph_text)


if __name__ == "__main__":
    unittest.main()
