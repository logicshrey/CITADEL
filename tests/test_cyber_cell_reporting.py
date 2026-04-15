from __future__ import annotations

import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from backend.main import preview_cyber_cell_report, send_cyber_cell_report
from services.cyber_cell_reporting import CyberCellReportRequest
from services.cyber_cell_reporting import preview_store
from services.cyber_cell_reporting.eligibility_validator import validate_case_selection


def build_case(
    *,
    case_id: str = "case_eligible",
    org_id: str = "acme.com",
    verified_org_match: bool = True,
    confidence_score: int = 92,
    severity: str = "High",
    evidence: list[dict] | None = None,
    domains: list[str] | None = None,
    emails: list[str] | None = None,
) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "id": case_id,
        "case_id": case_id,
        "org_id": org_id,
        "organization": org_id,
        "title": f"Exposure case for {org_id}",
        "summary": "Verified organization data exposure observed in external monitoring.",
        "severity": severity,
        "priority": "HIGH",
        "confidence_score": confidence_score,
        "verified_org_match": verified_org_match,
        "verification_status": "YES" if verified_org_match else "NO",
        "affected_assets": {
            "domains": domains or [org_id],
            "emails": emails or [f"security@{org_id}"],
            "ips": [],
            "usernames": [],
            "tokens": [],
            "wallets": [],
        },
        "evidence": evidence
        if evidence is not None
        else [
            {
                "evidence_id": f"ev_{case_id}",
                "source": "Dehashed",
                "source_platform": "Dehashed",
                "cleaned_snippet": f"Credential pair found for security@{org_id}",
                "timestamp": timestamp,
                "matched_entities": [f"security@{org_id}", org_id],
            }
        ],
        "sources": [{"source": "Dehashed", "source_locations": ["https://example.test/post/1"], "last_seen": timestamp}],
        "first_seen": timestamp,
        "last_seen": timestamp,
        "estimated_total_records": 25,
        "estimated_total_records_label": "25 records",
        "category": "Credential Leak",
        "suppressed_noise": False,
    }


class FakeDB:
    def __init__(self, cases: list[dict], *, send_count: int = 0) -> None:
        self.cases = {case["id"]: case for case in cases}
        self.audit_events: list[dict] = []
        self.send_count = send_count

    def get_case(self, case_id: str) -> dict | None:
        return self.cases.get(case_id)

    def list_cases(self, limit: int = 5000, **_: dict) -> list[dict]:
        return list(self.cases.values())[:limit]

    def record_audit_event(self, payload: dict) -> dict:
        event = dict(payload)
        event.setdefault("id", f"audit_{len(self.audit_events) + 1}")
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        self.audit_events.append(event)
        return event

    def count_audit_events(self, **_: dict) -> int:
        return self.send_count


class CyberCellReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        preview_store._previews.clear()
        self.request = SimpleNamespace(headers={})

    def test_validator_rejects_unverified_cases(self) -> None:
        case = build_case(verified_org_match=False)
        result = validate_case_selection([case], requested_org_id=case["org_id"])
        self.assertFalse(result["is_eligible"])
        self.assertIn("Case is not marked as a verified organization match.", result["rejected_case_ids"][0]["reasons"])

    def test_validator_rejects_low_confidence_cases(self) -> None:
        case = build_case(confidence_score=65)
        result = validate_case_selection([case], requested_org_id=case["org_id"])
        self.assertFalse(result["is_eligible"])
        self.assertIn("Confidence score is below 80.", result["rejected_case_ids"][0]["reasons"])

    def test_preview_endpoint_returns_complaint_formatting(self) -> None:
        fake_db = FakeDB([build_case()])
        with patch("backend.main.engine.db", fake_db):
            response = preview_cyber_cell_report(
                CyberCellReportRequest(
                    case_ids=["case_eligible"],
                    recipients=["cybercell@example.gov.in"],
                    contact_person_details={
                        "name": "Amit Sharma",
                        "designation": "CISO",
                        "email": "amit.sharma@acme.com",
                        "phone": "+91-9000000000",
                    },
                    organization_details={"organization_name": "ACME Bank", "industry": "Banking"},
                ),
                self.request,
            )

        self.assertIn("URGENT: Reporting Suspected Data Exposure / Credential Leak - ACME Bank", response["subject"])
        self.assertIn("Cyber Crime Cell / Cyber Police Station", response["complaint_body"])
        self.assertTrue(response["preview_id"])
        self.assertEqual(response["eligible_cases_count"], 1)

    def test_send_endpoint_creates_audit_log(self) -> None:
        fake_db = FakeDB([build_case()])
        with patch("backend.main.engine.db", fake_db), patch("backend.main.event_bus.publish", return_value=None), patch(
            "services.cyber_cell_reporting.email_sender.REPORTING_ENABLED", True
        ), patch("services.cyber_cell_reporting.email_sender.REPORTING_MOCK_MODE", True), patch(
            "services.cyber_cell_reporting.email_sender.SMTP_FROM_EMAIL", "alerts@citadel.test"
        ):
            preview_response = preview_cyber_cell_report(
                CyberCellReportRequest(
                    case_ids=["case_eligible"],
                    recipients=["cybercell@example.gov.in"],
                    contact_person_details={
                        "name": "Amit Sharma",
                        "designation": "CISO",
                        "email": "amit.sharma@acme.com",
                        "phone": "+91-9000000000",
                    },
                    organization_details={"organization_name": "ACME Bank"},
                ),
                self.request,
            )
            send_response = send_cyber_cell_report(
                CyberCellReportRequest(
                    case_ids=["case_eligible"],
                    recipients=["cybercell@example.gov.in"],
                    preview_id=preview_response["preview_id"],
                    confirmation_flag=True,
                    contact_person_details={
                        "name": "Amit Sharma",
                        "designation": "CISO",
                        "email": "amit.sharma@acme.com",
                        "phone": "+91-9000000000",
                    },
                    organization_details={"organization_name": "ACME Bank"},
                ),
                self.request,
            )

        self.assertEqual(send_response["status"], "sent")
        self.assertTrue(any(event["event_type"] == "cyber_cell_report_sent" for event in fake_db.audit_events))

    def test_rate_limit_enforcement_works(self) -> None:
        fake_db = FakeDB([build_case()], send_count=3)
        with patch("backend.main.engine.db", fake_db), patch("services.cyber_cell_reporting.email_sender.REPORTING_ENABLED", True), patch(
            "services.cyber_cell_reporting.email_sender.REPORTING_MOCK_MODE", True
        ), patch("services.cyber_cell_reporting.email_sender.SMTP_FROM_EMAIL", "alerts@citadel.test"):
            preview_response = preview_cyber_cell_report(
                CyberCellReportRequest(
                    case_ids=["case_eligible"],
                    recipients=["cybercell@example.gov.in"],
                    contact_person_details={
                        "name": "Amit Sharma",
                        "designation": "CISO",
                        "email": "amit.sharma@acme.com",
                        "phone": "+91-9000000000",
                    },
                    organization_details={"organization_name": "ACME Bank"},
                ),
                self.request,
            )
            with self.assertRaises(HTTPException) as exc:
                send_cyber_cell_report(
                    CyberCellReportRequest(
                        case_ids=["case_eligible"],
                        recipients=["cybercell@example.gov.in"],
                        preview_id=preview_response["preview_id"],
                        confirmation_flag=True,
                        contact_person_details={
                            "name": "Amit Sharma",
                            "designation": "CISO",
                            "email": "amit.sharma@acme.com",
                            "phone": "+91-9000000000",
                        },
                        organization_details={"organization_name": "ACME Bank"},
                    ),
                    self.request,
                )

        self.assertEqual(exc.exception.status_code, 429)
        self.assertIn("Daily cyber cell reporting limit reached", exc.exception.detail["message"])

    def test_email_format_validation_works(self) -> None:
        fake_db = FakeDB([build_case()])
        with patch("backend.main.engine.db", fake_db):
            with self.assertRaises(HTTPException) as exc:
                preview_cyber_cell_report(
                    CyberCellReportRequest(
                        case_ids=["case_eligible"],
                        recipients=["not-an-email"],
                        contact_person_details={
                            "name": "Amit Sharma",
                            "designation": "CISO",
                            "email": "amit.sharma@acme.com",
                            "phone": "+91-9000000000",
                        },
                        organization_details={"organization_name": "ACME Bank"},
                    ),
                    self.request,
                )

        self.assertEqual(exc.exception.status_code, 400)
        self.assertIn("Invalid recipient email address", exc.exception.detail["message"])


if __name__ == "__main__":
    unittest.main()
