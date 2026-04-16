from __future__ import annotations

import asyncio
import io
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from starlette.datastructures import UploadFile

from backend.main import get_report_verification_details, verify_uploaded_report
from security.report_signing.hashing import compute_sha256, compute_sha256_string
from security.report_signing.signing import sign_report_payload
from security.report_signing.verification import build_signed_payload_bytes, verify_signature
from services.signed_reports import create_signed_report_record, verify_uploaded_report_bytes
from utils.local_store import LocalMonitoringStore


def make_case(case_id: str = "case_1", org_id: str = "acme.com") -> dict:
    return {
        "id": case_id,
        "case_id": case_id,
        "org_id": org_id,
        "title": "Acme credential leak",
        "severity": "High",
        "category": "Credential Leak",
        "evidence": [{"evidence_id": "ev1", "cleaned_snippet": "credentials leaked"}],
    }


class FakeSignedReportDB:
    def __init__(self) -> None:
        self.records: dict[str, dict] = {}

    def save_signed_report(self, payload: dict) -> dict:
        record = dict(payload)
        self.records[record["report_id"]] = record
        return record

    def get_signed_report(self, report_id: str) -> dict | None:
        record = self.records.get(report_id)
        return dict(record) if record else None

    def update_signed_report(self, report_id: str, updates: dict) -> dict | None:
        if report_id not in self.records:
            return None
        self.records[report_id].update(updates)
        return dict(self.records[report_id])

    def expire_signed_reports(self, **_: dict) -> int:
        return 0


class SignedReportTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            import cryptography  # noqa: F401
        except Exception as exc:  # pragma: no cover
            self.skipTest(f"cryptography is required for signed report tests: {exc}")

    def test_hashing_is_consistent(self) -> None:
        payload = b"citadel-report"
        self.assertEqual(compute_sha256(payload), compute_sha256(payload))
        self.assertEqual(compute_sha256_string("citadel-report"), compute_sha256(payload))

    def test_sign_and_verify_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            private_key_path = Path(temp_dir) / "private_key.pem"
            public_key_path = Path(temp_dir) / "public_key.pem"
            with patch("security.report_signing.signing.REPORT_SIGNING_ENABLED", True), patch(
                "security.report_signing.signing.REPORT_SIGNING_DEV_AUTO_GENERATE", True
            ), patch("security.report_signing.signing.REPORT_PRIVATE_KEY_PATH", private_key_path), patch(
                "security.report_signing.signing.REPORT_PUBLIC_KEY_PATH", public_key_path
            ), patch("security.report_signing.verification.REPORT_PUBLIC_KEY_PATH", public_key_path
            ):
                payload_bytes = build_signed_payload_bytes({"report_id": "report-1", "pdf_sha256": "abc123"})
                result = sign_report_payload(payload_bytes)
                self.assertTrue(result["signed"])
                self.assertTrue(
                    verify_signature(
                        payload_bytes,
                        result["signature_base64"],
                        public_key_path=public_key_path,
                        algorithm=result["algorithm"],
                    )
                )

    def test_signed_report_store_and_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = LocalMonitoringStore(Path(temp_dir) / "monitoring_state.json")
            record = store.save_signed_report(
                {
                    "report_id": "report-expire",
                    "org_id": "acme.com",
                    "status": "generated",
                    "expires_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                }
            )
            self.assertEqual(record["report_id"], "report-expire")
            expired = store.expire_signed_reports()
            self.assertEqual(expired, 1)
            self.assertEqual(store.get_signed_report("report-expire")["status"], "expired")

    def test_verify_uploaded_report_bytes_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            private_key_path = Path(temp_dir) / "private_key.pem"
            public_key_path = Path(temp_dir) / "public_key.pem"
            db = FakeSignedReportDB()
            pdf_bytes = b"%PDF-1.4 citadel signed report"
            with patch("security.report_signing.signing.REPORT_SIGNING_ENABLED", True), patch(
                "security.report_signing.signing.REPORT_SIGNING_DEV_AUTO_GENERATE", True
            ), patch("security.report_signing.signing.REPORT_PRIVATE_KEY_PATH", private_key_path), patch(
                "security.report_signing.signing.REPORT_PUBLIC_KEY_PATH", public_key_path
            ), patch("security.report_signing.verification.REPORT_PUBLIC_KEY_PATH", public_key_path
            ):
                record = create_signed_report_record(
                    db,
                    org_id="acme.com",
                    created_by_user_id="tester",
                    report_type="manual",
                    cases=[make_case()],
                    pdf_bytes=pdf_bytes,
                    pdf_file_path="report.pdf",
                )
                valid = verify_uploaded_report_bytes(db, record["report_id"], pdf_bytes)
                invalid = verify_uploaded_report_bytes(db, record["report_id"], pdf_bytes + b"tampered")
            self.assertEqual(valid["verification_status"], "VALID")
            self.assertEqual(invalid["verification_status"], "INVALID")

    def test_public_verify_routes_return_expected_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            private_key_path = Path(temp_dir) / "private_key.pem"
            public_key_path = Path(temp_dir) / "public_key.pem"
            db = FakeSignedReportDB()
            pdf_bytes = b"%PDF-1.4 verification route test"
            with patch("security.report_signing.signing.REPORT_SIGNING_ENABLED", True), patch(
                "security.report_signing.signing.REPORT_SIGNING_DEV_AUTO_GENERATE", True
            ), patch("security.report_signing.signing.REPORT_PRIVATE_KEY_PATH", private_key_path), patch(
                "security.report_signing.signing.REPORT_PUBLIC_KEY_PATH", public_key_path
            ), patch("security.report_signing.verification.REPORT_PUBLIC_KEY_PATH", public_key_path
            ):
                record = create_signed_report_record(
                    db,
                    org_id="acme.com",
                    created_by_user_id="tester",
                    report_type="executive",
                    cases=[make_case()],
                    pdf_bytes=pdf_bytes,
                    pdf_file_path="report.pdf",
                )
                with patch("backend.main.engine.db", db):
                    metadata = get_report_verification_details(record["report_id"])
                    upload = UploadFile(filename="report.pdf", file=io.BytesIO(pdf_bytes))
                    upload_result = asyncio.run(verify_uploaded_report(record["report_id"], upload))
                    tampered_upload = UploadFile(filename="tampered.pdf", file=io.BytesIO(pdf_bytes + b"x"))
                    tampered_result = asyncio.run(verify_uploaded_report(record["report_id"], tampered_upload))
            self.assertEqual(metadata["verification_status"], "VALID")
            self.assertEqual(upload_result["verification_status"], "VALID")
            self.assertEqual(tampered_result["verification_status"], "INVALID")

    def test_missing_report_raises_not_found(self) -> None:
        with patch("backend.main.engine.db", FakeSignedReportDB()):
            with self.assertRaises(HTTPException) as exc:
                get_report_verification_details("missing-report")
        self.assertEqual(exc.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
