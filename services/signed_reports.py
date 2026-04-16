from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from security.report_signing import (
    build_signed_payload_bytes,
    build_verification_url,
    compute_sha256,
    get_signing_runtime_status,
    mask_value,
    sign_report_payload,
    verify_signature,
)
from utils.config import REPORT_SIGNED_REPORT_EXPIRY_DAYS


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _build_verification_summary(cases: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counter = Counter()
    category_counter = Counter()
    evidence_count = 0
    for case in cases:
        severity_counter[str(case.get("severity") or "Unknown")] += 1
        category_counter[str(case.get("category") or "Unknown")] += 1
        evidence_count += len(case.get("evidence", []) or [])
    return {
        "case_count": len(cases),
        "severity_distribution": dict(severity_counter),
        "category_distribution": dict(category_counter),
        "evidence_summary": {
            "total_evidence_items": evidence_count,
            "summary": f"{len(cases)} case(s) with {evidence_count} evidence item(s).",
        },
    }


def build_signed_report_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "report_id": record.get("report_id"),
        "org_id": record.get("org_id"),
        "created_at": record.get("created_at"),
        "report_type": record.get("report_type"),
        "case_ids": list(record.get("case_ids", [])),
        "pdf_sha256": record.get("pdf_sha256"),
        "evidence_sha256": record.get("evidence_sha256"),
        "public_verification_url": record.get("public_verification_url"),
        "expires_at": record.get("expires_at"),
    }


def build_pdf_verification_details(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "signed": bool(record.get("signature_base64")),
        "report_id": record.get("report_id"),
        "generated_at": record.get("created_at"),
        "pdf_sha256_short": mask_value(record.get("pdf_sha256"), prefix=16, suffix=12),
        "signature_short": mask_value(record.get("signature_base64"), prefix=16, suffix=12),
        "verification_url": record.get("public_verification_url"),
        "signing_algorithm": record.get("signing_algorithm"),
        "public_key_fingerprint_short": mask_value(record.get("public_key_fingerprint"), prefix=16, suffix=12),
        "signature_status": record.get("signature_status"),
        "warning": record.get("signing_warning"),
    }


def prepare_report_verification_details(
    *,
    report_id: str,
    created_at: str,
    public_verification_url: str,
) -> dict[str, Any]:
    signing_status = get_signing_runtime_status()
    return {
        "signed": bool(signing_status.get("available")),
        "report_id": report_id,
        "generated_at": created_at,
        "pdf_sha256_short": None,
        "signature_short": None,
        "verification_url": public_verification_url,
        "signing_algorithm": signing_status.get("algorithm"),
        "public_key_fingerprint_short": mask_value(signing_status.get("public_key_fingerprint"), prefix=16, suffix=12),
        "signature_status": "pending" if signing_status.get("enabled") else "unsigned",
        "warning": signing_status.get("warning"),
    }


def create_signed_report_record(
    db: Any,
    *,
    org_id: str,
    created_by_user_id: str,
    report_type: str,
    cases: list[dict[str, Any]],
    pdf_bytes: bytes,
    pdf_file_path: str | Path,
    evidence_bytes: bytes | None = None,
    audit_reference_id: str | None = None,
    status: str = "generated",
    report_id: str | None = None,
    created_at: str | None = None,
    public_verification_url: str | None = None,
) -> dict[str, Any]:
    created_at_dt = _parse_iso(created_at) if created_at else _now()
    resolved_report_id = report_id or str(uuid.uuid4())
    resolved_verification_url = public_verification_url or build_verification_url(resolved_report_id)
    record = {
        "report_id": resolved_report_id,
        "org_id": org_id,
        "created_by_user_id": created_by_user_id,
        "created_at": created_at_dt.isoformat(),
        "report_type": report_type,
        "case_ids": [case.get("id") or case.get("case_id") for case in cases if case.get("id") or case.get("case_id")],
        "pdf_file_path": str(pdf_file_path),
        "pdf_sha256": compute_sha256(pdf_bytes),
        "evidence_sha256": compute_sha256(evidence_bytes) if evidence_bytes else None,
        "signature_base64": None,
        "signing_algorithm": None,
        "public_verification_url": resolved_verification_url,
        "status": status,
        "expires_at": (created_at_dt + timedelta(days=REPORT_SIGNED_REPORT_EXPIRY_DAYS)).isoformat(),
        "audit_reference_id": audit_reference_id,
        "public_key_fingerprint": None,
        "signature_status": "unsigned",
        "signing_warning": None,
        "verification_summary": _build_verification_summary(cases),
    }
    signed_payload = build_signed_report_payload(record)
    sign_result = sign_report_payload(build_signed_payload_bytes(signed_payload))
    record["signature_base64"] = sign_result.get("signature_base64")
    record["signing_algorithm"] = sign_result.get("algorithm")
    record["public_key_fingerprint"] = sign_result.get("public_key_fingerprint")
    record["signature_status"] = "signed" if sign_result.get("signed") else "unsigned"
    record["signing_warning"] = sign_result.get("warning")
    record["signed_payload"] = signed_payload
    return db.save_signed_report(record)


def resolve_report_verification_status(record: dict[str, Any]) -> str:
    expires_at = _parse_iso(record.get("expires_at"))
    if expires_at is not None and expires_at <= _now():
        return "EXPIRED"
    if record.get("signature_base64"):
        return "VALID"
    return "INVALID"


def build_public_verification_response(record: dict[str, Any]) -> dict[str, Any]:
    summary = dict(record.get("verification_summary") or {})
    return {
        "report_id": record.get("report_id"),
        "org_name": record.get("org_id"),
        "generated_at": record.get("created_at"),
        "case_count": summary.get("case_count", len(record.get("case_ids", []))),
        "verification_status": resolve_report_verification_status(record),
        "pdf_sha256": record.get("pdf_sha256"),
        "signature_base64_masked": mask_value(record.get("signature_base64"), prefix=16, suffix=12),
        "public_key_fingerprint": record.get("public_key_fingerprint"),
        "evidence_summary": summary.get("evidence_summary", {}),
        "severity_distribution": summary.get("severity_distribution", {}),
        "category_distribution": summary.get("category_distribution", {}),
        "expires_at": record.get("expires_at"),
        "public_verification_url": record.get("public_verification_url"),
        "report_type": record.get("report_type"),
        "signature_status": record.get("signature_status"),
    }


def verify_uploaded_report_bytes(db: Any, report_id: str, pdf_bytes: bytes) -> dict[str, Any]:
    record = db.get_signed_report(report_id)
    if record is None:
        raise KeyError(report_id)
    uploaded_pdf_sha256 = compute_sha256(pdf_bytes)
    hash_match = uploaded_pdf_sha256 == record.get("pdf_sha256")
    payload = dict(record.get("signed_payload") or build_signed_report_payload(record))
    signature_valid = False
    if record.get("signature_base64"):
        try:
            signature_valid = verify_signature(
                build_signed_payload_bytes(payload),
                record.get("signature_base64"),
                algorithm=record.get("signing_algorithm"),
            )
        except Exception:
            signature_valid = False
    verification_status = "VALID" if hash_match and signature_valid else "INVALID"
    expires_at = _parse_iso(record.get("expires_at"))
    if expires_at is not None and expires_at <= _now():
        verification_status = "EXPIRED"
    return {
        "report_id": report_id,
        "verification_status": verification_status,
        "uploaded_pdf_sha256": uploaded_pdf_sha256,
        "stored_pdf_sha256": record.get("pdf_sha256"),
        "hash_match": hash_match,
        "signature_valid": signature_valid,
        "expires_at": record.get("expires_at"),
        "message": (
            "Uploaded report matches the stored signed record."
            if verification_status == "VALID"
            else "Uploaded report does not match the stored signed record."
        ),
    }
