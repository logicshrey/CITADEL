from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_text(value: str) -> str:
    return _hash_bytes(value.encode("utf-8"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_preview_audit(
    db: Any,
    *,
    org_id: str,
    user_id: str,
    recipients: list[str],
    cc: list[str],
    case_ids: list[str],
    preview_id: str,
    complaint_body: str,
    pdf_bytes: bytes,
) -> dict[str, Any]:
    return db.record_audit_event(
        {
            "event_type": "cyber_cell_report_preview",
            "org_id": org_id,
            "user_id": user_id,
            "recipients": recipients,
            "cc": cc,
            "case_ids": case_ids,
            "generated_timestamp": _now_iso(),
            "status": "previewed",
            "preview_id": preview_id,
            "pdf_hash": _hash_bytes(pdf_bytes),
            "complaint_hash": _hash_text(complaint_body),
        }
    )


def record_send_audit(
    db: Any,
    *,
    org_id: str,
    user_id: str,
    recipients: list[str],
    cc: list[str],
    case_ids: list[str],
    preview_id: str,
    complaint_body: str,
    pdf_bytes: bytes,
    status: str,
    error_message: str | None = None,
) -> dict[str, Any]:
    payload = {
        "event_type": "cyber_cell_report_sent" if status == "success" else "cyber_cell_report_failed",
        "org_id": org_id,
        "user_id": user_id,
        "recipients": recipients,
        "cc": cc,
        "case_ids": case_ids,
        "generated_timestamp": _now_iso(),
        "send_timestamp": _now_iso(),
        "status": status,
        "error_message": error_message,
        "preview_id": preview_id,
        "pdf_hash": _hash_bytes(pdf_bytes),
        "complaint_hash": _hash_text(complaint_body),
    }
    return db.record_audit_event(payload)


def record_rate_limit_audit(
    db: Any,
    *,
    org_id: str,
    user_id: str,
    recipients: list[str],
    cc: list[str],
    case_ids: list[str],
    preview_id: str,
    error_message: str,
) -> dict[str, Any]:
    return db.record_audit_event(
        {
            "event_type": "cyber_cell_report_rate_limited",
            "org_id": org_id,
            "user_id": user_id,
            "recipients": recipients,
            "cc": cc,
            "case_ids": case_ids,
            "generated_timestamp": _now_iso(),
            "send_timestamp": _now_iso(),
            "status": "rejected",
            "error_message": error_message,
            "preview_id": preview_id,
        }
    )
