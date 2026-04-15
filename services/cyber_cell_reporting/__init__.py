from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from services.cyber_cell_reporting.audit_logger import (
    record_preview_audit,
    record_rate_limit_audit,
    record_send_audit,
)
from services.cyber_cell_reporting.complaint_formatter import build_complaint_payload
from services.cyber_cell_reporting.email_sender import (
    CyberCellEmailError,
    build_recipient_lists,
    reporting_delivery_status,
    send_cyber_cell_email,
    validate_email_list,
)
from services.cyber_cell_reporting.eligibility_validator import validate_case_selection
from services.cyber_cell_reporting.preview_store import PreviewStore, build_request_fingerprint
from utils.config import CYBER_CELL_DAILY_SEND_LIMIT
from utils.reporting import filter_cases, generate_pdf_report


class CyberCellValidationError(Exception):
    def __init__(self, message: str, *, reasons: list[str] | None = None, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.reasons = reasons or [message]
        self.status_code = status_code


class DateRangeFilter(BaseModel):
    start_date: str | None = None
    end_date: str | None = None


class ContactPersonDetails(BaseModel):
    name: str = Field(..., min_length=2)
    designation: str = Field(..., min_length=2)
    email: str = Field(..., min_length=5)
    phone: str = Field(..., min_length=5)


class OrganizationDetails(BaseModel):
    organization_name: str | None = None
    industry: str | None = None
    registered_address: str | None = None


class CyberCellReportRequest(BaseModel):
    case_ids: list[str] = Field(default_factory=list)
    org_id: str | None = None
    date_range: DateRangeFilter | None = None
    severity: list[str] = Field(default_factory=list)
    recipients: list[str] = Field(default_factory=list, min_length=1)
    cc: list[str] = Field(default_factory=list)
    authority_location: str | None = None
    contact_person_details: ContactPersonDetails
    organization_details: OrganizationDetails | None = None
    include_json_bundle: bool = False
    preview_id: str | None = None
    confirmation_flag: bool = False


preview_store = PreviewStore()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_user_id(user_id: str | None, payload: CyberCellReportRequest) -> str:
    candidate = str(user_id or "").strip()
    if candidate:
        return candidate
    contact_email = str(payload.contact_person_details.email or "").strip().lower()
    return contact_email or "anonymous"


def _organization_name(payload: CyberCellReportRequest, organization: str) -> str:
    override = payload.organization_details.organization_name if payload.organization_details else None
    return str(override or organization or "Unknown Organization").strip()


def _selection_scope(payload: CyberCellReportRequest) -> dict[str, Any]:
    return {
        "case_ids": sorted({str(case_id or "").strip() for case_id in payload.case_ids if str(case_id or "").strip()}),
        "org_id": str(payload.org_id or "").strip().lower(),
        "date_range": payload.date_range.model_dump() if payload.date_range else {},
        "severity": sorted({str(value or "").strip() for value in payload.severity if str(value or "").strip()}),
        "recipients": sorted({str(value or "").strip().lower() for value in payload.recipients if str(value or "").strip()}),
        "cc": sorted({str(value or "").strip().lower() for value in payload.cc if str(value or "").strip()}),
        "authority_location": str(payload.authority_location or "").strip(),
        "contact_person_details": payload.contact_person_details.model_dump(),
        "organization_details": payload.organization_details.model_dump() if payload.organization_details else {},
        "include_json_bundle": bool(payload.include_json_bundle),
    }


def _resolve_cases(db: Any, payload: CyberCellReportRequest) -> list[dict[str, Any]]:
    if payload.case_ids:
        cases = []
        for case_id in payload.case_ids:
            case = db.get_case(case_id)
            if case is not None:
                cases.append(case)
        if not cases:
            raise CyberCellValidationError("No valid cases were found for the provided case IDs.")
    else:
        if not payload.org_id and not payload.date_range and not payload.severity:
            raise CyberCellValidationError("Provide case_ids or an org/date/severity filter to prepare a cyber cell report.")
        cases = db.list_cases(limit=5000)

    return filter_cases(
        cases,
        start_date=payload.date_range.start_date if payload.date_range else None,
        end_date=payload.date_range.end_date if payload.date_range else None,
        severity=payload.severity,
        category=[],
        org_id=payload.org_id,
    )


def _selected_case_preview(case: dict[str, Any], rejection_reasons: list[str]) -> dict[str, Any]:
    return {
        "case_id": case.get("id") or case.get("case_id"),
        "title": case.get("title"),
        "verification_status": "YES" if bool(case.get("verified_org_match")) or str(case.get("verification_status") or "").lower() == "yes" else "NO",
        "severity": case.get("severity"),
        "confidence_score": int(case.get("confidence_score", 0) or 0),
        "eligible": not rejection_reasons,
        "rejection_reasons": rejection_reasons,
    }


def _generate_attachments(
    cases: list[dict[str, Any]],
    *,
    payload: CyberCellReportRequest,
    organization: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    complaint = build_complaint_payload(
        cases,
        organization_name=_organization_name(payload, organization),
        contact_person_details=payload.contact_person_details.model_dump(),
        organization_details=payload.organization_details.model_dump() if payload.organization_details else {},
        authority_location=payload.authority_location,
    )
    pdf_path = generate_pdf_report(
        cases,
        start_date=payload.date_range.start_date if payload.date_range else None,
        end_date=payload.date_range.end_date if payload.date_range else None,
        severity=payload.severity,
        category=[],
        org_id=organization,
    )
    pdf_bytes = Path(pdf_path).read_bytes()
    attachments = [
        {
            "name": "citadel_exposure_report.pdf",
            "content": pdf_bytes,
            "mime_type": "application/pdf",
            "size_bytes": len(pdf_bytes),
        },
        {
            "name": "citadel_complaint_summary.txt",
            "content": complaint["complaint_body"].encode("utf-8"),
            "mime_type": "text/plain",
            "size_bytes": len(complaint["complaint_body"].encode("utf-8")),
        },
    ]
    if payload.include_json_bundle:
        bundle = {
            "generated_at": _now_iso(),
            "org_id": organization,
            "case_ids": [case.get("id") or case.get("case_id") for case in cases],
            "cases": cases,
        }
        bundle_bytes = json.dumps(bundle, indent=2).encode("utf-8")
        attachments.append(
            {
                "name": "citadel_evidence_bundle.json",
                "content": bundle_bytes,
                "mime_type": "application/json",
                "size_bytes": len(bundle_bytes),
            }
        )
    return attachments, complaint


def _ensure_send_rate_limit(db: Any, org_id: str) -> None:
    start_of_day = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    send_count = db.count_audit_events(
        event_type="cyber_cell_report_sent",
        org_id=org_id,
        status="success",
        since=start_of_day,
    )
    if send_count >= CYBER_CELL_DAILY_SEND_LIMIT:
        raise CyberCellValidationError(
            f"Daily cyber cell reporting limit reached for {org_id}. Maximum {CYBER_CELL_DAILY_SEND_LIMIT} sends per day are allowed.",
            status_code=429,
        )


def build_preview(db: Any, payload: CyberCellReportRequest, *, user_id: str | None = None) -> dict[str, Any]:
    resolved_cases = _resolve_cases(db, payload)
    recipients, cc = build_recipient_lists(payload.recipients, payload.cc)
    validate_email_list([payload.contact_person_details.email], field_name="contact")
    validation = validate_case_selection(resolved_cases, requested_org_id=payload.org_id)
    selected_case_map = {item["case_id"]: item["reasons"] for item in validation["rejected_case_ids"]}
    selected_cases = [
        _selected_case_preview(case, selected_case_map.get(case.get("id") or case.get("case_id"), []))
        for case in resolved_cases
    ]

    attachments_preview: list[dict[str, Any]] = []
    subject = ""
    complaint_body = ""
    preview_metadata: dict[str, Any] | None = None
    if validation["eligible_cases"]:
        attachments, complaint = _generate_attachments(validation["eligible_cases"], payload=payload, organization=validation["organization"])
        fingerprint = build_request_fingerprint(_selection_scope(payload))
        preview_metadata = preview_store.create(
            fingerprint=fingerprint,
            payload={
                "org_id": validation["organization"],
                "case_ids": validation["eligible_case_ids"],
                "recipients": recipients,
                "cc": cc,
            },
        )
        attachments_preview = [{"name": item["name"], "size_bytes": item["size_bytes"]} for item in attachments]
        subject = complaint["subject"]
        complaint_body = complaint["complaint_body"]
        record_preview_audit(
            db,
            org_id=validation["organization"],
            user_id=_normalize_user_id(user_id, payload),
            recipients=recipients,
            cc=cc,
            case_ids=validation["eligible_case_ids"],
            preview_id=preview_metadata["preview_id"],
            complaint_body=complaint_body,
            pdf_bytes=attachments[0]["content"],
        )

    return {
        "preview_id": preview_metadata["preview_id"] if preview_metadata else None,
        "preview_expires_at": preview_metadata["expires_at"] if preview_metadata else None,
        "subject": subject,
        "complaint_body": complaint_body,
        "attachments_preview": attachments_preview,
        "selected_cases": selected_cases,
        "eligible_cases_count": len(validation["eligible_case_ids"]),
        "rejected_cases": validation["rejected_case_ids"],
        "rejection_reasons": validation["rejection_reasons"],
        "report_summary": validation["report_summary"],
    }


def send_report(db: Any, payload: CyberCellReportRequest, *, user_id: str | None = None) -> dict[str, Any]:
    normalized_user_id = _normalize_user_id(user_id, payload)
    recipients, cc = build_recipient_lists(payload.recipients, payload.cc)
    validate_email_list([payload.contact_person_details.email], field_name="contact")
    resolved_cases = _resolve_cases(db, payload)
    validation = validate_case_selection(resolved_cases, requested_org_id=payload.org_id)
    preview_id = str(payload.preview_id or "").strip()
    if not payload.confirmation_flag:
        raise CyberCellValidationError("Confirmation flag must be true before sending the cyber cell report.")
    if not preview_id:
        raise CyberCellValidationError("A valid preview_id is required before sending the cyber cell report.")
    if not validation["eligible_cases"]:
        raise CyberCellValidationError("No eligible cases are available for cyber cell reporting.", reasons=validation["rejection_reasons"])
    if validation["rejected_case_ids"]:
        reasons = []
        for rejected in validation["rejected_case_ids"]:
            reasons.extend(rejected["reasons"])
        raise CyberCellValidationError(
            "All selected cases must meet cyber cell reporting eligibility before sending.",
            reasons=list(dict.fromkeys(reasons)),
        )

    fingerprint = build_request_fingerprint(_selection_scope(payload))
    try:
        preview_store.validate(preview_id=preview_id, fingerprint=fingerprint)
    except ValueError as exc:
        raise CyberCellValidationError(str(exc))

    try:
        _ensure_send_rate_limit(db, validation["organization"])
    except CyberCellValidationError as exc:
        reject_rate_limited_send(
            db,
            payload=payload,
            org_id=validation["organization"],
            user_id=normalized_user_id,
            error_message=exc.message,
        )
        raise
    attachments, complaint = _generate_attachments(validation["eligible_cases"], payload=payload, organization=validation["organization"])

    try:
        delivery = send_cyber_cell_email(
            subject=complaint["subject"],
            body_text=complaint["complaint_body"],
            recipients=recipients,
            cc=cc,
            attachments=attachments,
        )
    except (CyberCellEmailError, CyberCellValidationError) as exc:
        record_send_audit(
            db,
            org_id=validation["organization"],
            user_id=normalized_user_id,
            recipients=recipients,
            cc=cc,
            case_ids=validation["eligible_case_ids"],
            preview_id=preview_id,
            complaint_body=complaint["complaint_body"],
            pdf_bytes=attachments[0]["content"] if attachments else b"",
            status="failed",
            error_message=str(exc),
        )
        raise

    audit = record_send_audit(
        db,
        org_id=validation["organization"],
        user_id=normalized_user_id,
        recipients=recipients,
        cc=cc,
        case_ids=validation["eligible_case_ids"],
        preview_id=preview_id,
        complaint_body=complaint["complaint_body"],
        pdf_bytes=attachments[0]["content"] if attachments else b"",
        status="success",
    )
    return {
        "status": "sent",
        "audit_id": audit.get("id"),
        "sent_to": delivery["sent_to"],
        "delivery_mode": delivery.get("delivery_mode", "mock" if delivery.get("mocked") else "live"),
        "attachment_names": delivery["attachment_names"],
        "timestamp": audit.get("send_timestamp") or audit.get("timestamp"),
    }


def reject_rate_limited_send(
    db: Any,
    *,
    payload: CyberCellReportRequest,
    org_id: str,
    user_id: str | None,
    error_message: str,
) -> None:
    record_rate_limit_audit(
        db,
        org_id=org_id,
        user_id=_normalize_user_id(user_id, payload),
        recipients=[str(value or "").strip().lower() for value in payload.recipients],
        cc=[str(value or "").strip().lower() for value in payload.cc],
        case_ids=[str(value or "").strip() for value in payload.case_ids],
        preview_id=str(payload.preview_id or "").strip(),
        error_message=error_message,
    )


def get_reporting_status() -> dict[str, Any]:
    return reporting_delivery_status()
