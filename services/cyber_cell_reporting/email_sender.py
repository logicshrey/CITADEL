from __future__ import annotations

import smtplib
from email.message import EmailMessage
from typing import Any

from intelligence.validators import validate_entity
from utils.config import (
    REPORTING_ENABLED,
    REPORTING_MOCK_MODE,
    SMTP_DEFAULT_CC,
    SMTP_FROM_EMAIL,
    SMTP_HOST,
    SMTP_PASS,
    SMTP_PORT,
    SMTP_REPLY_TO,
    SMTP_TIMEOUT_SECONDS,
    SMTP_USE_SSL,
    SMTP_USE_STARTTLS,
    SMTP_USER,
)


class CyberCellEmailError(RuntimeError):
    pass


def reporting_delivery_status() -> dict[str, Any]:
    reasons: list[str] = []
    configured = bool(SMTP_HOST and (SMTP_FROM_EMAIL or SMTP_USER))
    if not REPORTING_ENABLED:
        reasons.append("Cyber cell reporting is disabled in server configuration.")
    if not SMTP_HOST:
        reasons.append("SMTP host is not configured.")
    if not (SMTP_FROM_EMAIL or SMTP_USER):
        reasons.append("SMTP sender address is not configured.")

    mode = "disabled"
    if REPORTING_MOCK_MODE:
        mode = "mock"
    elif REPORTING_ENABLED and configured:
        mode = "live"

    return {
        "enabled": REPORTING_ENABLED,
        "mock_mode": REPORTING_MOCK_MODE,
        "mode": mode,
        "smtp_ready": configured,
        "live_delivery_ready": REPORTING_ENABLED and configured and not REPORTING_MOCK_MODE,
        "host_configured": bool(SMTP_HOST),
        "sender_configured": bool(SMTP_FROM_EMAIL or SMTP_USER),
        "transport": "smtps" if SMTP_USE_SSL else "smtp+starttls" if SMTP_USE_STARTTLS else "smtp",
        "reasons": reasons,
    }


def _normalize_email_list(values: list[str] | None) -> list[str]:
    seen: set[str] = set()
    normalized: list[str] = []
    for value in values or []:
        candidate = str(value or "").strip().lower()
        if not candidate:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return normalized


def validate_email_list(values: list[str] | None, *, field_name: str) -> list[str]:
    normalized = _normalize_email_list(values)
    invalid = [value for value in normalized if validate_entity(value, "EMAIL") is None]
    if invalid:
        raise CyberCellEmailError(f"Invalid {field_name} email address(es): {', '.join(invalid)}.")
    return normalized


def build_recipient_lists(recipients: list[str], cc: list[str] | None = None) -> tuple[list[str], list[str]]:
    cleaned_recipients = validate_email_list(recipients, field_name="recipient")
    if not cleaned_recipients:
        raise CyberCellEmailError("At least one recipient email address is required.")
    combined_cc = _normalize_email_list([*(cc or []), *([SMTP_DEFAULT_CC] if SMTP_DEFAULT_CC else [])])
    cleaned_cc = validate_email_list(combined_cc, field_name="cc") if combined_cc else []
    cleaned_cc = [value for value in cleaned_cc if value not in cleaned_recipients]
    if len(cleaned_recipients) + len(cleaned_cc) > 10:
        raise CyberCellEmailError("A maximum of 10 recipient and CC email addresses is allowed per cyber cell report.")
    return cleaned_recipients, cleaned_cc


def send_cyber_cell_email(
    *,
    subject: str,
    body_text: str,
    recipients: list[str],
    cc: list[str] | None,
    attachments: list[dict[str, Any]],
) -> dict[str, Any]:
    delivery_status = reporting_delivery_status()
    if not REPORTING_ENABLED:
        raise CyberCellEmailError("Cyber cell reporting is currently disabled.")
    to_list, cc_list = build_recipient_lists(recipients, cc)
    sender = SMTP_FROM_EMAIL or SMTP_USER
    if not sender:
        raise CyberCellEmailError("SMTP sender address is not configured.")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = ", ".join(to_list)
    if cc_list:
        message["Cc"] = ", ".join(cc_list)
    if SMTP_REPLY_TO:
        message["Reply-To"] = SMTP_REPLY_TO
    message.set_content(body_text)

    for attachment in attachments:
        mime_type = str(attachment.get("mime_type") or "application/octet-stream")
        maintype, _, subtype = mime_type.partition("/")
        message.add_attachment(
            attachment.get("content", b""),
            maintype=maintype or "application",
            subtype=subtype or "octet-stream",
            filename=str(attachment.get("name") or "attachment.bin"),
        )

    if REPORTING_MOCK_MODE:
        return {
            "mocked": True,
            "delivery_mode": "mock",
            "sent_to": to_list,
            "cc": cc_list,
            "attachment_names": [attachment.get("name") for attachment in attachments],
        }

    if not delivery_status["smtp_ready"]:
        raise CyberCellEmailError("SMTP delivery is not configured for live cyber cell reporting.")

    try:
        if SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS)
        else:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS)
        with server:
            if SMTP_USE_STARTTLS and not SMTP_USE_SSL:
                server.starttls()
            if SMTP_USER:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(message)
    except Exception as exc:
        raise CyberCellEmailError(f"SMTP delivery failed: {exc}") from exc

    return {
        "mocked": False,
        "delivery_mode": "live",
        "sent_to": to_list,
        "cc": cc_list,
        "attachment_names": [attachment.get("name") for attachment in attachments],
    }
