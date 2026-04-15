from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

IST = timezone(timedelta(hours=5, minutes=30))


def _clean_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for value in values:
        normalized = _clean_text(value)
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        results.append(normalized)
    return results


def _format_list(values: list[str], fallback: str = "Not Identified") -> str:
    cleaned = _dedupe(values)
    if not cleaned:
        return fallback
    return "\n".join(f"- {value}" for value in cleaned)


def _max_severity(cases: list[dict[str, Any]]) -> str:
    ranking = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if not cases:
        return "Not Provided"
    selected = max(cases, key=lambda item: ranking.get(str(item.get("severity") or "").lower(), 0))
    return str(selected.get("severity") or "Not Provided")


def _confidence_score(cases: list[dict[str, Any]]) -> int:
    return max((int(case.get("confidence_score", 0) or 0) for case in cases), default=0)


def _first_seen(cases: list[dict[str, Any]]) -> str:
    values = sorted(str(case.get("first_seen") or "") for case in cases if case.get("first_seen"))
    return values[0] if values else "Not Provided"


def _last_seen(cases: list[dict[str, Any]]) -> str:
    values = sorted((str(case.get("last_seen") or "") for case in cases if case.get("last_seen")), reverse=True)
    return values[0] if values else "Not Provided"


def _estimate_identifiers(cases: list[dict[str, Any]]) -> str:
    total = 0
    found = False
    for case in cases:
        value = case.get("estimated_total_records")
        if value is None:
            continue
        try:
            total += max(int(value), 0)
            found = True
        except (TypeError, ValueError):
            continue
    return str(total) if found else str(sum(len(case.get("evidence", [])) for case in cases))


def _collect_sources(cases: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for case in cases:
        for source in case.get("sources", []):
            values.append(str(source.get("source") or "Unknown Source"))
    return _dedupe(values)


def _collect_source_identifiers(cases: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for case in cases:
        leak_origin = case.get("leak_origin") if isinstance(case.get("leak_origin"), dict) else {}
        values.extend(
            [
                str(leak_origin.get("channel_or_user") or ""),
                str(leak_origin.get("actor") or ""),
            ]
        )
    return _dedupe(values)


def _collect_post_urls(cases: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for case in cases:
        leak_origin = case.get("leak_origin") if isinstance(case.get("leak_origin"), dict) else {}
        values.append(str(leak_origin.get("post_url") or ""))
        for source in case.get("sources", []):
            values.extend(str(location or "") for location in source.get("source_locations", []))
    return [value for value in _dedupe(values) if value.lower().startswith(("http://", "https://"))]


def _collect_assets(cases: list[dict[str, Any]], key: str) -> list[str]:
    values: list[str] = []
    for case in cases:
        assets = case.get("affected_assets") if isinstance(case.get("affected_assets"), dict) else {}
        values.extend(str(value or "") for value in assets.get(key, []))
    return _dedupe(values)


def _collect_other_identifiers(cases: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for case in cases:
        assets = case.get("affected_assets") if isinstance(case.get("affected_assets"), dict) else {}
        for key in ("usernames", "tokens", "wallets"):
            values.extend(str(value or "") for value in assets.get(key, []))
    return _dedupe(values)


def _best_snippet(cases: list[dict[str, Any]]) -> str:
    for case in cases:
        for evidence in case.get("evidence", []):
            snippet = (
                evidence.get("cleaned_snippet")
                or evidence.get("raw_snippet")
                or evidence.get("raw_excerpt")
                or evidence.get("summary")
                or ""
            )
            cleaned = _clean_text(snippet)
            if cleaned:
                return cleaned[:600]
    for case in cases:
        cleaned = _clean_text(case.get("summary") or case.get("technical_summary") or case.get("exposure_summary"))
        if cleaned:
            return cleaned[:600]
    return "No evidence snippet available."


def _dominant_category(cases: list[dict[str, Any]]) -> str:
    categories = _dedupe([str(case.get("category") or "") for case in cases])
    if not categories:
        return "Suspected Exposure"
    if len(categories) == 1:
        return categories[0]
    return "Multiple exposure categories"


def build_complaint_payload(
    cases: list[dict[str, Any]],
    *,
    organization_name: str,
    contact_person_details: dict[str, Any],
    organization_details: dict[str, Any] | None = None,
    authority_location: str | None = None,
) -> dict[str, Any]:
    organization_details = dict(organization_details or {})
    now_utc = datetime.now(timezone.utc)
    now_ist = now_utc.astimezone(IST)
    domains = _collect_assets(cases, "domains")
    emails = _collect_assets(cases, "emails")
    ips = _collect_assets(cases, "ips")
    others = _collect_other_identifiers(cases)
    sources = _collect_sources(cases)
    source_identifiers = _collect_source_identifiers(cases)
    post_urls = _collect_post_urls(cases)
    subject = f"URGENT: Reporting Suspected Data Exposure / Credential Leak - {organization_name} - Generated by CITADEL"
    body = "\n".join(
        [
            "To,",
            "The Officer In-Charge,",
            "Cyber Crime Cell / Cyber Police Station,",
            authority_location or "India",
            "",
            f"Date: {now_ist.strftime('%Y-%m-%d')}",
            f"Time (UTC/IST): {now_utc.strftime('%Y-%m-%d %H:%M UTC')} / {now_ist.strftime('%Y-%m-%d %H:%M IST')}",
            "",
            f"Subject: Urgent Reporting of Suspected Data Exposure / Credential Leak - {organization_name}",
            "",
            "Respected Sir/Madam,",
            "",
            f"We, {organization_name}, are submitting this report to formally inform the Cyber Crime Cell about a suspected incident of data exposure / credential leak / database dump identified through our continuous external threat monitoring platform (CITADEL Exposure Intelligence System).",
            "",
            "This report is being submitted for early investigation, verification, and necessary action, as the incident may involve unauthorized access, leakage, or distribution of sensitive organizational data.",
            "",
            "Organization Details",
            f"Organization Name: {organization_name}",
            f"Organization Domain(s): {', '.join(domains) if domains else 'Not Provided'}",
            f"Industry Type: {_clean_text(organization_details.get('industry')) or 'Not Provided'}",
            f"Registered Address: {_clean_text(organization_details.get('registered_address')) or 'Not Provided'}",
            f"Point of Contact Name: {_clean_text(contact_person_details.get('name')) or 'Not Provided'}",
            f"Designation: {_clean_text(contact_person_details.get('designation')) or 'Not Provided'}",
            f"Email ID: {_clean_text(contact_person_details.get('email')) or 'Not Provided'}",
            f"Phone Number: {_clean_text(contact_person_details.get('phone')) or 'Not Provided'}",
            "Incident Summary (Non-Technical Explanation)",
            "CITADEL has detected that certain organization-related assets such as domains, email addresses, or other identifiers may have been exposed publicly or shared through external sources.",
            "",
            "The exposure may indicate:",
            "",
            "Unauthorized disclosure of credentials (username/password)",
            "Leakage of email addresses or sensitive records",
            "Exposure of a database or internal system to the public internet",
            "",
            "This could lead to risks such as account compromise, fraud, phishing attacks, and misuse of sensitive information.",
            "",
            "Exposure Detection Details",
            f"Detection Type: {_dominant_category(cases)}",
            f"Severity Level: {_max_severity(cases)}",
            f"Confidence Score: {_confidence_score(cases)}",
            f"Date of First Detection: {_first_seen(cases)}",
            f"Last Seen: {_last_seen(cases)}",
            f"Total Affected Identifiers (Estimated): {_estimate_identifiers(cases)}",
            "Impacted Assets Identified",
            "The following organization-linked assets were identified:",
            "",
            "Domains:",
            _format_list(domains),
            "",
            "Emails:",
            _format_list(emails),
            "",
            "IP Addresses:",
            _format_list(ips),
            "",
            "Other Identifiers:",
            _format_list(others),
            "",
            "Source & Evidence Details",
            "The suspected exposure was detected from the following intelligence sources:",
            f"Platform / Source: {', '.join(sources) if sources else 'Not Provided'}",
            f"Source Identifier: {', '.join(source_identifiers) if source_identifiers else 'Not Provided'}",
            f"Post / URL Reference: {', '.join(post_urls) if post_urls else 'Not Provided'}",
            f'Evidence Snippet (Extracted): "{_best_snippet(cases)}"',
            "",
            "Note: Full evidence details are attached in the enclosed report.",
            "",
            "Risk Assessment",
            "Based on current intelligence, the incident may cause:",
            "Unauthorized access to organizational systems",
            "Credential stuffing attacks",
            "Customer or employee data misuse",
            "Financial fraud attempts",
            "Large-scale phishing campaigns",
            "Reputation damage and compliance impact",
            "Immediate Actions Taken by Organization",
            "We have initiated preliminary containment steps, including:",
            "Internal security verification in progress",
            "Credential reset planning (where applicable)",
            "Access log monitoring",
            "Blocking suspicious activity (if confirmed)",
            "Further internal investigation underway",
            "Request to Cyber Crime Cell",
            "We respectfully request the Cyber Crime Cell to:",
            "Verify and investigate the source of leaked data.",
            "Assist in identifying the responsible party / origin.",
            "Support takedown action or blocking of distribution channels (if applicable).",
            "Provide guidance on legal and procedural steps for further action.",
            "Register this as an official cyber incident record if required.",
            "Attachments",
            "This email includes:",
            "CITADEL Exposure Intelligence Report (PDF)",
            "CITADEL Complaint Summary (Generated Document)",
            "Evidence Metadata (Optional JSON)",
            "",
            "Declaration",
            "We confirm that this report is generated based on external intelligence monitoring. The information provided is intended for early warning and investigation purposes. Further verification is in progress internally.",
            "",
            "Thank you,",
            organization_name,
            _clean_text(contact_person_details.get("name")) or "Not Provided",
            _clean_text(contact_person_details.get("designation")) or "Not Provided",
            _clean_text(contact_person_details.get("email")) or "Not Provided",
            _clean_text(contact_person_details.get("phone")) or "Not Provided",
            "",
            "Optional Legal Line:",
            "This incident may fall under relevant provisions of the Information Technology Act, 2000 (India), including unauthorized access, data theft, and cyber fraud.",
        ]
    )
    return {
        "subject": subject,
        "complaint_body": body,
        "generated_date": now_ist.strftime("%Y-%m-%d"),
        "generated_time_utc": now_utc.strftime("%Y-%m-%d %H:%M UTC"),
        "generated_time_ist": now_ist.strftime("%Y-%m-%d %H:%M IST"),
    }
