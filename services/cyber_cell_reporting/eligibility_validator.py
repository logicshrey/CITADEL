from __future__ import annotations

from collections import Counter
from typing import Any


def _case_org(case: dict[str, Any]) -> str:
    return str(case.get("org_id") or case.get("organization") or "").strip()


def _verified_org_match(case: dict[str, Any]) -> bool:
    if bool(case.get("verified_org_match")):
        return True
    return str(case.get("verification_status") or "").strip().lower() == "yes"


def _has_required_org_assets(case: dict[str, Any]) -> bool:
    assets = case.get("affected_assets") if isinstance(case.get("affected_assets"), dict) else {}
    return bool(assets.get("domains") or assets.get("emails"))


def _case_rejection_reasons(case: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if not _verified_org_match(case):
        reasons.append("Case is not marked as a verified organization match.")
    if int(case.get("confidence_score", 0) or 0) < 80:
        reasons.append("Confidence score is below 80.")
    if str(case.get("severity") or "").strip().lower() not in {"high", "critical"}:
        reasons.append("Severity must be High or Critical.")
    if not case.get("evidence"):
        reasons.append("Case does not contain evidence.")
    if not _has_required_org_assets(case):
        reasons.append("Case must include at least one verified organization-owned domain or email.")
    return reasons


def _severity_summary(cases: list[dict[str, Any]]) -> str:
    ranking = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if not cases:
        return "Unknown"
    highest = max(cases, key=lambda case: ranking.get(str(case.get("severity") or "").lower(), 0))
    return str(highest.get("severity") or "Unknown")


def _confidence_summary(cases: list[dict[str, Any]]) -> int:
    return max((int(case.get("confidence_score", 0) or 0) for case in cases), default=0)


def _first_seen(cases: list[dict[str, Any]]) -> str | None:
    values = sorted(str(case.get("first_seen") or "") for case in cases if case.get("first_seen"))
    return values[0] if values else None


def _last_seen(cases: list[dict[str, Any]]) -> str | None:
    values = sorted((str(case.get("last_seen") or "") for case in cases if case.get("last_seen")), reverse=True)
    return values[0] if values else None


def _estimated_identifiers(cases: list[dict[str, Any]]) -> int:
    total = 0
    for case in cases:
        try:
            total += max(int(case.get("estimated_total_records", 0) or 0), 0)
        except (TypeError, ValueError):
            continue
    if total > 0:
        return total
    return sum(len(case.get("evidence", [])) for case in cases)


def _category_summary(cases: list[dict[str, Any]]) -> str:
    values = [str(case.get("category") or "Unknown") for case in cases]
    if not values:
        return "Unknown"
    return Counter(values).most_common(1)[0][0]


def validate_case_selection(cases: list[dict[str, Any]], *, requested_org_id: str | None = None) -> dict[str, Any]:
    normalized_requested_org = str(requested_org_id or "").strip().lower()
    resolved_orgs = sorted({_case_org(case).lower() for case in cases if _case_org(case)})
    rejection_reasons: list[str] = []
    rejected_cases: list[dict[str, Any]] = []
    eligible_cases: list[dict[str, Any]] = []

    if not cases:
        rejection_reasons.append("No cases matched the provided selection.")

    if len(resolved_orgs) > 1:
        rejection_reasons.append("Cyber cell reporting only supports cases from a single organization per submission.")

    if normalized_requested_org and resolved_orgs and normalized_requested_org not in resolved_orgs:
        rejection_reasons.append("Selected cases do not match the requested organization.")

    for case in cases:
        case_reasons = list(rejection_reasons)
        org_value = _case_org(case)
        if normalized_requested_org and org_value and org_value.strip().lower() != normalized_requested_org:
            case_reasons.append("Case belongs to a different organization than the requested report scope.")
        case_reasons.extend(_case_rejection_reasons(case))
        if case_reasons:
            rejected_cases.append({"case_id": case.get("id") or case.get("case_id"), "reasons": case_reasons})
        else:
            eligible_cases.append(case)

    organization = _case_org(eligible_cases[0]) if eligible_cases else (_case_org(cases[0]) if cases else "")
    global_reasons = list(dict.fromkeys(rejection_reasons))
    if rejected_cases and not eligible_cases:
        global_reasons.extend(reason for item in rejected_cases for reason in item["reasons"])

    report_summary = {
        "org_id": organization,
        "severity": _severity_summary(eligible_cases),
        "confidence_score": _confidence_summary(eligible_cases),
        "first_seen": _first_seen(eligible_cases),
        "last_seen": _last_seen(eligible_cases),
        "estimated_identifiers": _estimated_identifiers(eligible_cases),
        "category": _category_summary(eligible_cases),
    }

    return {
        "is_eligible": bool(eligible_cases) and not rejected_cases and not rejection_reasons,
        "rejection_reasons": list(dict.fromkeys(global_reasons)),
        "eligible_case_ids": [case.get("id") or case.get("case_id") for case in eligible_cases],
        "rejected_case_ids": rejected_cases,
        "eligible_cases": eligible_cases,
        "organization": organization,
        "report_summary": report_summary,
    }
