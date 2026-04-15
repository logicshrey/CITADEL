from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


CaseCategory = Literal[
    "Credential Leak",
    "Data Sale",
    "Pastebin Leak",
    "Phishing",
    "Malware Chatter",
    "Impersonation",
    "Token Leak",
    "Database Dump",
    "Unknown",
]
SeverityLevel = Literal["Critical", "High", "Medium", "Low"]
TriageStatus = Literal["New", "Under Review", "Verified", "False Positive", "Closed"]
EvidenceType = Literal["screenshot", "text", "link", "dump snippet"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _coerce_str_list(values: Any) -> list[str]:
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return []

    results: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = str(value or "").strip()
        if not normalized:
            continue
        lowered = normalized.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        results.append(normalized)
    return results


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_timestamp(value: Any) -> str:
    parsed = _parse_iso(value)
    return parsed.isoformat() if parsed else _now_iso()


def _normalize_optional_timestamp(value: Any) -> str | None:
    parsed = _parse_iso(value)
    return parsed.isoformat() if parsed else None


def _priority_to_severity(priority: Any, priority_score: Any = None) -> SeverityLevel:
    normalized_priority = str(priority or "").strip().upper()
    score = _coerce_int(priority_score, 0)
    if normalized_priority == "CRITICAL" or score >= 85:
        return "Critical"
    if normalized_priority == "HIGH" or score >= 65:
        return "High"
    if normalized_priority == "MEDIUM" or score >= 40:
        return "Medium"
    return "Low"


def _severity_to_priority(severity: Any) -> str:
    normalized = str(severity or "").strip().lower()
    if normalized == "critical":
        return "CRITICAL"
    if normalized == "high":
        return "HIGH"
    if normalized == "medium":
        return "MEDIUM"
    return "LOW"


def _legacy_status_to_triage(status: Any) -> TriageStatus:
    normalized = str(status or "").strip().lower()
    mapping = {
        "new": "New",
        "under review": "Under Review",
        "investigating": "Under Review",
        "contained": "Under Review",
        "verified": "Verified",
        "resolved": "Verified",
        "false positive": "False Positive",
        "closed": "Closed",
    }
    return mapping.get(normalized, "New")


def _triage_to_legacy_status(status: Any) -> str:
    normalized = str(status or "").strip().lower()
    mapping = {
        "new": "new",
        "under review": "investigating",
        "verified": "resolved",
        "false positive": "closed",
        "closed": "closed",
    }
    return mapping.get(normalized, "new")


def _normalize_category(value: Any) -> CaseCategory:
    normalized = str(value or "").strip().lower()
    mapping: dict[str, CaseCategory] = {
        "credential leak": "Credential Leak",
        "database dump": "Database Dump",
        "data sale": "Data Sale",
        "pastebin leak": "Pastebin Leak",
        "phishing": "Phishing",
        "malware chatter": "Malware Chatter",
        "malware sale": "Malware Chatter",
        "impersonation": "Impersonation",
        "token leak": "Token Leak",
    }
    return mapping.get(normalized, "Unknown")


class AffectedAssets(BaseModel):
    model_config = ConfigDict(extra="ignore")

    domains: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    tokens: list[str] = Field(default_factory=list)
    wallets: list[str] = Field(default_factory=list)


class LeakOrigin(BaseModel):
    model_config = ConfigDict(extra="ignore")

    platform: str = "Unknown"
    channel_or_user: str | None = None
    post_url: str | None = None


class ConfidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="ignore")

    score: int = 0
    reasons: list[str] = Field(default_factory=list)


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="ignore")

    evidence_id: str
    evidence_type: EvidenceType = "text"
    source_platform: str = "Unknown"
    raw_snippet: str = ""
    cleaned_snippet: str = ""
    matched_entities: list[str] = Field(default_factory=list)
    timestamp: str
    source_locations: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    legacy_summary: str | None = None
    data_breakdown: list[dict[str, Any]] = Field(default_factory=list)


class SourceRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")

    source: str = "Unknown"
    first_seen: str | None = None
    last_seen: str | None = None
    evidence_count: int = 0
    source_locations: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    confidence_score: float = 0.0
    trust_score: float = 0.0
    related_sources: list[dict[str, Any]] = Field(default_factory=list)


class ExposureCase(BaseModel):
    model_config = ConfigDict(extra="ignore")

    case_id: str
    id: str
    created_at: str
    updated_at: str
    org_id: str
    organization: str
    query: str = ""
    category: CaseCategory = "Unknown"
    severity: SeverityLevel = "Low"
    confidence_score: int = 0
    risk_score: int = 0
    affected_assets: AffectedAssets = Field(default_factory=AffectedAssets)
    affected_assets_flat: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    sources: list[SourceRecord] = Field(default_factory=list)
    extracted_entities: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    leak_origin: LeakOrigin = Field(default_factory=LeakOrigin)
    exposure_summary: str = ""
    technical_summary: str = ""
    executive_summary: str = ""
    recommended_actions: list[str] = Field(default_factory=list)
    suggested_remediation_steps: list[str] = Field(default_factory=list)
    why_this_was_flagged: list[str] = Field(default_factory=list)
    confidence_assessment: ConfidenceAssessment = Field(default_factory=ConfidenceAssessment)
    triage_status: TriageStatus = "New"
    assigned_to: str = "Unassigned"
    business_unit: str = "Security Operations"
    tags: list[str] = Field(default_factory=list)
    watchlists: list[str] = Field(default_factory=list)
    matched_indicators: list[str] = Field(default_factory=list)
    exposed_data_types: list[str] = Field(default_factory=list)
    estimated_total_records: int | None = None
    estimated_total_records_label: str = "Amount not disclosed by the source"
    event_signature: str = ""
    fingerprint_key: str = ""
    source_count: int = 0
    evidence_count: int = 0
    corroborating_source_count: int = 0
    first_seen: str
    last_seen: str
    confidence_basis: list[str] = Field(default_factory=list)
    severity_reason: str = ""
    owner: str = "Unassigned"
    priority: str = "LOW"
    priority_score: int = 0
    risk_level: str = "LOW"
    threat_type: str = "Unknown"
    title: str = ""
    summary: str = ""
    case_status: str = "new"


class ReportFilterRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    org_id: str | None = None
    start_date: str | None = None
    end_date: str | None = None
    severity: list[str] = Field(default_factory=list)
    category: list[str] = Field(default_factory=list)


def flatten_affected_assets(value: Any) -> list[str]:
    if isinstance(value, dict):
        flattened: list[str] = []
        for asset_list in value.values():
            flattened.extend(_coerce_str_list(asset_list))
        return _coerce_str_list(flattened)
    return _coerce_str_list(value)


def normalize_affected_assets(payload: dict[str, Any]) -> AffectedAssets:
    existing = payload.get("affected_assets")
    if isinstance(existing, dict):
        return AffectedAssets.model_validate(existing)

    flat_assets = flatten_affected_assets(existing)
    matched_indicators = _coerce_str_list(payload.get("matched_indicators", []))
    evidence_entities: list[str] = []
    for evidence in payload.get("evidence", []):
        if isinstance(evidence, dict):
            evidence_entities.extend(_coerce_str_list(evidence.get("matched_entities")))
            evidence_entities.extend(_coerce_str_list(evidence.get("matched_indicators")))

    tokens = _coerce_str_list(payload.get("tokens", []))
    wallets = _coerce_str_list(payload.get("wallets", []))

    domains = [item for item in flat_assets if "." in item and "@" not in item and ":" not in item]
    emails = [item for item in [*flat_assets, *matched_indicators, *evidence_entities] if "@" in item]
    ips = [item for item in [*flat_assets, *matched_indicators] if item.count(".") == 3 and all(part.isdigit() for part in item.split("."))]
    usernames = [
        item
        for item in [*flat_assets, *matched_indicators, *evidence_entities]
        if item
        and item not in domains
        and item not in emails
        and item not in ips
        and item not in tokens
        and item not in wallets
    ]

    return AffectedAssets(
        domains=_coerce_str_list(domains),
        emails=_coerce_str_list(emails),
        ips=_coerce_str_list(ips),
        usernames=_coerce_str_list(usernames),
        tokens=_coerce_str_list(tokens),
        wallets=_coerce_str_list(wallets),
    )


def normalize_evidence_list(payload: dict[str, Any], default_source: str = "Unknown") -> list[EvidenceItem]:
    results: list[EvidenceItem] = []
    for index, evidence in enumerate(payload.get("evidence", [])):
        if not isinstance(evidence, dict):
            continue
        source_platform = str(
            evidence.get("source_platform")
            or evidence.get("source")
            or payload.get("leak_origin", {}).get("platform")
            or default_source
        ).strip() or "Unknown"
        raw_snippet = str(evidence.get("raw_snippet") or evidence.get("raw_excerpt") or evidence.get("summary") or "").strip()
        cleaned_snippet = str(evidence.get("cleaned_snippet") or evidence.get("summary") or raw_snippet[:500]).strip()
        source_locations = _coerce_str_list(evidence.get("source_locations", []))
        evidence_type: EvidenceType = "link" if any(location.startswith("http") for location in source_locations) else "text"
        results.append(
            EvidenceItem(
                evidence_id=str(evidence.get("evidence_id") or f"{source_platform.lower()}-evidence-{index + 1}"),
                evidence_type=evidence_type,
                source_platform=source_platform,
                raw_snippet=raw_snippet,
                cleaned_snippet=cleaned_snippet,
                matched_entities=_coerce_str_list(evidence.get("matched_entities") or evidence.get("matched_indicators") or []),
                timestamp=_normalize_timestamp(evidence.get("timestamp") or payload.get("last_seen")),
                source_locations=source_locations,
                provenance=evidence.get("provenance") if isinstance(evidence.get("provenance"), dict) else {},
                legacy_summary=str(evidence.get("summary") or "").strip() or None,
                data_breakdown=list(evidence.get("data_breakdown", [])) if isinstance(evidence.get("data_breakdown"), list) else [],
            )
        )
    return results


def normalize_source_records(payload: dict[str, Any]) -> list[SourceRecord]:
    results: list[SourceRecord] = []
    for source in payload.get("sources", []):
        if not isinstance(source, dict):
            continue
        results.append(
            SourceRecord(
                source=str(source.get("source") or "Unknown"),
                first_seen=_normalize_optional_timestamp(source.get("first_seen")),
                last_seen=_normalize_optional_timestamp(source.get("last_seen")),
                evidence_count=_coerce_int(source.get("evidence_count"), 0),
                source_locations=_coerce_str_list(source.get("source_locations", [])),
                risk_score=round(_coerce_float(source.get("risk_score"), 0.0), 2),
                confidence_score=round(_coerce_float(source.get("confidence_score"), 0.0), 4),
                trust_score=round(_coerce_float(source.get("trust_score"), 0.0), 2),
                related_sources=list(source.get("related_sources", [])) if isinstance(source.get("related_sources"), list) else [],
            )
        )
    return results


def normalize_case_record(payload: dict[str, Any]) -> dict[str, Any]:
    data = dict(payload or {})
    case_id = str(data.get("case_id") or data.get("id") or "")
    created_at = _normalize_timestamp(data.get("created_at") or data.get("first_seen") or data.get("last_seen"))
    updated_at = _normalize_timestamp(data.get("updated_at") or data.get("last_seen") or created_at)
    first_seen = _normalize_timestamp(data.get("first_seen") or created_at)
    last_seen = _normalize_timestamp(data.get("last_seen") or updated_at)

    priority = str(data.get("priority") or "LOW").upper()
    priority_score = _coerce_int(data.get("priority_score"), 0)
    severity = _priority_to_severity(data.get("severity") or priority, priority_score)
    triage_status = _legacy_status_to_triage(data.get("triage_status") or data.get("case_status"))
    leak_origin = data.get("leak_origin") if isinstance(data.get("leak_origin"), dict) else {}
    sources = normalize_source_records(data)
    source_names = [source.source for source in sources]
    canonical_assets = normalize_affected_assets(data)
    affected_assets_flat = flatten_affected_assets(data.get("affected_assets")) or flatten_affected_assets(canonical_assets.model_dump())
    evidence = normalize_evidence_list(data, default_source=source_names[0] if source_names else "Unknown")
    confidence_basis = _coerce_str_list(data.get("confidence_basis", []))
    why_this_was_flagged = _coerce_str_list(data.get("why_this_was_flagged", [])) or confidence_basis[:5]
    confidence_score = max(0, min(100, round(_coerce_float(data.get("confidence_score"), 0.0) * (100 if _coerce_float(data.get("confidence_score"), 0.0) <= 1 else 1))))
    risk_score = max(
        0,
        min(
            100,
            round(
                _coerce_float(data.get("risk_score"), 0.0) * (100 if _coerce_float(data.get("risk_score"), 0.0) <= 1 else 1)
            ),
        ),
    )
    technical_summary = str(data.get("technical_summary") or data.get("summary") or "").strip()
    exposure_summary = str(data.get("exposure_summary") or data.get("executive_summary") or technical_summary).strip()
    executive_summary = str(data.get("executive_summary") or exposure_summary or technical_summary).strip()
    assigned_to = str(data.get("assigned_to") or data.get("owner") or "Unassigned").strip() or "Unassigned"
    title = str(data.get("title") or f"{data.get('organization') or data.get('org_id') or 'Organization'} exposure case").strip()
    category = _normalize_category(data.get("category") or data.get("threat_type"))
    if category == "Unknown" and str(data.get("threat_type") or "").strip():
        category = _normalize_category(data.get("threat_type"))

    normalized_case = ExposureCase(
        case_id=case_id,
        id=case_id,
        created_at=created_at,
        updated_at=updated_at,
        org_id=str(data.get("org_id") or data.get("organization") or data.get("query") or "unknown-org"),
        organization=str(data.get("organization") or data.get("org_id") or data.get("query") or "unknown-org"),
        query=str(data.get("query") or data.get("organization") or ""),
        category=category,
        severity=severity,
        confidence_score=confidence_score,
        risk_score=risk_score,
        affected_assets=canonical_assets,
        affected_assets_flat=affected_assets_flat,
        evidence=evidence,
        sources=sources,
        extracted_entities=_coerce_str_list(data.get("extracted_entities") or data.get("matched_indicators") or []),
        timeline=list(data.get("timeline", [])) if isinstance(data.get("timeline"), list) else [],
        leak_origin=LeakOrigin.model_validate(
            {
                "platform": leak_origin.get("platform") or (source_names[0] if source_names else "Unknown"),
                "channel_or_user": leak_origin.get("channel_or_user"),
                "post_url": leak_origin.get("post_url"),
            }
        ),
        exposure_summary=exposure_summary,
        technical_summary=technical_summary,
        executive_summary=executive_summary,
        recommended_actions=_coerce_str_list(data.get("recommended_actions", [])),
        suggested_remediation_steps=_coerce_str_list(
            data.get("suggested_remediation_steps") or data.get("recommended_actions", [])
        ),
        why_this_was_flagged=why_this_was_flagged,
        confidence_assessment=ConfidenceAssessment(
            score=confidence_score,
            reasons=why_this_was_flagged,
        ),
        triage_status=triage_status,
        assigned_to=assigned_to,
        business_unit=str(data.get("business_unit") or "Security Operations"),
        tags=_coerce_str_list(data.get("tags", [])),
        watchlists=_coerce_str_list(data.get("watchlists", [])),
        matched_indicators=_coerce_str_list(data.get("matched_indicators", [])),
        exposed_data_types=_coerce_str_list(data.get("exposed_data_types", [])),
        estimated_total_records=data.get("estimated_total_records")
        if isinstance(data.get("estimated_total_records"), int)
        else None,
        estimated_total_records_label=str(
            data.get("estimated_total_records_label") or "Amount not disclosed by the source"
        ),
        event_signature=str(data.get("event_signature") or data.get("fingerprint_key") or case_id),
        fingerprint_key=str(data.get("fingerprint_key") or data.get("event_signature") or case_id),
        source_count=len(sources),
        evidence_count=len(evidence),
        corroborating_source_count=max(0, len(sources) - 1),
        first_seen=first_seen,
        last_seen=last_seen,
        confidence_basis=confidence_basis,
        severity_reason=str(data.get("severity_reason") or ""),
        owner=assigned_to,
        priority=_severity_to_priority(severity),
        priority_score=priority_score,
        risk_level=str(data.get("risk_level") or "LOW"),
        threat_type=str(data.get("threat_type") or data.get("category") or "Unknown"),
        title=title,
        summary=technical_summary or exposure_summary,
        case_status=_triage_to_legacy_status(triage_status),
    )
    return normalized_case.model_dump()


def normalize_case_list(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [normalize_case_record(value) for value in values if isinstance(value, dict)]
