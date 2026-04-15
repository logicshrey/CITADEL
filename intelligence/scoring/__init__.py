from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CaseScore:
    severity: str
    severity_score: int
    confidence_score: int
    priority: str
    priority_score: int
    risk_level: str
    why_flagged: list[str]
    severity_reason: str
    severity_reasoning: list[str]
    confidence_reasoning: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "severity_score": self.severity_score,
            "confidence_score": self.confidence_score,
            "priority": self.priority,
            "priority_score": self.priority_score,
            "risk_level": self.risk_level,
            "why_flagged": list(self.why_flagged),
            "severity_reason": self.severity_reason,
            "severity_reasoning": list(self.severity_reasoning),
            "confidence_reasoning": list(self.confidence_reasoning),
        }


def score_case(result: dict[str, Any], correlation_assessment: dict[str, Any]) -> CaseScore:
    external = result.get("external_intelligence", {})
    relevance_assessment = result.get("relevance_assessment", {})
    data_types = {str(item).lower() for item in external.get("data_types", [])}
    matched_entities = list(correlation_assessment.get("matched_watchlist_entities", []))
    validated_entity_count = int(correlation_assessment.get("validated_entity_count", 0) or 0)
    correlation_score = int(correlation_assessment.get("correlation_score", 0) or 0)
    source_trust = float(correlation_assessment.get("source_trust", 0.0) or 0.0)
    relevance_score = int(relevance_assessment.get("relevance_score", correlation_assessment.get("relevance_score", 0)) or 0)
    verified_asset_count = int(relevance_assessment.get("verified_asset_count", len(matched_entities)) or 0)
    suppressed_noise = bool(relevance_assessment.get("suppressed_noise", correlation_assessment.get("suppressed_noise", False)))

    credentials_present = "credentials" in data_types or bool(result.get("patterns", {}).get("passwords"))
    token_present = "token leak" == str(result.get("threat_type", "")).strip().lower() or any(
        str(entity.get("entity_type") or "").upper() == "TOKEN" for entity in result.get("entities", [])
    )
    database_present = "database dump" == str(result.get("threat_type", "")).strip().lower() or "bulk personal records" in data_types
    org_email_present = any("@" in value for value in matched_entities)

    severity_score = 10
    severity_reasons: list[str] = []
    confidence_reasons: list[str] = list(correlation_assessment.get("reasoning", []))

    if token_present:
        severity_score += 45
        severity_reasons.append("Validated token exposure raises immediate compromise risk.")
    if credentials_present and (org_email_present or verified_asset_count > 0):
        severity_score += 40
        severity_reasons.append("Credentials are linked to a verified monitored asset.")
    elif credentials_present:
        severity_score += 24
        severity_reasons.append("Credential material is present but asset linkage is limited.")
    if database_present:
        severity_score += 25
        severity_reasons.append("Database or bulk-record exposure indicators were validated.")

    if verified_asset_count >= 2:
        severity_score += 15
        severity_reasons.append("Multiple verified organization assets are involved.")
    elif verified_asset_count == 1:
        severity_score += 8
        severity_reasons.append("At least one monitored organization asset is involved.")

    if source_trust >= 0.75:
        severity_score += 10
        confidence_reasons.append("High-trust source evidence supports the case.")
    elif source_trust >= 0.45:
        severity_score += 6
        confidence_reasons.append("Moderate-trust source evidence supports the case.")

    if correlation_score >= 80:
        severity_score += 14
        confidence_reasons.append("Correlation score shows strong alignment with monitored entities and evidence.")
    elif correlation_score >= 60:
        severity_score += 9
        confidence_reasons.append("Correlation score exceeds the high-confidence case threshold.")

    if relevance_score >= 75:
        severity_score += 12
        confidence_reasons.append("Organization relevance engine retained multiple verified organization assets.")
    elif relevance_score >= 45:
        severity_score += 6
        confidence_reasons.append("Organization relevance engine confirmed meaningful organization-owned evidence.")

    if validated_entity_count == 0:
        severity_score = min(severity_score, 25)
        severity_reasons.append("Severity was capped because no validated entities were retained.")
    if verified_asset_count == 0:
        severity_score = min(severity_score, 30)
        severity_reasons.append("Severity was capped because no verified organization-owned assets were retained.")
        confidence_reasons.append("Keyword-only or weak contextual matches cannot produce high-confidence cases.")
    if suppressed_noise:
        severity_score = min(severity_score, 20)
        severity_reasons.append("Case was marked as suppressed noise because no verified organization-owned assets survived relevance filtering.")

    severity_score = max(0, min(100, severity_score))
    confidence_score = max(
        0,
        min(
            100,
            int(
                round(
                    (relevance_score * 0.35)
                    + (correlation_score * 0.25)
                    + (validated_entity_count * 5)
                    + (verified_asset_count * 8)
                    + (source_trust * 20)
                    + (10 if credentials_present or token_present or database_present else 0)
                )
            ),
        ),
    )
    if verified_asset_count == 0:
        confidence_score = min(confidence_score, 40)
    if suppressed_noise:
        confidence_score = min(confidence_score, 25)

    if severity_score >= 85:
        severity = "Critical"
    elif severity_score >= 65:
        severity = "High"
    elif severity_score >= 40:
        severity = "Medium"
    else:
        severity = "Low"

    priority = severity.upper()
    risk_level = "HIGH" if severity in {"Critical", "High"} else "MEDIUM" if severity == "Medium" else "LOW"
    severity_reason = severity_reasons[0] if severity_reasons else "Case severity remained low due to limited evidence."
    why_flagged = _dedupe([*severity_reasons, *confidence_reasons])[:8]

    return CaseScore(
        severity=severity,
        severity_score=severity_score,
        confidence_score=confidence_score,
        priority=priority,
        priority_score=severity_score,
        risk_level=risk_level,
        why_flagged=why_flagged,
        severity_reason=severity_reason,
        severity_reasoning=_dedupe(severity_reasons),
        confidence_reasoning=_dedupe(confidence_reasons),
    )


def _dedupe(values: list[str]) -> list[str]:
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


__all__ = ["CaseScore", "score_case"]
