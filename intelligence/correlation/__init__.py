from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from utils.signal_quality import source_trust_score


LEAK_KEYWORDS = {
    "access",
    "breach",
    "combo",
    "credential",
    "credentials",
    "database",
    "dump",
    "exposed",
    "hash",
    "leak",
    "password",
    "phishing",
    "session",
    "token",
}
VALIDATED_ENTITY_TYPES = {"DOMAIN", "EMAIL", "IP", "TOKEN", "WALLET"}


@dataclass(frozen=True)
class CorrelationAssessment:
    should_create_case: bool
    correlation_score: int
    relevance_score: int
    keyword_match_weight: int
    entity_match_weight: int
    source_trust_weight: int
    evidence_clarity_weight: int
    source_trust: float
    matched_watchlist_entities: list[str]
    validated_entity_count: int
    verified_org_match: bool
    suppressed_noise: bool
    suppression_reasons: list[str]
    reasoning: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "should_create_case": self.should_create_case,
            "correlation_score": self.correlation_score,
            "relevance_score": self.relevance_score,
            "keyword_match_weight": self.keyword_match_weight,
            "entity_match_weight": self.entity_match_weight,
            "source_trust_weight": self.source_trust_weight,
            "evidence_clarity_weight": self.evidence_clarity_weight,
            "source_trust": round(self.source_trust, 2),
            "matched_watchlist_entities": list(self.matched_watchlist_entities),
            "validated_entity_count": self.validated_entity_count,
            "verified_org_match": self.verified_org_match,
            "suppressed_noise": self.suppressed_noise,
            "suppression_reasons": list(self.suppression_reasons),
            "reasoning": list(self.reasoning),
        }


def assess_correlation(
    *,
    query: str,
    result: dict[str, Any],
    watchlist: dict[str, Any] | None = None,
    correlation_threshold: int = 55,
    source_trust_threshold: float = 0.45,
) -> CorrelationAssessment:
    tracked_entities = _build_tracked_entities(query, watchlist)
    query_normalized = str(query or "").strip().lower()
    text = str(result.get("input_text") or result.get("cleaned_text") or "").lower()
    entities = list(result.get("entities", []))
    external = result.get("external_intelligence", {})
    patterns = result.get("patterns", {})
    relevance_assessment = result.get("relevance_assessment", {})

    validated_entities = [
        entity
        for entity in entities
        if str(entity.get("entity_type") or entity.get("label") or "").upper() in VALIDATED_ENTITY_TYPES
        and float(entity.get("confidence", 0.0) or 0.0) >= 0.7
    ]
    validated_entity_count = len(validated_entities)
    relevance_score = int(relevance_assessment.get("relevance_score", 0) or 0)
    verified_org_match = bool(relevance_assessment.get("verified_org_match", False))
    suppressed_noise = bool(relevance_assessment.get("suppressed_noise", False))
    suppression_reasons = list(relevance_assessment.get("suppression_reasons", []))
    matched_assets = list(relevance_assessment.get("matched_indicators", []) or [])

    matched_watchlist_entities: list[str] = []
    entity_match_weight = 0
    if matched_assets:
        matched_watchlist_entities.extend(matched_assets)
        entity_match_weight += min(48, 22 + (len(matched_assets) - 1) * 8)
    elif _looks_like_domain(query_normalized):
        matched_watchlist_entities.extend(_match_domain_entities(query_normalized, validated_entities))
    else:
        if query_normalized and query_normalized in text:
            matched_watchlist_entities.append(query_normalized)
            entity_match_weight += 6
    for tracked in tracked_entities:
        if tracked != query_normalized:
            matched_watchlist_entities.extend(_match_tracked_entity(tracked, validated_entities, text))

    matched_watchlist_entities = _dedupe(matched_watchlist_entities)
    if matched_watchlist_entities:
        entity_match_weight += min(44, 18 + (len(matched_watchlist_entities) - 1) * 9)

    keyword_hits = [keyword for keyword in LEAK_KEYWORDS if keyword in text]
    keyword_match_weight = min(18, len(keyword_hits) * 3)
    if query_normalized and query_normalized in text:
        keyword_match_weight += 4

    source_trust = float(
        result.get("confidence_assessment", {}).get("source_trust")
        or external.get("source_trust")
        or source_trust_score(result.get("source") or external.get("source") or "Unknown")
    )
    source_trust_weight = min(16, int(round(source_trust * 16)))

    evidence_clarity_weight = 0
    if external.get("source_locations"):
        evidence_clarity_weight += 6
    if result.get("patterns", {}).get("passwords"):
        evidence_clarity_weight += 7
    if any(data_type in {"credentials", "hashed passwords", "bulk personal records"} for data_type in external.get("data_types", [])):
        evidence_clarity_weight += 7
    if validated_entity_count:
        evidence_clarity_weight += min(8, validated_entity_count * 2)
    if relevance_score >= 70:
        evidence_clarity_weight += 6
    elif relevance_score >= 45:
        evidence_clarity_weight += 3
    evidence_clarity_weight = min(22, evidence_clarity_weight)

    correlation_score = min(
        100,
        entity_match_weight + keyword_match_weight + source_trust_weight + evidence_clarity_weight + int(round(relevance_score * 0.18)),
    )

    strong_watchlist_match = bool(matched_watchlist_entities) or verified_org_match
    evidence_is_strong = evidence_clarity_weight >= 12
    should_create_case = (
        not suppressed_noise
        and strong_watchlist_match
        and len(matched_assets) > 0
        and validated_entity_count > 0
        and relevance_score >= 45
        and (source_trust >= source_trust_threshold or evidence_is_strong)
        and correlation_score >= correlation_threshold
    )

    reasons: list[str] = []
    if matched_watchlist_entities:
        reasons.append(f"Strong watchlist match on {', '.join(matched_watchlist_entities[:4])}.")
    elif query_normalized and query_normalized in text:
        reasons.append("Organization query appears directly in the source text, but text-only matching is treated as weak evidence.")
    if validated_entity_count:
        reasons.append(f"Validated {validated_entity_count} entity signal(s) before case creation.")
    if relevance_score:
        reasons.append(f"Organization relevance score is {relevance_score}.")
    if keyword_hits:
        reasons.append(f"Leak evidence terms detected: {', '.join(sorted(keyword_hits)[:4])}.")
    if suppression_reasons:
        reasons.extend(suppression_reasons[:2])
    reasons.append(f"Source trust contributed {source_trust_weight} correlation points.")
    reasons.append(f"Evidence clarity contributed {evidence_clarity_weight} correlation points.")

    return CorrelationAssessment(
        should_create_case=should_create_case,
        correlation_score=correlation_score,
        relevance_score=relevance_score,
        keyword_match_weight=keyword_match_weight,
        entity_match_weight=entity_match_weight,
        source_trust_weight=source_trust_weight,
        evidence_clarity_weight=evidence_clarity_weight,
        source_trust=source_trust,
        matched_watchlist_entities=matched_watchlist_entities,
        validated_entity_count=validated_entity_count,
        verified_org_match=verified_org_match,
        suppressed_noise=suppressed_noise,
        suppression_reasons=suppression_reasons,
        reasoning=_dedupe(reasons),
    )


def _build_tracked_entities(query: str, watchlist: dict[str, Any] | None) -> list[str]:
    tracked = [str(query or "").strip().lower()]
    if watchlist:
        tracked.extend(str(asset or "").strip().lower() for asset in watchlist.get("assets", []))
        tracked.append(str(watchlist.get("name") or "").strip().lower())
    return [item for item in _dedupe(tracked) if item]


def _match_domain_entities(query: str, entities: list[dict[str, Any]]) -> list[str]:
    matches: list[str] = []
    for entity in entities:
        label = str(entity.get("entity_type") or entity.get("label") or "").upper()
        value = str(entity.get("text") or "").strip().lower()
        if not value:
            continue
        if label == "DOMAIN" and (value == query or value.endswith(f".{query}")):
            matches.append(value)
        if label == "EMAIL" and value.endswith(f"@{query}"):
            matches.append(value)
    return matches


def _match_tracked_entity(tracked: str, entities: list[dict[str, Any]], text: str) -> list[str]:
    matches: list[str] = []
    tracked = tracked.lower()
    if not tracked:
        return matches
    if tracked in text:
        matches.append(tracked)
    for entity in entities:
        value = str(entity.get("text") or "").strip().lower()
        if not value:
            continue
        if value == tracked:
            matches.append(value)
    return matches


def _looks_like_domain(value: str) -> bool:
    return bool(re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,24}", value or ""))


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


__all__ = ["CorrelationAssessment", "assess_correlation"]
