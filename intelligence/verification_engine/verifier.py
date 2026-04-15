from __future__ import annotations

from typing import Any

from intelligence.verification_engine.models import VerificationResult
from intelligence.verification_engine.rules import (
    HIGH_SIGNAL_SENSITIVE_TYPES,
    LIKELY_BADGE,
    VERIFIED_BADGE,
    WEAK_SIGNAL_BADGE,
)


def compute_verification_status(case: dict[str, Any]) -> VerificationResult:
    relevance_score = int(case.get("relevance_score", 0) or 0)
    confidence_score = int(case.get("confidence_score", 0) or 0)
    severity_score = int(case.get("severity_score", 0) or 0)
    evidence_count = int(case.get("evidence_count", len(case.get("evidence", []))) or 0)
    source_trust = _source_trust(case)
    sensitive_types = {str(value or "").strip() for value in case.get("sensitive_data_types", []) if str(value or "").strip()}
    suppressed_noise = bool(case.get("suppressed_noise", False))
    verified_org_match = bool(case.get("verified_org_match", False))
    high_signal_sensitive = bool(sensitive_types.intersection(HIGH_SIGNAL_SENSITIVE_TYPES))
    explicit_dump_proof = "SQL Dump Indicator" in sensitive_types or str(case.get("threat_type", "")).strip().lower() == "database dump"
    keyword_only = relevance_score < 60 or not verified_org_match

    reasons: list[str] = []
    score = min(
        100,
        max(
            0,
            int(
                round(
                    (relevance_score * 0.35)
                    + (confidence_score * 0.3)
                    + (severity_score * 0.15)
                    + (min(evidence_count, 3) * 6)
                    + (source_trust * 15)
                    + (10 if high_signal_sensitive else 0)
                )
            ),
        ),
    )

    if evidence_count == 0:
        reasons.append("No supporting evidence snippet was retained for verification.")
    else:
        reasons.append(f"{evidence_count} evidence item(s) support this case.")

    if relevance_score >= 80:
        reasons.append("Organization relevance strongly confirms the evidence belongs to the monitored organization.")
    elif relevance_score >= 60:
        reasons.append("Organization relevance is meaningful but still requires analyst confirmation.")
    else:
        reasons.append("Organization relevance remains weak, so this may be a noisy or contextual mention.")

    if high_signal_sensitive:
        reasons.append("Sensitive or compromise-ready material was detected in the supporting evidence.")
    if explicit_dump_proof:
        reasons.append("Database dump indicators were detected in the evidence.")
    if source_trust >= 0.75:
        reasons.append("Source trust is high enough to materially support verification confidence.")

    if suppressed_noise or evidence_count == 0 or keyword_only:
        badge = WEAK_SIGNAL_BADGE
        score = min(score, 49 if evidence_count else 35)
        reasons.append("The case was downgraded because the signal is weak, noisy, or lacks verified organization ownership.")
    elif relevance_score >= 80 and evidence_count >= 1 and confidence_score >= 85 and (high_signal_sensitive or explicit_dump_proof):
        badge = VERIFIED_BADGE
        score = max(score, 86)
        reasons.append("This case satisfies the high-confidence verification threshold.")
    elif relevance_score >= 60 and evidence_count >= 1 and confidence_score >= 65:
        badge = LIKELY_BADGE
        score = max(score, 65)
        reasons.append("This case meets the likely-verification threshold but still needs analyst review.")
    else:
        badge = WEAK_SIGNAL_BADGE
        score = min(score, 55)
        reasons.append("The signal did not meet the stronger verification thresholds.")

    return VerificationResult(
        verification_badge=badge,
        verification_score=score,
        verification_reasons=_dedupe(reasons),
    )


def _source_trust(case: dict[str, Any]) -> float:
    sources = case.get("sources", [])
    if sources:
        values = [float(source.get("trust_score", 0.0) or 0.0) for source in sources if isinstance(source, dict)]
        if values:
            return max(values)
    external = case.get("external_intelligence", {})
    return float(external.get("source_trust", 0.0) or 0.0) if isinstance(external, dict) else 0.0


def _dedupe(values: list[str]) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = str(value or "").strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        results.append(normalized)
    return results
