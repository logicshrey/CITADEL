from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from utils.config import PLATFORM_REPUTATION_SCORES


TOKEN_PATTERN = re.compile(r"[a-z0-9@._:-]+")
URL_PATTERN = re.compile(r"https?://\S+", re.IGNORECASE)

COMMON_STOPWORDS = {
    "a",
    "about",
    "after",
    "all",
    "an",
    "and",
    "any",
    "are",
    "as",
    "at",
    "be",
    "been",
    "by",
    "can",
    "com",
    "for",
    "from",
    "general",
    "how",
    "in",
    "into",
    "is",
    "it",
    "its",
    "just",
    "more",
    "no",
    "notes",
    "of",
    "on",
    "or",
    "page",
    "repo",
    "repository",
    "sample",
    "some",
    "text",
    "the",
    "their",
    "there",
    "this",
    "to",
    "using",
    "with",
}

NOISE_KEYWORDS = {
    "allowlist",
    "blog",
    "cheat sheet",
    "class notes",
    "cors",
    "developer forum",
    "documentation",
    "example.com",
    "harmless",
    "learning",
    "mozilla",
    "norton",
    "notes.md",
    "readme",
    "training",
    "tutorial",
    "whatsapp",
    "youtube.com",
}

GENERIC_ORG_NOISE = {
    "account",
    "admin",
    "bank",
    "company",
    "corp",
    "customer",
    "email",
    "login",
    "password",
    "support",
    "team",
    "user",
}

HIGH_SIGNAL_TERMS = {
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
    "logs",
    "otp",
    "phishing",
    "private key",
    "ransomware",
    "session",
    "stealer",
    "stolen",
    "token",
    "wallet",
}

LOW_TRUST_SOURCES = {"telegram", "pastebin", "unknown"}
HIGH_TRUST_SOURCES = {"dehashed", "leakix"}


@dataclass
class ConfidenceResult:
    score: int
    reasons: list[str]
    source_trust: float
    exact_match: bool
    likely_noise: bool
    similarity_score: float


def normalize_signal_text(text: str) -> str:
    lowered = str(text or "").lower()
    lowered = URL_PATTERN.sub(" ", lowered)
    lowered = re.sub(r"[^a-z0-9@._:\-/\s]+", " ", lowered)
    lowered = re.sub(r"\s+", " ", lowered).strip()
    return lowered


def tokenize_signal_text(text: str) -> list[str]:
    normalized = normalize_signal_text(text)
    return [
        token
        for token in TOKEN_PATTERN.findall(normalized)
        if token
        and len(token) > 2
        and token not in COMMON_STOPWORDS
    ]


def token_similarity(left: str, right: str) -> float:
    left_tokens = set(tokenize_signal_text(left))
    right_tokens = set(tokenize_signal_text(right))
    if not left_tokens or not right_tokens:
        return 0.0
    return round(len(left_tokens.intersection(right_tokens)) / len(left_tokens.union(right_tokens)), 4)


def source_trust_score(source: str) -> float:
    normalized = str(source or "Unknown").strip()
    return round(float(PLATFORM_REPUTATION_SCORES.get(normalized, PLATFORM_REPUTATION_SCORES.get(normalized.title(), 0.35))), 2)


def is_likely_noise(text: str, source: str = "", metadata: dict[str, Any] | None = None) -> tuple[bool, list[str]]:
    metadata_blob = " ".join(str(value) for value in (metadata or {}).values())
    normalized = normalize_signal_text(f"{text} {metadata_blob}")
    reasons: list[str] = []
    if any(keyword in normalized for keyword in NOISE_KEYWORDS):
        reasons.append("Contains common educational or incidental-reference keywords.")
    if "github" in normalized and any(keyword in normalized for keyword in {"readme", "notes", "tutorial", "allowlist"}):
        reasons.append("Looks like documentation or training material rather than a leak artifact.")
    if str(source or "").strip().lower() == "github" and "search_type" in (metadata or {}) and not any(
        signal in normalized for signal in HIGH_SIGNAL_TERMS
    ):
        reasons.append("GitHub reference lacks strong exposure context.")
    return (bool(reasons), reasons)


def query_match_strength(query: str, text: str, matched_indicators: list[str] | None = None) -> tuple[bool, list[str]]:
    normalized_query = str(query or "").strip().lower()
    if not normalized_query:
        return False, []

    normalized_text = normalize_signal_text(text)
    indicators = [item.lower() for item in (matched_indicators or [])]
    reasons: list[str] = []

    exact_domain_match = "." in normalized_query and f"@{normalized_query}" in normalized_text or normalized_query in indicators
    if exact_domain_match:
        reasons.append("Direct monitored domain or indicator match.")
    elif normalized_query in normalized_text:
        reasons.append("Query text appears in the source content.")

    return bool(reasons), reasons


def generic_mention_penalty(query: str, text: str) -> tuple[int, list[str]]:
    normalized_query = str(query or "").strip().lower()
    normalized_text = normalize_signal_text(text)
    if "." in normalized_query and " " not in normalized_query:
        if any(pattern in normalized_text for pattern in {"gmail.com password dump", "yahoo.com password dump", "hotmail.com password dump"}):
            return 25, ["Matches a generic consumer-domain dump phrase rather than an organization-specific leak."]
        return 0, []

    query_tokens = [token for token in tokenize_signal_text(normalized_query) if token not in GENERIC_ORG_NOISE]
    text_tokens = tokenize_signal_text(normalized_text)
    if not query_tokens:
        return 20, ["Organization query is too generic without strong context."]

    overlap = set(query_tokens).intersection(text_tokens)
    if not overlap:
        return 15, ["Organization name mention is weak or absent after normalization."]
    return 0, []


def score_confidence(
    *,
    query: str,
    text: str,
    source: str,
    matched_indicators: list[str] | None = None,
    data_types: list[str] | None = None,
    source_locations: list[str] | None = None,
    evidence_count: int = 1,
    metadata: dict[str, Any] | None = None,
) -> ConfidenceResult:
    matched_indicators = matched_indicators or []
    data_types = data_types or []
    source_locations = source_locations or []
    source_trust = source_trust_score(source)
    exact_match, exact_match_reasons = query_match_strength(query, text, matched_indicators)
    likely_noise, noise_reasons = is_likely_noise(text, source=source, metadata=metadata)
    generic_penalty, generic_reasons = generic_mention_penalty(query, text)
    normalized_text = normalize_signal_text(text)
    signal_terms = [term for term in HIGH_SIGNAL_TERMS if term in normalized_text]

    score = 20
    reasons: list[str] = []

    if exact_match:
        score += 32
        reasons.extend(exact_match_reasons)
    elif str(query or "").strip().lower() in normalized_text:
        score += 12
        reasons.append("Observed mention of the monitored query in source content.")

    if matched_indicators:
        score += min(20, len(matched_indicators) * 4)
        reasons.append(f"Matched {len(matched_indicators)} extracted indicator(s).")

    if data_types:
        score += min(14, len(data_types) * 4)
        reasons.append(f"Extracted exposure-related data types: {', '.join(data_types[:3])}.")

    if source_locations:
        score += 6
        reasons.append("Evidence contains traceable source locations.")

    if evidence_count > 1:
        score += min(10, evidence_count * 2)
        reasons.append("Multiple evidence items support the same finding.")

    score += round(source_trust * 18)
    reasons.append(f"Source trust weighting contributed {round(source_trust * 18)} points.")

    if signal_terms:
        score += min(12, len(signal_terms) * 3)
        reasons.append(f"High-signal leak terms detected: {', '.join(sorted(signal_terms)[:4])}.")

    if likely_noise:
        score -= 22
        reasons.extend(noise_reasons)

    if generic_penalty:
        score -= generic_penalty
        reasons.extend(generic_reasons)

    score = max(0, min(100, score))
    similarity_score = 1.0 if exact_match else round(min(1.0, (len(signal_terms) + len(matched_indicators)) / 12), 4)
    return ConfidenceResult(
        score=score,
        reasons=_dedupe_reasons(reasons),
        source_trust=source_trust,
        exact_match=exact_match,
        likely_noise=likely_noise,
        similarity_score=similarity_score,
    )


def build_event_signature(
    *,
    query: str,
    source: str,
    title: str = "",
    text: str = "",
    matched_indicators: list[str] | None = None,
    source_locations: list[str] | None = None,
    channel_hint: str = "",
) -> str:
    matched_indicators = matched_indicators or []
    source_locations = source_locations or []
    normalized_text = normalize_signal_text(text)
    dominant_tokens = Counter(tokenize_signal_text(f"{title} {normalized_text}")).most_common(12)
    signature_basis = [
        str(query or "").strip().lower(),
        str(source or "").strip().lower(),
        str(channel_hint or "").strip().lower(),
        "|".join(sorted(item.lower() for item in matched_indicators[:8])),
        "|".join(sorted(item.lower() for item in source_locations[:4])),
        "|".join(token for token, _ in dominant_tokens),
    ]
    return hashlib.sha256("::".join(signature_basis).encode("utf-8")).hexdigest()[:24]


def choose_primary_location(source_locations: list[str]) -> tuple[str | None, str | None]:
    for location in source_locations:
        normalized = str(location or "").strip()
        if normalized.startswith("http"):
            return None, normalized
    for location in source_locations:
        normalized = str(location or "").strip()
        if normalized:
            return normalized, None
    return None, None


def should_promote_finding(confidence: ConfidenceResult, minimum_score: int = 45) -> bool:
    if confidence.likely_noise and confidence.score < 70:
        return False
    return confidence.score >= minimum_score


def _dedupe_reasons(values: list[str]) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
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
