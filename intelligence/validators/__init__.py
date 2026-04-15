from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import ipaddress
import math
import re
from typing import Any

from intelligence.validators.email_validator import validate_semantic_email


EMAIL_PATTERN = re.compile(
    r"^(?=.{6,254}$)(?=.{1,64}@)"
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$"
)
DOMAIN_PATTERN = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$",
    re.IGNORECASE,
)
BITCOIN_WALLET_PATTERN = re.compile(r"^(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_\-./+=]{20,512}$")

BLOCKED_FILE_SUFFIXES = {
    "7z",
    "bmp",
    "css",
    "csv",
    "gif",
    "html",
    "ico",
    "jpeg",
    "jpg",
    "js",
    "json",
    "md",
    "pdf",
    "php",
    "png",
    "svg",
    "tar",
    "txt",
    "webp",
    "xml",
    "yaml",
    "yml",
    "zip",
}
PATH_LIKE_NOISE = {
    "admin.php",
    "db.php",
    "favicon.ico",
    "index.html",
    "index.php",
    "login.php",
    "readme.md",
    "robots.txt",
    "sitemap.xml",
}
GENERIC_ENTITY_CONFIDENCE = {
    "GPE": 0.68,
    "HANDLE": 0.72,
    "ORG": 0.74,
    "PERSON": 0.64,
    "PLATFORM": 0.7,
    "USERNAME": 0.69,
}
PATTERN_BUCKET_TO_ENTITY = {
    "bitcoin_wallets": "WALLET",
    "domains": "DOMAIN",
    "emails": "EMAIL",
    "ips": "IP",
    "tokens": "TOKEN",
}


@dataclass(frozen=True)
class ValidatedEntity:
    text: str
    label: str
    entity_type: str
    confidence: float
    validation_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "label": self.label,
            "entity_type": self.entity_type,
            "confidence": round(self.confidence, 2),
            "validation_reason": self.validation_reason,
        }


def validate_entity(value: str, entity_type: str) -> dict[str, Any] | None:
    normalized_type = _normalize_entity_type(entity_type)
    normalized_value = _normalize_text(value)
    if not normalized_value:
        return None

    validator = _ENTITY_VALIDATORS.get(normalized_type, _validate_generic_entity)
    result = validator(normalized_value, normalized_type)
    if result is None:
        return None
    return result.to_dict()


def validate_entities(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    validated: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for entity in entities:
        value = str(entity.get("text") or entity.get("value") or "").strip()
        entity_type = str(entity.get("label") or entity.get("entity_type") or "").strip()
        result = validate_entity(value, entity_type)
        if result is None:
            continue
        key = (result["text"].lower(), result["label"])
        if key in seen:
            continue
        seen.add(key)
        validated.append(result)
    return validated


def validate_string_list(entity_type: str, values: list[str]) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for value in values:
        validated = validate_entity(value, entity_type)
        if validated is None:
            continue
        normalized = str(validated["text"]).strip()
        lowered = normalized.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        results.append(normalized)
    return results


def filter_pattern_matches(matches: dict[str, list[str]]) -> dict[str, list[str]]:
    filtered: dict[str, list[str]] = {}
    for bucket, values in matches.items():
        entity_type = PATTERN_BUCKET_TO_ENTITY.get(bucket)
        if entity_type is None:
            filtered[bucket] = _dedupe_strings(values)
            continue
        filtered[bucket] = validate_string_list(entity_type, values)
    return filtered


@lru_cache(maxsize=4096)
def _validate_email(value: str, _: str) -> ValidatedEntity | None:
    normalized = value.strip()
    semantic = validate_semantic_email(normalized)
    if not semantic.is_valid_email:
        return None
    local_part, domain = semantic.normalized_email.rsplit("@", 1)
    validated_domain = _validate_domain(domain, "DOMAIN")
    if validated_domain is None:
        return None
    return ValidatedEntity(
        text=f"{local_part}@{validated_domain.text}",
        label="EMAIL",
        entity_type="EMAIL",
        confidence=0.99,
        validation_reason=semantic.rejection_reason,
    )


@lru_cache(maxsize=4096)
def _validate_domain(value: str, _: str) -> ValidatedEntity | None:
    normalized = value.strip().lower().rstrip(".")
    if not normalized or normalized in PATH_LIKE_NOISE:
        return None
    if any(separator in normalized for separator in ("/", "\\", "?", "#", "@", ":")):
        return None
    if normalized.startswith(("http://", "https://")):
        return None
    suffix = normalized.rsplit(".", 1)[-1]
    if suffix in BLOCKED_FILE_SUFFIXES:
        return None
    if not DOMAIN_PATTERN.fullmatch(normalized):
        return None
    labels = normalized.split(".")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        return None
    return ValidatedEntity(
        text=normalized,
        label="DOMAIN",
        entity_type="DOMAIN",
        confidence=0.97,
        validation_reason="Validated domain structure and rejected file-like suffixes.",
    )


@lru_cache(maxsize=4096)
def _validate_ip(value: str, _: str) -> ValidatedEntity | None:
    normalized = value.strip()
    try:
        parsed = ipaddress.ip_address(normalized)
    except ValueError:
        return None
    version = "IPv6" if parsed.version == 6 else "IPv4"
    return ValidatedEntity(
        text=parsed.compressed,
        label="IP",
        entity_type="IP",
        confidence=0.98,
        validation_reason=f"Validated {version} address syntax.",
    )


@lru_cache(maxsize=4096)
def _validate_token(value: str, _: str) -> ValidatedEntity | None:
    normalized = value.strip()
    if not TOKEN_PATTERN.fullmatch(normalized):
        return None
    if len(normalized) < 20:
        return None
    entropy = _shannon_entropy(normalized)
    if entropy < 3.5:
        return None
    return ValidatedEntity(
        text=normalized,
        label="TOKEN",
        entity_type="TOKEN",
        confidence=0.88,
        validation_reason=f"Validated token candidate with length {len(normalized)} and entropy {entropy:.2f}.",
    )


@lru_cache(maxsize=4096)
def _validate_wallet(value: str, _: str) -> ValidatedEntity | None:
    normalized = value.strip()
    if not BITCOIN_WALLET_PATTERN.fullmatch(normalized):
        return None
    return ValidatedEntity(
        text=normalized,
        label="WALLET",
        entity_type="WALLET",
        confidence=0.96,
        validation_reason="Validated Bitcoin wallet format.",
    )


@lru_cache(maxsize=4096)
def _validate_generic_entity(value: str, entity_type: str) -> ValidatedEntity | None:
    normalized = _normalize_text(value)
    if len(normalized) < 2:
        return None
    label = _normalize_entity_type(entity_type)
    return ValidatedEntity(
        text=normalized,
        label=label,
        entity_type=label,
        confidence=GENERIC_ENTITY_CONFIDENCE.get(label, 0.65),
        validation_reason=f"Accepted contextual {label} entity after normalization.",
    )


def _normalize_entity_type(entity_type: str) -> str:
    normalized = str(entity_type or "").strip().upper()
    aliases = {
        "EMAILS": "EMAIL",
        "DOMAINS": "DOMAIN",
        "HANDLES": "HANDLE",
        "IPS": "IP",
        "IPV4": "IP",
        "IPV6": "IP",
        "TOKENS": "TOKEN",
        "WALLETS": "WALLET",
    }
    return aliases.get(normalized, normalized or "UNKNOWN")


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip())


def _dedupe_strings(values: list[str]) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = _normalize_text(value)
        if not normalized:
            continue
        lowered = normalized.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        results.append(normalized)
    return results


def _shannon_entropy(value: str) -> float:
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


_ENTITY_VALIDATORS = {
    "DOMAIN": _validate_domain,
    "EMAIL": _validate_email,
    "IP": _validate_ip,
    "TOKEN": _validate_token,
    "WALLET": _validate_wallet,
}


__all__ = [
    "ValidatedEntity",
    "filter_pattern_matches",
    "validate_entities",
    "validate_entity",
    "validate_string_list",
    "validate_semantic_email",
]
