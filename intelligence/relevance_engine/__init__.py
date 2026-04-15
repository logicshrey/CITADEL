from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from intelligence.validators import validate_entity
from intelligence.validators.email_validator import validate_semantic_email
from utils.config import ORG_PROFILES_PATH


logger = logging.getLogger(__name__)
OWNERSHIP_CUES = ("owned by", "belongs to", "bank portal", "employee", "corporate", "login", "credential", "breach", "dump")


class OrganizationProfile(BaseModel):
    model_config = ConfigDict(extra="ignore")

    org_name: str
    org_keywords: list[str] = Field(default_factory=list)
    official_domains: list[str] = Field(default_factory=list)
    email_patterns: list[str] = Field(default_factory=list)
    known_ips: list[str] = Field(default_factory=list)
    known_brands: list[str] = Field(default_factory=list)
    trusted_assets: list[str] = Field(default_factory=list)


class RelevanceAssessment(BaseModel):
    model_config = ConfigDict(extra="ignore")

    profile: OrganizationProfile
    filtered_entities: list[dict[str, Any]] = Field(default_factory=list)
    matched_assets: dict[str, list[str]] = Field(default_factory=dict)
    matched_indicators: list[str] = Field(default_factory=list)
    relevance_score: int = 0
    relevance_reasons: list[str] = Field(default_factory=list)
    verified_org_match: bool = False
    verification_status: str = "NO"
    suppressed_noise: bool = False
    suppression_reasons: list[str] = Field(default_factory=list)
    rejected_entities: list[dict[str, str]] = Field(default_factory=list)

    @property
    def verified_asset_count(self) -> int:
        return sum(
            len(self.matched_assets.get(key, []))
            for key in ("domains", "emails", "ips", "usernames", "tokens")
        )

    def to_public_dict(self) -> dict[str, Any]:
        payload = self.model_dump()
        payload["verified_asset_count"] = self.verified_asset_count
        payload["matched_assets_flat"] = flatten_relevant_assets(self.matched_assets)
        return payload


def load_organization_profiles(path: Path = ORG_PROFILES_PATH) -> dict[str, OrganizationProfile]:
    try:
        if not path.exists():
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.debug("Failed to load organization profiles from %s: %s", path, exc)
        return {}

    if not isinstance(payload, dict):
        return {}
    profiles: dict[str, OrganizationProfile] = {}
    for key, value in payload.items():
        if not isinstance(value, dict):
            continue
        try:
            profile = OrganizationProfile.model_validate(value)
        except Exception as exc:
            logger.debug("Skipped invalid organization profile %s: %s", key, exc)
            continue
        profiles[_profile_key(key or profile.org_name)] = _normalize_profile(profile)
    return profiles


def save_organization_profiles(profiles: dict[str, OrganizationProfile], path: Path = ORG_PROFILES_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serializable = {
        _profile_key(key): _normalize_profile(profile).model_dump()
        for key, profile in profiles.items()
    }
    path.write_text(json.dumps(serializable, indent=2), encoding="utf-8")


def resolve_organization_profile(query: str, watchlist: dict[str, Any] | None = None) -> OrganizationProfile:
    profiles = load_organization_profiles()
    profile_key = _profile_key(query)
    stored = profiles.get(profile_key)
    inferred = _infer_profile(query, watchlist)
    if stored is None:
        return inferred
    merged = OrganizationProfile.model_validate(
        {
            "org_name": stored.org_name or inferred.org_name,
            "org_keywords": sorted(set([*stored.org_keywords, *inferred.org_keywords])),
            "official_domains": sorted(set([*stored.official_domains, *inferred.official_domains])),
            "email_patterns": sorted(set([*stored.email_patterns, *inferred.email_patterns])),
            "known_ips": sorted(set([*stored.known_ips, *inferred.known_ips])),
            "known_brands": sorted(set([*stored.known_brands, *inferred.known_brands])),
            "trusted_assets": sorted(set([*stored.trusted_assets, *inferred.trusted_assets])),
        }
    )
    return _normalize_profile(merged)


def assess_organization_relevance(
    *,
    profile: OrganizationProfile,
    extracted_entities: list[dict[str, Any]],
    raw_evidence_snippet: str,
    source_metadata: dict[str, Any] | None = None,
) -> RelevanceAssessment:
    evidence_text = _build_evidence_text(raw_evidence_snippet, source_metadata)
    matched_assets = {
        "domains": [],
        "emails": [],
        "ips": [],
        "usernames": [],
        "tokens": [],
        "wallets": [],
    }
    filtered_entities: list[dict[str, Any]] = []
    relevance_reasons: list[str] = []
    rejected_entities: list[dict[str, str]] = []
    strong_asset_points = 0
    explicit_org_identifier = _explicit_org_identifier(profile, evidence_text)

    for entity in extracted_entities:
        normalized_entity = _normalize_entity(entity)
        if normalized_entity is None:
            continue
        label = str(normalized_entity.get("entity_type") or normalized_entity.get("label") or "").upper()
        value = str(normalized_entity.get("text") or "").strip()
        if not value:
            continue

        accepted = False
        reason = ""
        bucket = None

        if label == "EMAIL":
            email_check = validate_semantic_email(
                value,
                official_domains=profile.official_domains,
                org_keywords=[*profile.org_keywords, *profile.known_brands],
                evidence_text=evidence_text,
                whitelisted_domains=profile.trusted_assets,
            )
            if not email_check.is_valid_email:
                reason = email_check.rejection_reason
            elif email_check.is_org_relevant:
                accepted = True
                reason = email_check.rejection_reason
                bucket = "emails"
                strong_asset_points += 32
            else:
                reason = email_check.rejection_reason
        elif label == "DOMAIN":
            if _domain_matches_profile(value, profile):
                accepted = True
                reason = f"Accepted domain {value} because it matches an official organization domain."
                bucket = "domains"
                strong_asset_points += 34
            elif _has_strong_context_match(value, profile, evidence_text):
                accepted = True
                reason = f"Accepted domain {value} because the evidence strongly ties it to the organization."
                bucket = "domains"
                strong_asset_points += 20
            else:
                reason = f"Rejected domain {value} because it is not tied to the organization profile."
        elif label == "IP":
            if _ip_matches_profile(value, profile):
                accepted = True
                reason = f"Accepted IP {value} because it matches a known organization IP range."
                bucket = "ips"
                strong_asset_points += 30
            elif _ip_has_context_support(value, profile, evidence_text):
                accepted = True
                reason = f"Accepted IP {value} because it appears alongside strong organization evidence."
                bucket = "ips"
                strong_asset_points += 16
            else:
                reason = f"Rejected IP {value} because it is not tied to known organization infrastructure."
        elif label == "USERNAME":
            if _username_matches_profile(value, profile, evidence_text):
                accepted = True
                reason = f"Accepted username {value} because it follows the organization naming pattern."
                bucket = "usernames"
                strong_asset_points += 18
            else:
                reason = f"Rejected username {value} because it is not attributable to the organization."
        elif label == "TOKEN":
            if _has_strong_context_match(value, profile, evidence_text):
                accepted = True
                reason = "Accepted token because the surrounding evidence strongly ties it to the organization."
                bucket = "tokens"
                strong_asset_points += 18
            else:
                reason = "Rejected token because it lacks organization-owned context."
        elif label == "WALLET":
            if _has_strong_context_match(value, profile, evidence_text):
                accepted = True
                reason = "Accepted wallet because the surrounding evidence strongly ties it to the organization."
                bucket = "wallets"
                strong_asset_points += 10
            else:
                reason = "Rejected wallet because it lacks organization-owned context."
        elif label == "ORG":
            if _org_entity_matches_profile(value, profile):
                accepted = True
                reason = f"Accepted organization identifier {value} because it matches the organization profile."
        elif label == "PLATFORM":
            accepted = False
            reason = f"Rejected platform label {value} because it is not an organization asset."

        if accepted:
            filtered_entities.append(normalized_entity)
            if bucket:
                matched_assets[bucket].append(value)
            relevance_reasons.append(reason)
            logger.debug("Relevance accepted entity %s (%s): %s", value, label, reason)
        else:
            rejected_entities.append({"text": value, "label": label, "reason": reason or "Rejected by relevance rules."})
            logger.debug("Relevance rejected entity %s (%s): %s", value, label, reason)

    matched_assets = {key: _dedupe(values) for key, values in matched_assets.items()}
    matched_indicators = flatten_relevant_assets(matched_assets)
    verified_asset_count = sum(len(matched_assets.get(key, [])) for key in ("domains", "emails", "ips", "usernames", "tokens"))

    keyword_support = 12 if explicit_org_identifier else 0
    evidence_support = 10 if _evidence_contains_trusted_asset(profile, evidence_text) else 0
    relevance_score = min(100, strong_asset_points + keyword_support + evidence_support)
    if verified_asset_count == 0:
        relevance_score = min(relevance_score, 40)

    verified_org_match = bool(verified_asset_count > 0 or explicit_org_identifier)
    suppression_reasons: list[str] = []
    if verified_asset_count == 0:
        suppression_reasons.append("No verified organization-owned domains, emails, IPs, usernames, or tokens were retained.")

    if not relevance_reasons and explicit_org_identifier:
        relevance_reasons.append("Evidence contains an explicit organization identifier but no verified organization-owned assets.")
    if explicit_org_identifier:
        relevance_reasons.append("Evidence contains an explicit organization identifier.")

    assessment = RelevanceAssessment(
        profile=profile,
        filtered_entities=_dedupe_entities(filtered_entities),
        matched_assets=matched_assets,
        matched_indicators=_dedupe(matched_indicators),
        relevance_score=relevance_score,
        relevance_reasons=_dedupe(relevance_reasons),
        verified_org_match=verified_org_match,
        verification_status="YES" if verified_asset_count > 0 else "NO",
        suppressed_noise=bool(suppression_reasons),
        suppression_reasons=suppression_reasons,
        rejected_entities=rejected_entities[:30],
    )
    logger.debug(
        "Computed relevance for %s: score=%s verified_assets=%s suppressed=%s",
        profile.org_name,
        assessment.relevance_score,
        assessment.verified_asset_count,
        assessment.suppressed_noise,
    )
    return assessment


def flatten_relevant_assets(matched_assets: dict[str, list[str]]) -> list[str]:
    ordered: list[str] = []
    for key in ("domains", "emails", "ips", "usernames", "tokens", "wallets"):
        ordered.extend(matched_assets.get(key, []))
    return _dedupe(ordered)


def _infer_profile(query: str, watchlist: dict[str, Any] | None) -> OrganizationProfile:
    query_value = str(query or "").strip()
    watchlist_name = str((watchlist or {}).get("name") or query_value).strip()
    asset_values = list((watchlist or {}).get("assets", []))
    inferred_domains = []
    inferred_ips = []
    trusted_assets = []

    query_domain = validate_entity(query_value, "DOMAIN")
    if query_domain:
        inferred_domains.append(query_domain["text"])

    for asset in asset_values:
        asset_text = str(asset or "").strip()
        if not asset_text:
            continue
        domain_match = validate_entity(asset_text, "DOMAIN")
        if domain_match:
            inferred_domains.append(domain_match["text"])
            trusted_assets.append(domain_match["text"])
            continue
        ip_match = validate_entity(asset_text, "IP")
        if ip_match:
            inferred_ips.append(ip_match["text"])
            trusted_assets.append(ip_match["text"])
            continue
        if "@" in asset_text:
            domain = asset_text.split("@", 1)[-1].strip().lower()
            if validate_entity(domain, "DOMAIN"):
                inferred_domains.append(domain)
                trusted_assets.append(asset_text.strip().lower())

    official_domains = _dedupe(inferred_domains)
    org_keywords = _keywordize([query_value, watchlist_name, *official_domains])
    known_brands = _dedupe([query_value, watchlist_name])
    email_patterns = [f"*@{domain}" for domain in official_domains]

    return _normalize_profile(
        OrganizationProfile(
            org_name=query_value or watchlist_name or "unknown-org",
            org_keywords=org_keywords,
            official_domains=official_domains,
            email_patterns=email_patterns,
            known_ips=_dedupe(inferred_ips),
            known_brands=known_brands,
            trusted_assets=_dedupe([*trusted_assets, *official_domains]),
        )
    )


def _normalize_profile(profile: OrganizationProfile) -> OrganizationProfile:
    return OrganizationProfile.model_validate(
        {
            "org_name": str(profile.org_name or "").strip(),
            "org_keywords": _keywordize(profile.org_keywords),
            "official_domains": _dedupe(str(domain or "").strip().lower() for domain in profile.official_domains),
            "email_patterns": _dedupe(str(pattern or "").strip().lower() for pattern in profile.email_patterns),
            "known_ips": _dedupe(str(ip or "").strip() for ip in profile.known_ips),
            "known_brands": _dedupe(str(brand or "").strip() for brand in profile.known_brands),
            "trusted_assets": _dedupe(str(asset or "").strip().lower() for asset in profile.trusted_assets),
        }
    )


def _normalize_entity(entity: dict[str, Any]) -> dict[str, Any] | None:
    value = str(entity.get("text") or "").strip()
    label = str(entity.get("entity_type") or entity.get("label") or "").upper().strip()
    if not value or not label:
        return None
    normalized = dict(entity)
    normalized["text"] = value
    normalized["label"] = label
    normalized["entity_type"] = label
    return normalized


def _keywordize(values: list[str]) -> list[str]:
    keywords: list[str] = []
    for value in values:
        keywords.extend(token for token in re.split(r"[^a-z0-9]+", str(value or "").lower()) if len(token) > 2)
    return _dedupe(keywords)


def _profile_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-") or "unknown-org"


def _domain_matches_profile(domain: str, profile: OrganizationProfile) -> bool:
    lowered = domain.lower()
    return any(lowered == official or lowered.endswith(f".{official}") for official in profile.official_domains if official)


def _ip_matches_profile(ip_value: str, profile: OrganizationProfile) -> bool:
    try:
        parsed_ip = ipaddress.ip_address(str(ip_value).strip())
    except ValueError:
        return False
    for entry in profile.known_ips:
        try:
            if "/" in entry:
                if parsed_ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif parsed_ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


def _ip_has_context_support(ip_value: str, profile: OrganizationProfile, evidence_text: str) -> bool:
    if ip_value not in evidence_text:
        return False
    return _evidence_contains_trusted_asset(profile, evidence_text) and any(cue in evidence_text for cue in OWNERSHIP_CUES)


def _username_matches_profile(username: str, profile: OrganizationProfile, evidence_text: str) -> bool:
    lowered = username.lower()
    if any(keyword in lowered for keyword in profile.org_keywords if len(keyword) > 3):
        return True
    if any(brand.lower().replace(" ", "") in lowered for brand in profile.known_brands if brand):
        return True
    for domain in profile.official_domains:
        domain_tokens = [token for token in re.split(r"[^a-z0-9]+", domain.lower()) if len(token) > 2]
        if any(token in lowered for token in domain_tokens):
            return True
    return False


def _has_strong_context_match(value: str, profile: OrganizationProfile, evidence_text: str) -> bool:
    lowered = str(value or "").lower()
    if lowered not in evidence_text:
        return False
    if not any(keyword in evidence_text for keyword in [*profile.org_keywords, *[brand.lower() for brand in profile.known_brands]] if keyword):
        return False
    return any(cue in evidence_text for cue in OWNERSHIP_CUES)


def _explicit_org_identifier(profile: OrganizationProfile, evidence_text: str) -> bool:
    return any(
        keyword in evidence_text
        for keyword in [*profile.org_keywords, *[brand.lower() for brand in profile.known_brands]]
        if keyword and len(keyword) > 2
    )


def _evidence_contains_trusted_asset(profile: OrganizationProfile, evidence_text: str) -> bool:
    trusted = [*profile.official_domains, *profile.trusted_assets]
    return any(asset and asset.lower() in evidence_text for asset in trusted)


def _org_entity_matches_profile(value: str, profile: OrganizationProfile) -> bool:
    lowered = value.lower()
    return lowered == profile.org_name.lower() or lowered in [brand.lower() for brand in profile.known_brands]


def _build_evidence_text(raw_evidence_snippet: str, source_metadata: dict[str, Any] | None) -> str:
    parts = [str(raw_evidence_snippet or "")]
    if source_metadata:
        for value in source_metadata.values():
            parts.extend(_flatten_text(value))
    return "\n".join(part for part in parts if part).lower()


def _flatten_text(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        results: list[str] = []
        for nested in value.values():
            results.extend(_flatten_text(nested))
        return results
    if isinstance(value, (list, tuple, set)):
        results: list[str] = []
        for nested in value:
            results.extend(_flatten_text(nested))
        return results
    if value is None:
        return []
    return [str(value)]


def _dedupe(values: Any) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
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


def _dedupe_entities(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for entity in entities:
        key = (
            str(entity.get("text") or "").strip().lower(),
            str(entity.get("entity_type") or entity.get("label") or "").strip().upper(),
        )
        if not key[0] or key in seen:
            continue
        seen.add(key)
        results.append(entity)
    return results


__all__ = [
    "OrganizationProfile",
    "RelevanceAssessment",
    "assess_organization_relevance",
    "flatten_relevant_assets",
    "load_organization_profiles",
    "resolve_organization_profile",
    "save_organization_profiles",
]
