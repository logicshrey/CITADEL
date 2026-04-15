from __future__ import annotations

from dataclasses import dataclass
import re


EMAIL_PATTERN = re.compile(
    r"^(?=.{6,254}$)(?=.{1,64}@)"
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}$"
)
DOMAIN_PATTERN = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$",
    re.IGNORECASE,
)
BLOCKED_PSEUDO_TLDS = {"service", "local", "internal", "lan"}
BLOCKED_DOMAIN_KEYWORDS = {"systemd", "tty", "frr", "configfs", "drm", "fuse", "keygen"}
BLOCKED_SERVICE_USERS = {
    "agetty",
    "daemon",
    "dbus",
    "heartbeat-failed",
    "modprobe",
    "nobody",
    "postfix",
    "root",
    "sshd",
    "systemd",
}


@dataclass(frozen=True)
class SemanticEmailValidation:
    normalized_email: str
    is_valid_email: bool
    is_org_relevant: bool
    rejection_reason: str


def validate_semantic_email(
    value: str,
    *,
    official_domains: list[str] | None = None,
    org_keywords: list[str] | None = None,
    evidence_text: str = "",
    whitelisted_domains: list[str] | None = None,
) -> SemanticEmailValidation:
    normalized = str(value or "").strip().lower()
    if not EMAIL_PATTERN.fullmatch(normalized):
        return SemanticEmailValidation(normalized, False, False, "Rejected email because the address format is invalid.")

    local_part, domain = normalized.rsplit("@", 1)
    if local_part.startswith(".") or local_part.endswith(".") or ".." in local_part:
        return SemanticEmailValidation(normalized, False, False, "Rejected email because the local part is malformed.")
    if not DOMAIN_PATTERN.fullmatch(domain):
        return SemanticEmailValidation(normalized, False, False, "Rejected email because the domain format is invalid.")

    tld = domain.rsplit(".", 1)[-1]
    if tld in BLOCKED_PSEUDO_TLDS:
        return SemanticEmailValidation(normalized, False, False, f"Rejected email because the domain uses pseudo-TLD .{tld}.")
    if any(keyword in domain for keyword in BLOCKED_DOMAIN_KEYWORDS):
        return SemanticEmailValidation(normalized, False, False, "Rejected email because the domain looks like a service or host identifier.")
    if _looks_like_service_account(local_part):
        return SemanticEmailValidation(normalized, False, False, "Rejected email because the username looks like a service account.")

    official_domains = _normalize_domains(official_domains or [])
    whitelisted_domains = _normalize_domains(whitelisted_domains or [])
    evidence_text = str(evidence_text or "").lower()
    org_keywords = [token for token in _normalize_keywords(org_keywords or []) if len(token) > 2]

    domain_matches_org = _domain_in_scope(domain, official_domains) or _domain_in_scope(domain, whitelisted_domains)
    strong_context = bool(evidence_text) and (
        domain in evidence_text
        and any(keyword in evidence_text for keyword in org_keywords)
    )

    if domain_matches_org or strong_context:
        reason = (
            "Validated email because it matches an organization domain."
            if domain_matches_org
            else "Validated email because evidence strongly ties it to the organization."
        )
        return SemanticEmailValidation(normalized, True, True, reason)

    return SemanticEmailValidation(
        normalized,
        True,
        False,
        "Validated email syntax, but the address is not yet tied to the organization.",
    )


def _normalize_domains(values: list[str]) -> list[str]:
    domains: list[str] = []
    for value in values:
        normalized = str(value or "").strip().lower()
        if not normalized:
            continue
        domains.append(normalized.lstrip("*."))
    return sorted(set(domains))


def _normalize_keywords(values: list[str]) -> list[str]:
    keywords: list[str] = []
    for value in values:
        keywords.extend(token for token in re.split(r"[^a-z0-9]+", str(value or "").lower()) if token)
    return sorted(set(keywords))


def _looks_like_service_account(local_part: str) -> bool:
    lowered = local_part.lower()
    if lowered in BLOCKED_SERVICE_USERS:
        return True
    if lowered.endswith(("-service", ".service", "_service")):
        return True
    return any(token in lowered for token in BLOCKED_DOMAIN_KEYWORDS)


def _domain_in_scope(candidate: str, allowed_domains: list[str]) -> bool:
    lowered = candidate.lower()
    return any(lowered == domain or lowered.endswith(f".{domain}") for domain in allowed_domains if domain)


__all__ = ["SemanticEmailValidation", "validate_semantic_email"]
