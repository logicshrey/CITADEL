from __future__ import annotations

import hashlib
from functools import lru_cache

from intelligence.sensitive_detector.luhn import passes_luhn
from intelligence.sensitive_detector.models import SensitiveDetectionResult, SensitiveFinding
from intelligence.sensitive_detector.patterns import (
    Aadhaar_PATTERN,
    ARGON2_PATTERN,
    AWS_SECRET_KEY_PATTERN,
    BANK_ACCOUNT_PATTERN,
    CREDIT_CARD_PATTERN,
    GITHUB_TOKEN_PATTERN,
    GOOGLE_API_KEY_PATTERN,
    HASH_PATTERNS,
    IFSC_PATTERN,
    PAN_PATTERN,
    PASSWORD_PATTERN,
    PHONE_PATTERN,
    SQL_DUMP_PATTERN,
    STRIPE_KEY_PATTERN,
    TOKEN_PATTERNS,
)


RISK_WEIGHTS = {
    "Credential Pair": 12,
    "JWT Token": 12,
    "AWS Access Key": 12,
    "AWS Secret Key": 12,
    "Google API Key": 10,
    "GitHub Token": 10,
    "Stripe Key": 10,
    "MD5 Hash": 7,
    "SHA1 Hash": 7,
    "SHA256 Hash": 8,
    "bcrypt Hash": 9,
    "argon2 Hash": 9,
    "PAN": 10,
    "Aadhaar": 12,
    "Credit Card": 12,
    "Bank Account": 7,
    "IFSC": 4,
    "Phone Number": 3,
    "SQL Dump Indicator": 9,
}


def detect_sensitive_data(text: str) -> SensitiveDetectionResult:
    raw_text = str(text or "").strip()
    if not raw_text:
        return SensitiveDetectionResult()

    snippet_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    return SensitiveDetectionResult.model_validate(_detect_sensitive_data_cached(snippet_hash, raw_text))


@lru_cache(maxsize=1024)
def _detect_sensitive_data_cached(snippet_hash: str, text: str) -> dict:
    del snippet_hash
    sensitive_types: list[str] = []
    matched_samples: list[dict] = []
    detection_reasons: list[str] = []
    total_risk = 0

    def add_finding(finding_type: str, raw_value: str, reason: str) -> None:
        nonlocal total_risk
        if not raw_value:
            return
        masked_value = _mask_value(raw_value)
        if any(item["finding_type"] == finding_type and item["masked_value"] == masked_value for item in matched_samples):
            return
        risk_weight = RISK_WEIGHTS.get(finding_type, 4)
        matched_samples.append(
            SensitiveFinding(finding_type=finding_type, masked_value=masked_value, risk_weight=risk_weight).model_dump()
        )
        if finding_type not in sensitive_types:
            sensitive_types.append(finding_type)
        if reason not in detection_reasons:
            detection_reasons.append(reason)
        total_risk = min(30, total_risk + risk_weight)

    for match in PASSWORD_PATTERN.finditer(text):
        secret = match.group(1)
        add_finding("Credential Pair", secret, "Evidence snippet contains a password or credential-style assignment.")

    for finding_type, pattern in HASH_PATTERNS.items():
        for match in pattern.finditer(text):
            add_finding(finding_type, match.group(0), f"Evidence snippet contains a {finding_type.lower()}.")

    for finding_type, pattern in TOKEN_PATTERNS.items():
        for match in pattern.finditer(text):
            add_finding(finding_type, match.group(0), f"Evidence snippet contains a {finding_type.lower()}.")

    for match in AWS_SECRET_KEY_PATTERN.finditer(text):
        add_finding("AWS Secret Key", match.group(1), "Evidence snippet contains an AWS secret key style assignment.")

    for match in PAN_PATTERN.finditer(text.upper()):
        add_finding("PAN", match.group(0), "Evidence snippet contains an Indian PAN-like identifier.")

    for match in Aadhaar_PATTERN.finditer(text):
        digits = "".join(char for char in match.group(0) if char.isdigit())
        if len(digits) == 12 and len(set(digits)) > 1:
            add_finding("Aadhaar", digits, "Evidence snippet contains an Aadhaar-like identifier.")

    for match in CREDIT_CARD_PATTERN.finditer(text):
        digits = "".join(char for char in match.group(0) if char.isdigit())
        if passes_luhn(digits):
            add_finding("Credit Card", digits, "Evidence snippet contains a payment card number that passed Luhn validation.")

    for match in BANK_ACCOUNT_PATTERN.finditer(text):
        digits = match.group(0)
        if len(set(digits)) > 1 and not passes_luhn(digits):
            add_finding("Bank Account", digits, "Evidence snippet contains a bank account style number.")

    for match in IFSC_PATTERN.finditer(text.upper()):
        add_finding("IFSC", match.group(0), "Evidence snippet contains an IFSC-style code.")

    for match in PHONE_PATTERN.finditer(text):
        add_finding("Phone Number", "".join(char for char in match.group(0) if char.isdigit()), "Evidence snippet contains a phone number.")

    if SQL_DUMP_PATTERN.search(text):
        add_finding("SQL Dump Indicator", "SQL dump evidence", "Evidence snippet contains database dump or SQL export indicators.")

    return SensitiveDetectionResult(
        sensitive_types=sensitive_types,
        matched_samples=[SensitiveFinding.model_validate(item) for item in matched_samples],
        risk_score_addition=min(30, total_risk),
        detection_reasons=detection_reasons,
    ).model_dump()


def _mask_value(value: str) -> str:
    compact = str(value or "").strip()
    if not compact:
        return ""
    if len(compact) <= 4:
        return "*" * len(compact)
    if compact.isdigit():
        return f"{compact[:2]}{'*' * max(0, len(compact) - 6)}{compact[-4:]}"
    if compact.startswith("$argon2") or compact.startswith("$2"):
        return f"{compact[:8]}***{compact[-6:]}"
    return f"{compact[:4]}{'*' * max(4, len(compact) - 8)}{compact[-4:]}"
