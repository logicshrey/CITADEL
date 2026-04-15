from __future__ import annotations

import re


PAN_PATTERN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
Aadhaar_PATTERN = re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b")
CREDIT_CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
JWT_PATTERN = re.compile(r"\b(?:eyJ[A-Za-z0-9_-]{6,}|[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
AWS_ACCESS_KEY_PATTERN = re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b")
AWS_SECRET_KEY_PATTERN = re.compile(
    r"(?i)\b(?:aws|amazon)?[_\s-]*(?:secret|secret[_\s-]*access)[_\s-]*key\b\s*[:=]\s*([A-Za-z0-9/+=]{40})"
)
GOOGLE_API_KEY_PATTERN = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
GITHUB_TOKEN_PATTERN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b")
STRIPE_KEY_PATTERN = re.compile(r"\b(?:sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b")
PASSWORD_PATTERN = re.compile(r"(?i)\b(?:password|passwd|pwd|pass)\b\s*[:=]\s*([^\s,;\"'<>]{3,})")
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
BCRYPT_PATTERN = re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")
ARGON2_PATTERN = re.compile(r"\$argon2(?:id|i|d)\$[^\s]{20,}")
BANK_ACCOUNT_PATTERN = re.compile(r"\b\d{9,18}\b")
IFSC_PATTERN = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
PHONE_PATTERN = re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b")
SQL_DUMP_PATTERN = re.compile(r"(?i)\b(?:INSERT\s+INTO|CREATE\s+TABLE|DROP\s+TABLE|mysqldump|pg_dump|database dump|\.sql\b|SELECT \* FROM)\b")


HASH_PATTERNS = {
    "MD5 Hash": MD5_PATTERN,
    "SHA1 Hash": SHA1_PATTERN,
    "SHA256 Hash": SHA256_PATTERN,
    "bcrypt Hash": BCRYPT_PATTERN,
    "argon2 Hash": ARGON2_PATTERN,
}


TOKEN_PATTERNS = {
    "JWT Token": JWT_PATTERN,
    "AWS Access Key": AWS_ACCESS_KEY_PATTERN,
    "Google API Key": GOOGLE_API_KEY_PATTERN,
    "GitHub Token": GITHUB_TOKEN_PATTERN,
    "Stripe Key": STRIPE_KEY_PATTERN,
}
