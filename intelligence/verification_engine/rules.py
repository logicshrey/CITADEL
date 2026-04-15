from __future__ import annotations


VERIFIED_BADGE = "VERIFIED"
LIKELY_BADGE = "LIKELY"
WEAK_SIGNAL_BADGE = "WEAK_SIGNAL"

HIGH_SIGNAL_SENSITIVE_TYPES = {
    "Credential Pair",
    "JWT Token",
    "AWS Access Key",
    "AWS Secret Key",
    "Google API Key",
    "GitHub Token",
    "Stripe Key",
    "MD5 Hash",
    "SHA1 Hash",
    "SHA256 Hash",
    "bcrypt Hash",
    "argon2 Hash",
    "SQL Dump Indicator",
}
