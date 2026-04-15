from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re


STOPWORD_BLACKLIST = {
    "admin.php",
    "db.php",
    "index.php",
    "phpinfo.php",
    "readme.md",
    "robots.txt",
    "server-status",
    "sitemap.xml",
}
GENERIC_SCAN_PATTERNS = (
    "dir listing",
    "directory listing",
    "http/1.1 200 ok",
    "nmap scan",
    "open port",
    "service banner",
    "ssl certificate",
    "status: 200",
    "title:",
)
STRONG_SIGNAL_PATTERNS = (
    "account takeover",
    "api key",
    "bearer",
    "combo",
    "credential",
    "database",
    "dump",
    "hash",
    "leak",
    "password",
    "phishing",
    "secret",
    "session",
    "token",
)
FILE_LINE_PATTERN = re.compile(
    r"^(?:[\w./-]+/)?[\w.-]+\.(?:php|txt|xml|json|js|css|png|jpg|jpeg|svg|gif|ico|html|md)$",
    re.IGNORECASE,
)
TIMESTAMP_PATTERN = re.compile(r"\b\d{4}-\d{2}-\d{2}[t\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:?\d{2})?\b", re.IGNORECASE)
UUID_PATTERN = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.IGNORECASE)
LONG_ID_PATTERN = re.compile(r"\b[a-f0-9]{16,}\b", re.IGNORECASE)
WHITESPACE_PATTERN = re.compile(r"\s+")
TOKEN_PATTERN = re.compile(r"[a-z0-9@._:-]+")


@dataclass(frozen=True)
class NoiseFilterResult:
    likely_noise: bool
    reasons: list[str]
    score: int
    canonical_text: str


def assess_noise(text: str, *, source: str = "", matched_assets: list[str] | None = None) -> NoiseFilterResult:
    normalized = canonicalize_event_text(text)
    lowered = normalized.lower()
    matched_assets = [str(asset or "").strip().lower() for asset in (matched_assets or []) if str(asset or "").strip()]
    reasons: list[str] = []
    score = 0

    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    file_lines = [line for line in lines if FILE_LINE_PATTERN.fullmatch(line)]
    blacklist_hits = sorted({term for term in STOPWORD_BLACKLIST if term in lowered})
    generic_scan_hits = sorted({term for term in GENERIC_SCAN_PATTERNS if term in lowered})
    strong_signal_hits = sorted({term for term in STRONG_SIGNAL_PATTERNS if term in lowered})
    matched_asset_hits = [asset for asset in matched_assets if asset and asset in lowered]

    if file_lines and len(file_lines) >= 3 and len(file_lines) >= max(3, len(lines) // 2):
        score += 28
        reasons.append("Content is dominated by generic file listings instead of incident evidence.")

    if blacklist_hits and not matched_asset_hits:
        score += min(18, len(blacklist_hits) * 6)
        reasons.append(f"Contains common junk artifacts: {', '.join(blacklist_hits[:4])}.")

    if generic_scan_hits and not matched_asset_hits:
        score += min(18, len(generic_scan_hits) * 6)
        reasons.append("Looks like generic scanning or inventory output without a clear organization asset match.")

    if not strong_signal_hits and (blacklist_hits or file_lines):
        score += 10
        reasons.append("No strong leak indicators were found alongside the noisy artifacts.")

    return NoiseFilterResult(
        likely_noise=score >= 25,
        reasons=_dedupe(reasons),
        score=score,
        canonical_text=normalized,
    )


def canonicalize_event_text(text: str) -> str:
    normalized = str(text or "").lower()
    normalized = TIMESTAMP_PATTERN.sub(" ", normalized)
    normalized = UUID_PATTERN.sub(" ", normalized)
    normalized = LONG_ID_PATTERN.sub(" ", normalized)
    normalized = re.sub(
        r"\b(?:id|msg|message|event|event_id|ref|request|request_id|trace|trace_id)[:=_#-]?[a-f0-9]{6,}\b",
        " ",
        normalized,
        flags=re.IGNORECASE,
    )
    normalized = WHITESPACE_PATTERN.sub(" ", normalized)
    return normalized.strip()


def build_canonical_event_signature(
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
    canonical_text = canonicalize_event_text(f"{title} {text}")
    dominant_tokens = _tokenize(canonical_text)[:16]
    signature_basis = [
        str(query or "").strip().lower(),
        str(source or "").strip().lower(),
        str(channel_hint or "").strip().lower(),
        "|".join(sorted(item.lower() for item in matched_indicators[:8])),
        "|".join(sorted(item.lower() for item in source_locations[:4])),
        "|".join(dominant_tokens),
    ]
    return hashlib.sha256("::".join(signature_basis).encode("utf-8")).hexdigest()[:24]


def similarity_score(left: str, right: str) -> float:
    left_tokens = set(_tokenize(canonicalize_event_text(left)))
    right_tokens = set(_tokenize(canonicalize_event_text(right)))
    if not left_tokens or not right_tokens:
        return 0.0
    return round(len(left_tokens.intersection(right_tokens)) / len(left_tokens.union(right_tokens)), 4)


def _tokenize(text: str) -> list[str]:
    return [
        token
        for token in TOKEN_PATTERN.findall(str(text or ""))
        if token and len(token) > 2 and token not in STOPWORD_BLACKLIST
    ]


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


__all__ = [
    "NoiseFilterResult",
    "assess_noise",
    "build_canonical_event_signature",
    "canonicalize_event_text",
    "similarity_score",
]
