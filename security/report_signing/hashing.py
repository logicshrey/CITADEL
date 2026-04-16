from __future__ import annotations

import hashlib


def compute_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def compute_sha256_string(text: str) -> str:
    return compute_sha256(text.encode("utf-8"))
