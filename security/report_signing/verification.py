from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from utils.config import REPORT_PUBLIC_KEY_PATH


def build_signed_payload_bytes(payload: dict[str, Any]) -> bytes:
    normalized = {key: value for key, value in payload.items() if value is not None}
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _load_public_key(public_key_path: Path | None = None, public_key_pem: bytes | None = None) -> Any:
    from cryptography.hazmat.primitives import serialization

    if public_key_pem is not None:
        return serialization.load_pem_public_key(public_key_pem)
    resolved_path = Path(public_key_path or REPORT_PUBLIC_KEY_PATH)
    return serialization.load_pem_public_key(resolved_path.read_bytes())


def verify_signature(
    payload_bytes: bytes,
    signature_base64: str | None,
    *,
    public_key_path: Path | None = None,
    public_key_pem: bytes | None = None,
    algorithm: str | None = None,
) -> bool:
    if not signature_base64:
        return False
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

    public_key = _load_public_key(public_key_path=public_key_path, public_key_pem=public_key_pem)
    signature = base64.b64decode(signature_base64)
    if isinstance(public_key, ed25519.Ed25519PublicKey) or str(algorithm or "").upper() == "ED25519":
        public_key.verify(signature, payload_bytes)
        return True
    if isinstance(public_key, rsa.RSAPublicKey) or "RSA" in str(algorithm or "").upper():
        public_key.verify(signature, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
        return True
    return False
