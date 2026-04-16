from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from utils.config import (
    REPORT_PRIVATE_KEY_PATH,
    REPORT_PUBLIC_KEY_PATH,
    REPORT_SIGNING_DEV_AUTO_GENERATE,
    REPORT_SIGNING_ENABLED,
    REPORT_VERIFICATION_BASE_URL,
)


def _is_production_environment() -> bool:
    environment = str(os.getenv("ENVIRONMENT") or os.getenv("ENV") or "").strip().lower()
    return environment in {"prod", "production"}


def build_verification_url(report_id: str) -> str:
    base_url = REPORT_VERIFICATION_BASE_URL.rstrip("/")
    return f"{base_url}/verify/{report_id}"


def mask_value(value: str | None, *, prefix: int = 12, suffix: int = 8) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        return ""
    if len(normalized) <= prefix + suffix:
        return normalized
    return f"{normalized[:prefix]}...{normalized[-suffix:]}"


@dataclass
class KeyMaterial:
    algorithm: str
    private_key: Any
    public_key: Any
    private_key_path: Path
    public_key_path: Path


def _crypto_modules() -> tuple[Any, Any, Any, Any, Any]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

    return ed25519, hashes, padding, rsa, serialization


def _write_key_files(private_key_path: Path, public_key_path: Path, private_bytes: bytes, public_bytes: bytes) -> None:
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.write_bytes(private_bytes)
    public_key_path.write_bytes(public_bytes)


def _generate_ed25519_keypair(private_key_path: Path, public_key_path: Path) -> KeyMaterial:
    ed25519, _, _, _, serialization = _crypto_modules()
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_key_files(private_key_path, public_key_path, private_bytes, public_bytes)
    return KeyMaterial(
        algorithm="Ed25519",
        private_key=private_key,
        public_key=public_key,
        private_key_path=private_key_path,
        public_key_path=public_key_path,
    )


def _load_existing_keys(private_key_path: Path, public_key_path: Path) -> KeyMaterial:
    ed25519, _, _, rsa, serialization = _crypto_modules()
    private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    algorithm = "RSA-SHA256"
    if isinstance(private_key, ed25519.Ed25519PrivateKey) and isinstance(public_key, ed25519.Ed25519PublicKey):
        algorithm = "Ed25519"
    elif isinstance(private_key, rsa.RSAPrivateKey):
        algorithm = "RSA-SHA256"
    return KeyMaterial(
        algorithm=algorithm,
        private_key=private_key,
        public_key=public_key,
        private_key_path=private_key_path,
        public_key_path=public_key_path,
    )


def _resolve_key_material() -> KeyMaterial:
    private_key_path = Path(REPORT_PRIVATE_KEY_PATH)
    public_key_path = Path(REPORT_PUBLIC_KEY_PATH)
    if private_key_path.exists() and public_key_path.exists():
        return _load_existing_keys(private_key_path, public_key_path)
    if REPORT_SIGNING_DEV_AUTO_GENERATE and not _is_production_environment():
        return _generate_ed25519_keypair(private_key_path, public_key_path)
    missing_parts = []
    if not private_key_path.exists():
        missing_parts.append(str(private_key_path))
    if not public_key_path.exists():
        missing_parts.append(str(public_key_path))
    raise FileNotFoundError(f"Missing report signing key material: {', '.join(missing_parts)}")


def public_key_fingerprint(public_key: Any) -> str:
    _, _, _, _, serialization = _crypto_modules()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    from security.report_signing.hashing import compute_sha256

    return compute_sha256(public_bytes)


def get_signing_runtime_status() -> dict[str, Any]:
    status = {
        "enabled": REPORT_SIGNING_ENABLED,
        "available": False,
        "algorithm": None,
        "public_key_fingerprint": None,
        "warning": None,
    }
    if not REPORT_SIGNING_ENABLED:
        status["warning"] = "Report signing is disabled."
        return status
    try:
        material = _resolve_key_material()
        status["available"] = True
        status["algorithm"] = material.algorithm
        status["public_key_fingerprint"] = public_key_fingerprint(material.public_key)
        return status
    except Exception as exc:
        status["warning"] = str(exc)
        return status


def sign_report_payload(payload_bytes: bytes) -> dict[str, Any]:
    if not REPORT_SIGNING_ENABLED:
        return {
            "enabled": False,
            "signed": False,
            "algorithm": None,
            "signature_base64": None,
            "public_key_fingerprint": None,
            "warning": "Report signing is disabled.",
        }
    try:
        ed25519, hashes, padding, rsa, _ = _crypto_modules()
        material = _resolve_key_material()
        if isinstance(material.private_key, ed25519.Ed25519PrivateKey):
            signature = material.private_key.sign(payload_bytes)
        elif isinstance(material.private_key, rsa.RSAPrivateKey):
            signature = material.private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise TypeError("Unsupported private key type for report signing.")
        return {
            "enabled": True,
            "signed": True,
            "algorithm": material.algorithm,
            "signature_base64": base64.b64encode(signature).decode("ascii"),
            "public_key_fingerprint": public_key_fingerprint(material.public_key),
            "warning": None,
        }
    except Exception as exc:
        return {
            "enabled": True,
            "signed": False,
            "algorithm": None,
            "signature_base64": None,
            "public_key_fingerprint": None,
            "warning": str(exc),
        }
