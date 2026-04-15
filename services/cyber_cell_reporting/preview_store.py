from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from utils.config import CYBER_CELL_PREVIEW_TTL_SECONDS


def _now() -> datetime:
    return datetime.now(timezone.utc)


def build_request_fingerprint(payload: dict[str, Any]) -> str:
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class PreviewStore:
    def __init__(self, ttl_seconds: int = CYBER_CELL_PREVIEW_TTL_SECONDS) -> None:
        self.ttl_seconds = ttl_seconds
        self._lock = threading.RLock()
        self._previews: dict[str, dict[str, Any]] = {}

    def _purge_expired(self) -> None:
        cutoff = _now()
        expired = [preview_id for preview_id, record in self._previews.items() if record["expires_at"] <= cutoff]
        for preview_id in expired:
            self._previews.pop(preview_id, None)

    def create(self, *, fingerprint: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._purge_expired()
            preview_id = f"preview_{uuid.uuid4().hex[:12]}"
            record = {
                "preview_id": preview_id,
                "fingerprint": fingerprint,
                "payload": payload,
                "generated_at": _now(),
                "expires_at": _now() + timedelta(seconds=max(60, int(self.ttl_seconds))),
            }
            self._previews[preview_id] = record
            return {
                "preview_id": preview_id,
                "generated_at": record["generated_at"].isoformat(),
                "expires_at": record["expires_at"].isoformat(),
            }

    def validate(self, *, preview_id: str, fingerprint: str) -> dict[str, Any]:
        with self._lock:
            self._purge_expired()
            record = self._previews.get(preview_id)
            if record is None:
                raise ValueError("Preview session is missing or has expired.")
            if record["fingerprint"] != fingerprint:
                raise ValueError("Preview session does not match the current reporting request.")
            return {
                "preview_id": record["preview_id"],
                "generated_at": record["generated_at"].isoformat(),
                "expires_at": record["expires_at"].isoformat(),
                "payload": dict(record["payload"]),
            }
