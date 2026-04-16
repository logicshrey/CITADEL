from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from typing import Any

from utils.config import REPORT_VERIFICATION_CACHE_TTL_SECONDS


class VerificationResponseCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, dict[str, Any]] = {}

    def get(self, report_id: str) -> dict[str, Any] | None:
        with self._lock:
            entry = self._entries.get(report_id)
            if entry is None:
                return None
            if entry["expires_at"] <= datetime.now(timezone.utc):
                self._entries.pop(report_id, None)
                return None
            return dict(entry["value"])

    def set(self, report_id: str, value: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._entries[report_id] = {
                "value": dict(value),
                "expires_at": datetime.now(timezone.utc) + timedelta(seconds=REPORT_VERIFICATION_CACHE_TTL_SECONDS),
            }
        return dict(value)

    def invalidate(self, report_id: str) -> None:
        with self._lock:
            self._entries.pop(report_id, None)


verification_response_cache = VerificationResponseCache()
