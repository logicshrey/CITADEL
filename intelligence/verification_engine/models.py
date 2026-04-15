from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    verification_badge: str = "WEAK_SIGNAL"
    verification_score: int = 0
    verification_reasons: list[str] = Field(default_factory=list)
