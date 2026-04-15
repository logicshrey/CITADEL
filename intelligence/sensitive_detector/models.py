from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class SensitiveFinding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    finding_type: str
    masked_value: str
    source_evidence_id: str | None = None
    source_index: int | None = None
    risk_weight: int = 0


class SensitiveDetectionResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    sensitive_types: list[str] = Field(default_factory=list)
    matched_samples: list[SensitiveFinding] = Field(default_factory=list)
    risk_score_addition: int = 0
    detection_reasons: list[str] = Field(default_factory=list)
