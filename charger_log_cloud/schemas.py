from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class JobResponse(BaseModel):
    id: str
    created_at: datetime
    updated_at: datetime
    created_by: str
    status: Literal["queued", "running", "succeeded", "failed"]
    original_name: str
    request: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class FeedbackRequest(BaseModel):
    verdict: Literal["correct", "partially_correct", "incorrect", "inconclusive"]
    corrected_domains: list[str] = Field(default_factory=list)
    corrected_root_cause_category: str = ""
    corrected_summary: str = ""
    evidence_event_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class FeedbackResponse(BaseModel):
    id: str
    job_id: str
    created_at: datetime
    created_by: str
    verdict: str
    review_status: str
    payload: dict[str, Any]


class HealthResponse(BaseModel):
    status: str
    version: str
