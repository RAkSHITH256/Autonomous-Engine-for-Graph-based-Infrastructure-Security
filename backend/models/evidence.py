from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SecurityEvidence(BaseModel):
    evidence_id: str = Field(..., description="Unique identifier for this evidence")
    source: str = Field(..., description="Tool or system that produced the evidence")
    evidence_type: str = Field(..., description="Type of security evidence")
    timestamp: datetime = Field(..., description="Time when the evidence was collected")
    raw_data: dict[str, Any] = Field(..., description="Original evidence data")
    metadata: dict[str, Any] = Field(default_factory=dict)