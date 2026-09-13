from typing import Any

from pydantic import BaseModel, Field


class Finding(BaseModel):
    finding_id: str = Field(..., description="Unique identifier for the finding")
    category: str = Field(..., description="Security category of the finding")
    severity: str = Field(..., description="Severity of the finding")
    title: str = Field(..., description="Short description of the security issue")
    description: str = Field(..., description="Detailed explanation of the finding")
    asset_id: str = Field(..., description="ID of the affected asset")
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Evidence IDs supporting this finding",
    )
    status: str = Field(default="OPEN", description="Current finding status")
    metadata: dict[str, Any] = Field(default_factory=dict)