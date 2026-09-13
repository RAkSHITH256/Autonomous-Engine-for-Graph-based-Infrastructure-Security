from typing import Any

from pydantic import BaseModel, Field


class Remediation(BaseModel):
    remediation_id: str = Field(
        ...,
        description="Unique identifier for the remediation",
    )
    target_asset_id: str = Field(
        ...,
        description="Asset that the remediation targets",
    )
    strategy: str = Field(
        ...,
        description="Remediation strategy",
    )
    reason: str = Field(
        ...,
        description="Why this remediation was selected",
    )
    security_gain: str = Field(
        ...,
        description="Expected security improvement",
    )
    availability_impact: str = Field(
        ...,
        description="Expected impact on availability",
    )
    change_risk: str = Field(
        ...,
        description="Risk associated with making the change",
    )
    execution_mode: str = Field(
        ...,
        description="AUTO, APPROVAL, or PR",
    )
    status: str = Field(
        default="PROPOSED",
        description="Current remediation status",
    )
    verification_result: str | None = Field(
        default=None,
        description="Result of remediation verification",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)
