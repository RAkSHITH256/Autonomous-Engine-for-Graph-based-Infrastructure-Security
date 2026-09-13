from typing import Any

from pydantic import BaseModel, Field


class Asset(BaseModel):
    asset_id: str = Field(..., description="Unique identifier for the asset")
    asset_type: str = Field(..., description="Type of infrastructure or resource")
    name: str = Field(..., description="Name of the asset")
    namespace: str | None = Field(
        default=None,
        description="Kubernetes namespace, if applicable",
    )
    environment: str = Field(
        default="unknown",
        description="Environment where the asset exists",
    )
    metadata: dict[str, Any] = Field(default_factory=dict)