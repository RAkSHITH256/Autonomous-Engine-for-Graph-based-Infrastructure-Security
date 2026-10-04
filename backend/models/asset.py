from typing import Any

from pydantic import BaseModel, Field


class Asset(BaseModel):
    asset_id: str
    asset_type: str
    name: str
    namespace: str | None = None
    environment: str = "unknown"
    metadata: dict[str, Any] = Field(default_factory=dict)
