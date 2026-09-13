from pydantic import BaseModel, Field


class AttackPathNode(BaseModel):
    asset_id: str
    asset_type: str
    name: str


class AttackPathEdge(BaseModel):
    source_id: str
    target_id: str
    relationship: str


class AttackPath(BaseModel):
    path_id: str = Field(..., description="Unique identifier for the attack path")
    source: str = Field(..., description="Starting point of the attack path")
    target: str = Field(..., description="Target of the attack path")
    nodes: list[AttackPathNode] = Field(default_factory=list)
    edges: list[AttackPathEdge] = Field(default_factory=list)
    vulnerability_ids: list[str] = Field(default_factory=list)
    exploitability: str = Field(default="UNKNOWN")
    asset_criticality: str = Field(default="UNKNOWN")
    risk_score: float | None = Field(default=None)
    status: str = Field(default="ACTIVE")
