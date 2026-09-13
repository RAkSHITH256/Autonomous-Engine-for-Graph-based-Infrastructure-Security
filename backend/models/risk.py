from pydantic import BaseModel, Field


class RiskScore(BaseModel):
    score: float = Field(
        ...,
        ge=0,
        le=100,
        description="Contextual risk score from 0 to 100",
    )
    level: str = Field(
        ...,
        description="Risk level",
    )
    factors: dict[str, float] = Field(
        default_factory=dict,
        description="Individual factors contributing to the score",
    )
    explanation: str = Field(
        ...,
        description="Human-readable explanation of the risk",
    )
