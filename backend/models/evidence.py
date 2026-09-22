from dataclasses import dataclass, field
from typing import Any


@dataclass
class Evidence:
    evidence_id: str
    source: str
    raw_data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)