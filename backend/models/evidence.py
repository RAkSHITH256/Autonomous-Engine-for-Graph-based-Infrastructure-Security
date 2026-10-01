from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Evidence:
    evidence_id: str
    source: str
    raw_data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityEvidence:
    """
    Represents security evidence collected by AEGIS
    from scanners such as Trivy, Semgrep, and SBOM.
    """

    evidence_id: str
    source: str
    evidence_type: str
    timestamp: datetime
    raw_data: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)