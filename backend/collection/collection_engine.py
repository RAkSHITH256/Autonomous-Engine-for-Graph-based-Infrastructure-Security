from typing import Any

from backend.correlation.sbom_finding_adapter import SBOMFindingAdapter
from backend.models.finding import Finding


class CollectionEngine:
    """
    Unified AEGIS collection layer.

    Combines findings from:
        - Trivy
        - Semgrep
        - SBOM

    into one normalized Finding collection.
    """

    def __init__(self):
        self.sbom_adapter = SBOMFindingAdapter()

    def collect(
        self,
        trivy_findings: list[Finding] | None = None,
        semgrep_findings: list[Finding] | None = None,
        sbom_dependencies: list[dict[str, Any]] | None = None,
        asset_id: str | None = None,
    ) -> list[Finding]:

        findings: list[Finding] = []

        # ---------------------------------------------------------
        # Trivy
        # ---------------------------------------------------------

        if trivy_findings:
            findings.extend(trivy_findings)

        # ---------------------------------------------------------
        # Semgrep
        # ---------------------------------------------------------

        if semgrep_findings:
            findings.extend(semgrep_findings)

        # ---------------------------------------------------------
        # SBOM
        # ---------------------------------------------------------

        if sbom_dependencies:

            if not asset_id:
                raise ValueError(
                    "asset_id is required when collecting SBOM dependencies"
                )

            sbom_findings = self.sbom_adapter.to_findings(
                dependencies=sbom_dependencies,
                asset_id=asset_id,
            )

            findings.extend(sbom_findings)

        return findings
