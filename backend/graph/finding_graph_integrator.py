from typing import Any

from backend.correlation.correlation_engine import CorrelationEngine
from backend.graph.graph_builder import GraphBuilder
from backend.models.asset import Asset
from backend.models.finding import Finding


class FindingGraphIntegrator:
    """
    Connects normalized AEGIS security findings to the
    infrastructure security graph.

    Flow:

        Finding[]
            ↓
        CorrelationEngine
            ↓
        Asset
            ↓
        GraphBuilder
            ↓
        Neo4j
    """

    def __init__(
        self,
        graph_builder: GraphBuilder,
    ):
        self.graph_builder = graph_builder
        self.correlation_engine = CorrelationEngine()

    # =========================================================
    # CORRELATE FINDINGS
    # =========================================================

    def correlate(
        self,
        findings: list[Finding],
        assets: list[Asset],
    ) -> dict[str, Asset]:
        """
        Match normalized findings to known infrastructure assets.
        """

        return self.correlation_engine.correlate_findings(
            findings=findings,
            assets=assets,
        )

    # =========================================================
    # STORE CORRELATIONS
    # =========================================================

    def store(
        self,
        correlations: dict[str, Asset],
        findings: list[Finding],
    ) -> None:
        """
        Store correlated findings and vulnerabilities in Neo4j.
        """

        self.correlation_engine.store_correlations(
            correlations=correlations,
            findings=findings,
            client=self.graph_builder.client,
        )

    # =========================================================
    # BUILD GRAPH FROM FINDINGS
    # =========================================================

    def integrate(
        self,
        findings: list[Finding],
        assets: list[Asset],
    ) -> dict[str, Any]:
        """
        Correlate findings with infrastructure assets and
        persist the resulting security relationships.

        Returns a summary of the integration.
        """

        correlations = self.correlate(
            findings=findings,
            assets=assets,
        )

        self.store(
            correlations=correlations,
            findings=findings,
        )

        unmatched = [
            finding.finding_id
            for finding in findings
            if finding.finding_id not in correlations
        ]

        return {
            "status": "success",
            "total_findings": len(findings),
            "correlated_findings": len(correlations),
            "unmatched_findings": len(unmatched),
            "correlations": {
                finding_id: asset.asset_id
                for finding_id, asset in correlations.items()
            },
            "unmatched": unmatched,
        }
