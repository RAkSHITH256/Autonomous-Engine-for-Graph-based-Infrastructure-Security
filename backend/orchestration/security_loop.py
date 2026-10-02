import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.collection.collection_engine import CollectionEngine

from backend.collectors.trivy.trivy_parser import TrivyParser
from backend.collectors.semgrep.semgrep_parser import parse_semgrep_results
from backend.collectors.sbom.sbom_parser import SBOMParser

from backend.models.evidence import SecurityEvidence

from backend.discovery.docker_discovery import DockerDiscovery

from backend.graph.finding_graph_integrator import (
    FindingGraphIntegrator,
)
from backend.graph.graph_builder import GraphBuilder
from backend.models.asset import Asset

from backend.decision.decision_engine import DecisionEngine
from backend.remediation.remediation_engine import RemediationEngine
from backend.remediation.remediation_executor import RemediationExecutor
from backend.remediation.verification_engine import VerificationEngine
from backend.reassessment.reassessment_engine import ReassessmentEngine


class SecurityLoop:

    def __init__(
        self,
        dry_run: bool = True,
        simulate_success: bool = False,
    ):
        self.collection_engine = CollectionEngine()
        self.graph_integrator = None

        self.decision_engine = DecisionEngine()
        self.remediation_engine = RemediationEngine()

        self.executor = RemediationExecutor(
            dry_run=dry_run,
            simulate_success=simulate_success,
        )

        self.verification_engine = VerificationEngine()
        self.reassessment_engine = ReassessmentEngine()

    # =============================================================
    # GRAPH INTEGRATION
    # =============================================================

    def integrate_findings_with_graph(
        self,
        findings,
        assets: list[Asset],
        graph_builder: GraphBuilder,
    ) -> dict[str, Any]:
        """
        Correlate normalized security findings with known
        infrastructure assets and store the correlations
        in Neo4j.
        """

        self.graph_integrator = FindingGraphIntegrator(
            graph_builder=graph_builder,
        )

        return self.graph_integrator.integrate(
            findings=findings,
            assets=assets,
        )

    # =============================================================
    # DOCKER INFRASTRUCTURE DISCOVERY
    # =============================================================

    def discover_and_import_docker(
        self,
        graph_builder: GraphBuilder,
    ) -> dict[str, Any]:
        """
        Discover the current Docker infrastructure and import it
        into the AEGIS security graph.

        Discovery provides:

            - Docker containers
            - Docker images
            - Container -> image relationships

        The discovered infrastructure is converted into the
        GraphBuilder format and persisted in Neo4j.
        """

        # ---------------------------------------------------------
        # Discover Docker infrastructure
        # ---------------------------------------------------------

        discovery = DockerDiscovery()

        discovery_result = discovery.discover()

        discovered_assets = discovery_result["assets"]

        discovered_relationships = discovery_result[
            "relationships"
        ]

        # ---------------------------------------------------------
        # Convert Asset models to GraphBuilder format
        # ---------------------------------------------------------

        graph_assets = []

        for asset in discovered_assets:

            graph_assets.append(
                {
                    "asset_id": asset.asset_id,
                    "name": asset.name,
                    "type": asset.asset_type,
                    "criticality": asset.metadata.get(
                        "criticality",
                        "UNKNOWN",
                    ),
                    "metadata": asset.metadata,
                }
            )

        # ---------------------------------------------------------
        # Convert relationships to GraphBuilder format
        # ---------------------------------------------------------

        graph_relationships = []

        for relationship in discovered_relationships:

            graph_relationships.append(
                {
                    "source": relationship["source"],
                    "target": relationship["target"],
                    "type": relationship["relationship"],
                }
            )

        # ---------------------------------------------------------
        # Persist infrastructure graph
        # ---------------------------------------------------------

        graph_builder.build_graph(
            assets=graph_assets,
            relationships=graph_relationships,
            vulnerabilities=[],
        )

        # ---------------------------------------------------------
        # Return discovery result
        # ---------------------------------------------------------

        return {
            "status": "success",
            "assets_discovered": len(
                discovered_assets
            ),
            "relationships_discovered": len(
                discovered_relationships
            ),
            "assets": discovered_assets,
            "relationships": discovered_relationships,
        }

    # =============================================================
    # EXISTING SINGLE-VULNERABILITY FLOW
    # =============================================================

    def process(
        self,
        vulnerability: dict[str, Any],
        risk: Any,
        approved: bool = False,
    ) -> dict[str, Any]:

        # 1. Risk → Decision
        decision = self.decision_engine.decide(risk)

        # 2. Decision → Remediation
        remediation = (
            self.remediation_engine.generate_recommendation(
                vulnerability=vulnerability,
                decision=decision,
            )
        )

        # 3. Remediation → Execution
        execution = self.executor.execute(
            remediation=remediation,
            approved=approved,
        )

        # 4. Execution → Verification
        verification = self.verification_engine.verify(
            vulnerability=vulnerability,
            remediation=execution,
        )

        # 5. Verification → Reassessment
        reassessment = self.reassessment_engine.reassess(
            vulnerability=vulnerability,
            verification=verification,
            current_risk=risk,
        )

        return {
            "status": "success",
            "vulnerability": vulnerability,

            "risk": {
                "score": risk.score,
                "level": risk.level,
                "factors": risk.factors,
                "explanation": risk.explanation,
            },

            "decision": decision,
            "remediation": remediation,
            "execution": execution,
            "verification": verification,
            "reassessment": reassessment,

            "loop_status": reassessment["status"],
        }

    # =============================================================
    # REAL CI SECURITY EVIDENCE
    # =============================================================

    def collect_from_ci_reports(
        self,
        reports_dir: str = "security/reports",
        asset_id: str = "aegis-application",
    ) -> dict[str, Any]:
        """
        Load real Trivy, Semgrep and SBOM reports produced by CI.

        Expected files:

            security/reports/
            ├── trivy.json
            ├── semgrep.json
            └── sbom.json

        The reports are parsed and converted into normalized
        AEGIS Finding objects.
        """

        reports_path = Path(reports_dir)

        trivy_path = reports_path / "trivy.json"
        semgrep_path = reports_path / "semgrep.json"
        sbom_path = reports_path / "sbom.json"

        # ---------------------------------------------------------
        # Trivy
        # ---------------------------------------------------------

        trivy_findings = []

        if trivy_path.exists():

            with trivy_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                trivy_data = json.load(file)

            trivy_evidence = SecurityEvidence(
                evidence_id="ci-trivy",
                source="trivy",
                evidence_type="container_vulnerability_scan",
                timestamp=datetime.now(timezone.utc),
                raw_data=trivy_data,
                metadata={
                    "image": asset_id,
                },
            )

            trivy_findings = TrivyParser().parse(
                trivy_evidence
            )

        # ---------------------------------------------------------
        # Semgrep
        # ---------------------------------------------------------

        semgrep_findings = []

        if semgrep_path.exists():

            with semgrep_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                semgrep_data = json.load(file)

            semgrep_findings = parse_semgrep_results(
                semgrep_data,
                asset_id=asset_id,
            )

        # ---------------------------------------------------------
        # SBOM
        # ---------------------------------------------------------

        sbom_dependencies = []

        if sbom_path.exists():

            with sbom_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                sbom_data = json.load(file)

            sbom_dependencies = SBOMParser().parse(
                sbom_data
            )

        # ---------------------------------------------------------
        # Unified AEGIS collection
        # ---------------------------------------------------------

        findings = self.collect_findings(
            trivy_findings=trivy_findings,
            semgrep_findings=semgrep_findings,
            sbom_dependencies=sbom_dependencies,
            asset_id=asset_id,
        )

        # ---------------------------------------------------------
        # Summary
        # ---------------------------------------------------------

        summary = self.collection_summary(
            findings
        )

        return {
            "status": "success",
            "reports_dir": str(reports_path),
            "findings": findings,
            "summary": summary,
        }

    # =============================================================
    # UNIFIED COLLECTION
    # =============================================================

    def collect_findings(
        self,
        trivy_findings=None,
        semgrep_findings=None,
        sbom_dependencies=None,
        asset_id=None,
    ):
        """
        Collect findings from all supported security sources.

        Sources:
            Trivy
            Semgrep
            SBOM
        """

        return self.collection_engine.collect(
            trivy_findings=trivy_findings,
            semgrep_findings=semgrep_findings,
            sbom_dependencies=sbom_dependencies,
            asset_id=asset_id,
        )

    # =============================================================
    # COLLECTION SUMMARY
    # =============================================================

    def collection_summary(
        self,
        findings,
    ) -> dict[str, Any]:
        """
        Generate a simple summary of unified findings.
        """

        summary = {
            "total": len(findings),
            "sources": {},
            "severities": {},
        }

        for finding in findings:

            source = finding.metadata.get(
                "source",
                "UNKNOWN",
            )

            severity = finding.severity.upper()

            summary["sources"][source] = (
                summary["sources"].get(source, 0) + 1
            )

            summary["severities"][severity] = (
                summary["severities"].get(severity, 0) + 1
            )

        return summary

    # =============================================================
    # COMPLETE COLLECTION ENTRY POINT
    # =============================================================

    def collect_and_summarize(
        self,
        trivy_findings=None,
        semgrep_findings=None,
        sbom_dependencies=None,
        asset_id=None,
    ) -> dict[str, Any]:
        """
        Collect all security findings and return a normalized
        collection result.
        """

        findings = self.collect_findings(
            trivy_findings=trivy_findings,
            semgrep_findings=semgrep_findings,
            sbom_dependencies=sbom_dependencies,
            asset_id=asset_id,
        )

        summary = self.collection_summary(
            findings
        )

        return {
            "status": "success",
            "findings": findings,
            "summary": summary,
        }