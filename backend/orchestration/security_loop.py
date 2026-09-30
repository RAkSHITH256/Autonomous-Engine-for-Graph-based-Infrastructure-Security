from typing import Any

from backend.collection.collection_engine import CollectionEngine
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

        self.decision_engine = DecisionEngine()
        self.remediation_engine = RemediationEngine()

        self.executor = RemediationExecutor(
            dry_run=dry_run,
            simulate_success=simulate_success,
        )

        self.verification_engine = VerificationEngine()
        self.reassessment_engine = ReassessmentEngine()

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