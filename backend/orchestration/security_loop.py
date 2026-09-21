from typing import Any

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
        self.decision_engine = DecisionEngine()

        self.remediation_engine = RemediationEngine()

        self.executor = RemediationExecutor(
            dry_run=dry_run,
            simulate_success=simulate_success,
        )

        self.verification_engine = VerificationEngine()

        self.reassessment_engine = ReassessmentEngine()

    def process(
        self,
        vulnerability: dict[str, Any],
        risk: Any,
        approved: bool = False,
    ) -> dict[str, Any]:

        # =========================================================
        # 1. Risk → Decision
        # =========================================================

        decision = self.decision_engine.decide(risk)

        # =========================================================
        # 2. Decision → Remediation
        # =========================================================

        remediation = (
            self.remediation_engine.generate_recommendation(
                vulnerability=vulnerability,
                decision=decision,
            )
        )

        # =========================================================
        # 3. Remediation → Execution
        # =========================================================

        execution = self.executor.execute(
            remediation=remediation,
            approved=approved,
        )

        # =========================================================
        # 4. Execution → Verification
        # =========================================================

        verification = self.verification_engine.verify(
            vulnerability=vulnerability,
            remediation=execution,
        )

        # =========================================================
        # 5. Verification → Reassessment
        # =========================================================

        reassessment = self.reassessment_engine.reassess(
            vulnerability=vulnerability,
            verification=verification,
            current_risk=risk,
        )

        # =========================================================
        # 6. Complete Security Lifecycle
        # =========================================================

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