from typing import Any


class ReassessmentEngine:

    def reassess(
        self,
        vulnerability: dict[str, Any],
        verification: dict[str, Any],
        current_risk: Any,
    ) -> dict[str, Any]:
        """
        Determine whether remediation resolved the vulnerability.

        This version is intentionally simulation-safe.
        It does not modify the real system.
        """

        identifier = vulnerability.get(
            "identifier",
            "UNKNOWN",
        )

        package = vulnerability.get(
            "package",
            "UNKNOWN",
        )

        installed_version = vulnerability.get(
            "installed_version",
            "",
        )

        fixed_version = vulnerability.get(
            "fixed_version",
            "",
        )

        verification_status = verification.get(
            "status",
            "UNKNOWN",
        )

        verified = verification.get(
            "verified",
            False,
        )

        # ---------------------------------------------------------
        # 1. Successfully verified remediation
        # ---------------------------------------------------------

        if (
            verification_status == "RESOLVED"
            and verified
        ):
            return {
                "status": "RESOLVED",
                "vulnerability": identifier,
                "package": package,
                "previous_version": installed_version,
                "current_version": fixed_version,
                "previous_risk": current_risk.score,
                "current_risk": 0,
                "risk_level": "RESOLVED",
                "action": "CLOSE_FINDING",
                "message": (
                    f"{identifier} was successfully remediated. "
                    f"{package} is now at fixed version "
                    f"{fixed_version}."
                ),
            }

        # ---------------------------------------------------------
        # 2. Remediation has not been executed
        # ---------------------------------------------------------

        if verification_status == "NOT_VERIFIED":
            return {
                "status": "WAITING",
                "vulnerability": identifier,
                "package": package,
                "previous_version": installed_version,
                "current_version": installed_version,
                "previous_risk": current_risk.score,
                "current_risk": current_risk.score,
                "risk_level": current_risk.level,
                "action": "WAIT_FOR_REMEDIATION",
                "message": (
                    "Remediation has not been executed. "
                    "The vulnerability remains open."
                ),
            }

        # ---------------------------------------------------------
        # 3. Verification failed
        # ---------------------------------------------------------

        return {
            "status": "REASSESS_REQUIRED",
            "vulnerability": identifier,
            "package": package,
            "previous_version": installed_version,
            "current_version": installed_version,
            "previous_risk": current_risk.score,
            "current_risk": current_risk.score,
            "risk_level": current_risk.level,
            "action": "REASSESS_RISK",
            "message": (
                f"Remediation verification failed for "
                f"{identifier}. Reassessment is required."
            ),
        }