from typing import Any


class VerificationEngine:

    def verify(
        self,
        vulnerability: dict[str, Any],
        remediation: dict[str, Any],
    ) -> dict[str, Any]:

        identifier = vulnerability.get(
            "identifier",
            "UNKNOWN",
        )

        package = vulnerability.get(
            "package",
            "UNKNOWN",
        )

        current_version = vulnerability.get(
            "installed_version",
            "UNKNOWN",
        )

        fixed_version = vulnerability.get(
            "fixed_version",
            "",
        )

        remediation_status = remediation.get(
            "status",
            "UNKNOWN",
        )

        # ---------------------------------------------------------
        # Remediation was not executed
        # ---------------------------------------------------------

        if remediation_status in {
            "DRY_RUN",
            "PENDING_APPROVAL",
            "READY_FOR_EXECUTION",
        }:

            return {
                "status": "NOT_VERIFIED",
                "verified": False,
                "vulnerability": identifier,
                "package": package,
                "current_version": current_version,
                "fixed_version": fixed_version,
                "reason": (
                    "Remediation has not been executed. "
                    "Verification cannot confirm that the "
                    "vulnerability has been resolved."
                ),
            }

        # ---------------------------------------------------------
        # Failed remediation
        # ---------------------------------------------------------

        if remediation_status == "FAILED":

            return {
                "status": "VERIFICATION_FAILED",
                "verified": False,
                "vulnerability": identifier,
                "package": package,
                "current_version": current_version,
                "fixed_version": fixed_version,
                "reason": (
                    "Remediation execution failed. "
                    "The vulnerability remains unresolved."
                ),
            }

        # ---------------------------------------------------------
        # Verify successful upgrade
        # ---------------------------------------------------------

        if remediation_status == "EXECUTED":

            if (
                fixed_version
                and current_version == fixed_version
            ):

                return {
                    "status": "RESOLVED",
                    "verified": True,
                    "vulnerability": identifier,
                    "package": package,
                    "current_version": current_version,
                    "fixed_version": fixed_version,
                    "reason": (
                        f"{package} is running the fixed version "
                        f"{fixed_version}. "
                        f"{identifier} is considered resolved."
                    ),
                }

            return {
                "status": "VERIFICATION_FAILED",
                "verified": False,
                "vulnerability": identifier,
                "package": package,
                "current_version": current_version,
                "fixed_version": fixed_version,
                "reason": (
                    "The installed version does not match "
                    "the expected fixed version."
                ),
            }

        # ---------------------------------------------------------
        # Unknown state
        # ---------------------------------------------------------

        return {
            "status": "UNKNOWN",
            "verified": False,
            "vulnerability": identifier,
            "package": package,
            "current_version": current_version,
            "fixed_version": fixed_version,
            "reason": (
                f"Unknown remediation status: "
                f"{remediation_status}"
            ),
        }
