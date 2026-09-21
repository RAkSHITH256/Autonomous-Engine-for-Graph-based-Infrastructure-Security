from typing import Any


class RemediationEngine:

    def generate_recommendation(
        self,
        vulnerability: dict[str, Any],
        decision: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Generate a remediation recommendation from a vulnerability
        and the decision produced by the Decision Engine.
        """

        severity = vulnerability.get("severity", "UNKNOWN").upper()
        package = vulnerability.get("package", "UNKNOWN")
        installed_version = vulnerability.get(
            "installed_version",
            "UNKNOWN",
        )
        fixed_version = vulnerability.get(
            "fixed_version",
            "",
        )
        identifier = vulnerability.get(
            "identifier",
            "UNKNOWN",
        )

        action = decision.get(
            "action",
            "MONITOR",
        )

        priority = decision.get(
            "priority",
            "P3",
        )

        # ---------------------------------------------------------
        # Determine remediation action
        # ---------------------------------------------------------

        if fixed_version:
            remediation_action = "UPGRADE_PACKAGE"

            command = (
                f"Upgrade {package} from "
                f"{installed_version} to {fixed_version}."
            )

            recommendation = (
                f"Upgrade {package} to fixed version "
                f"{fixed_version} to remediate {identifier}."
            )

        else:
            remediation_action = "INVESTIGATE_OR_REPLACE"

            command = (
                f"Investigate {package} and identify a "
                f"patched or replacement version."
            )

            recommendation = (
                f"No fixed version is currently available for "
                f"{identifier}. Investigate a patched release "
                f"or replace the affected package."
            )

        # ---------------------------------------------------------
        # Emergency handling
        # ---------------------------------------------------------

        if action == "IMMEDIATE_REMEDIATION":
            urgency = "IMMEDIATE"

        elif action == "PRIORITIZE_REMEDIATION":
            urgency = "HIGH"

        elif action == "SCHEDULE_REMEDIATION":
            urgency = "SCHEDULED"

        else:
            urgency = "LOW"

        return {
            "vulnerability": identifier,
            "severity": severity,
            "package": package,
            "installed_version": installed_version,
            "fixed_version": fixed_version,
            "decision": action,
            "priority": priority,
            "urgency": urgency,
            "remediation_action": remediation_action,
            "recommendation": recommendation,
            "command": command,
            "automated_execution": False,
        }
