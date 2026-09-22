from typing import Any


class RemediationPlanner:

    def plan(
        self,
        vulnerability: dict[str, Any],
        decision: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Convert a DecisionEngine decision and vulnerability
        into a standardized remediation plan.
        """

        action = decision.get("action", "MONITOR")
        priority = decision.get("priority", "P3")
        automated = decision.get("automated", False)
        reason = decision.get("reason", "")

        vulnerability_id = vulnerability.get(
            "identifier",
            vulnerability.get(
                "vulnerability_id",
                vulnerability.get("VulnerabilityID", "UNKNOWN"),
            ),
        )

        package = vulnerability.get(
            "package",
            vulnerability.get(
                "PkgName",
                "UNKNOWN",
            ),
        )

        installed_version = vulnerability.get(
            "installed_version",
            vulnerability.get(
                "InstalledVersion",
                "UNKNOWN",
            ),
        )

        fixed_version = vulnerability.get(
            "fixed_version",
            vulnerability.get(
                "FixedVersion",
                "",
            ),
        )

        # ---------------------------------------------------------
        # Determine remediation action
        # ---------------------------------------------------------

        if action in (
            "IMMEDIATE_REMEDIATION",
            "PRIORITIZE_REMEDIATION",
            "SCHEDULE_REMEDIATION",
        ):

            if fixed_version:
                remediation_action = "UPGRADE_PACKAGE"
            else:
                remediation_action = "UNKNOWN"

        else:
            remediation_action = "MONITOR"

        # ---------------------------------------------------------
        # Build remediation plan
        # ---------------------------------------------------------

        return {
            "vulnerability": vulnerability_id,
            "remediation_action": remediation_action,
            "package": package,
            "installed_version": installed_version,
            "fixed_version": fixed_version,
            "priority": priority,
            "automated": automated,
            "decision": action,
            "reason": reason,
        }