from typing import Any
from datetime import datetime


class RemediationExecutor:

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    def execute(
        self,
        remediation: dict[str, Any],
        approved: bool = False,
    ) -> dict[str, Any]:

        vulnerability = remediation.get(
            "vulnerability",
            "UNKNOWN",
        )

        action = remediation.get(
            "remediation_action",
            "UNKNOWN",
        )

        package = remediation.get(
            "package",
            "UNKNOWN",
        )

        installed_version = remediation.get(
            "installed_version",
            "UNKNOWN",
        )

        fixed_version = remediation.get(
            "fixed_version",
            "",
        )

        priority = remediation.get(
            "priority",
            "P3",
        )

        # Safety: require approval
        if not approved:
            return {
                "status": "PENDING_APPROVAL",
                "executed": False,
                "dry_run": self.dry_run,
                "vulnerability": vulnerability,
                "action": action,
                "priority": priority,
                "message": (
                    "Remediation requires explicit approval "
                    "before execution."
                ),
                "timestamp": datetime.utcnow().isoformat(),
            }

        # Safe testing mode
        if self.dry_run:
            return {
                "status": "DRY_RUN",
                "executed": False,
                "dry_run": True,
                "vulnerability": vulnerability,
                "action": action,
                "package": package,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "priority": priority,
                "message": (
                    f"Would upgrade {package} from "
                    f"{installed_version} to "
                    f"{fixed_version}."
                ),
                "timestamp": datetime.utcnow().isoformat(),
            }

        # Validate package upgrade
        if action == "UPGRADE_PACKAGE":

            if not fixed_version:
                return {
                    "status": "FAILED",
                    "executed": False,
                    "dry_run": False,
                    "vulnerability": vulnerability,
                    "action": action,
                    "message": (
                        "Cannot execute package upgrade because "
                        "no fixed version was provided."
                    ),
                    "timestamp": datetime.utcnow().isoformat(),
                }

            return {
                "status": "READY_FOR_EXECUTION",
                "executed": False,
                "dry_run": False,
                "vulnerability": vulnerability,
                "action": action,
                "package": package,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "priority": priority,
                "message": (
                    f"Validated upgrade of {package} from "
                    f"{installed_version} to {fixed_version}. "
                    "Real execution is disabled."
                ),
                "timestamp": datetime.utcnow().isoformat(),
            }

        return {
            "status": "UNSUPPORTED_ACTION",
            "executed": False,
            "dry_run": self.dry_run,
            "vulnerability": vulnerability,
            "action": action,
            "message": (
                f"Remediation action '{action}' "
                "is not supported."
            ),
            "timestamp": datetime.utcnow().isoformat(),
        }
