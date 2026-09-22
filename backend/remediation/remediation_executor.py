from typing import Any
from datetime import datetime, UTC


class RemediationExecutor:

    def __init__(
        self,
        dry_run: bool = True,
        simulate_success: bool = False,
    ):
        """
        Execute or simulate remediation actions.

        dry_run:
            Prevents real system changes.

        simulate_success:
            Simulates a successful remediation without
            modifying the real system.

        Both are safe for development and testing.
        """

        self.dry_run = dry_run
        self.simulate_success = simulate_success

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

        timestamp = datetime.now(UTC).isoformat()

        # =========================================================
        # 1. Approval check
        # =========================================================

        if not approved:

            return {
                "status": "PENDING_APPROVAL",
                "executed": False,
                "dry_run": self.dry_run,
                "simulated": False,
                "vulnerability": vulnerability,
                "action": action,
                "priority": priority,
                "message": (
                    "Remediation requires explicit approval "
                    "before execution."
                ),
                "timestamp": timestamp,
            }

        # =========================================================
        # 2. Package upgrade
        # =========================================================

        if action == "UPGRADE_PACKAGE":

            # -----------------------------------------------------
            # Fixed version validation
            # -----------------------------------------------------

            if not fixed_version:

                return {
                    "status": "FAILED",
                    "executed": False,
                    "dry_run": self.dry_run,
                    "simulated": False,
                    "vulnerability": vulnerability,
                    "action": action,
                    "package": package,
                    "installed_version": installed_version,
                    "fixed_version": fixed_version,
                    "priority": priority,
                    "message": (
                        "Cannot execute package upgrade because "
                        "no fixed version was provided."
                    ),
                    "timestamp": timestamp,
                }

            # -----------------------------------------------------
            # Simulation mode
            # -----------------------------------------------------

            if self.simulate_success:

                return {
                    "status": "EXECUTED",
                    "executed": True,
                    "dry_run": True,
                    "simulated": True,
                    "vulnerability": vulnerability,
                    "action": action,
                    "package": package,
                    "previous_version": installed_version,
                    "installed_version": installed_version,
                    "fixed_version": fixed_version,
                    "current_version": fixed_version,
                    "priority": priority,
                    "message": (
                        f"Simulated successful upgrade of "
                        f"{package} from "
                        f"{installed_version} to "
                        f"{fixed_version}."
                    ),
                    "timestamp": timestamp,
                }

            # -----------------------------------------------------
            # Normal dry-run
            # -----------------------------------------------------

            if self.dry_run:

                return {
                    "status": "DRY_RUN",
                    "executed": False,
                    "dry_run": True,
                    "simulated": False,
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
                    "timestamp": timestamp,
                }

            # -----------------------------------------------------
            # Real execution intentionally disabled
            # -----------------------------------------------------

            return {
                "status": "READY_FOR_EXECUTION",
                "executed": False,
                "dry_run": False,
                "simulated": False,
                "vulnerability": vulnerability,
                "action": action,
                "package": package,
                "installed_version": installed_version,
                "fixed_version": fixed_version,
                "priority": priority,
                "message": (
                    f"Validated upgrade of {package} from "
                    f"{installed_version} to "
                    f"{fixed_version}. "
                    "Real package execution is disabled."
                ),
                "timestamp": timestamp,
            }

        # =========================================================
        # 3. Unsupported action
        # =========================================================

        return {
            "status": "UNSUPPORTED_ACTION",
            "executed": False,
            "dry_run": self.dry_run,
            "simulated": False,
            "vulnerability": vulnerability,
            "action": action,
            "priority": priority,
            "message": (
                f"Remediation action '{action}' "
                "is not supported."
            ),
            "timestamp": timestamp,
        }