from backend.models.risk import RiskScore


class DecisionEngine:

    def decide(self, risk: RiskScore) -> dict:
        """
        Convert a calculated RiskScore into an operational decision.
        """

        if risk.level == "CRITICAL":
            return {
                "action": "IMMEDIATE_REMEDIATION",
                "priority": "P0",
                "automated": True,
                "reason": (
                    "Critical risk detected. "
                    "Immediate remediation is required."
                ),
            }

        if risk.level == "HIGH":
            return {
                "action": "PRIORITIZE_REMEDIATION",
                "priority": "P1",
                "automated": False,
                "reason": (
                    "High risk detected. "
                    "Remediation should be prioritized."
                ),
            }

        if risk.level == "MEDIUM":
            return {
                "action": "SCHEDULE_REMEDIATION",
                "priority": "P2",
                "automated": False,
                "reason": (
                    "Medium risk detected. "
                    "Remediation should be scheduled."
                ),
            }

        return {
            "action": "MONITOR",
            "priority": "P3",
            "automated": False,
            "reason": (
                "Low risk detected. "
                "Continue monitoring."
            ),
        }
