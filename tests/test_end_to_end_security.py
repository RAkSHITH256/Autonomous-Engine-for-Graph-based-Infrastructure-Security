from backend.risk.risk_engine import assess_risk
from backend.decision.decision_engine import DecisionEngine
from backend.remediation.remediation_planner import RemediationPlanner
from backend.remediation.remediation_executor import RemediationExecutor


def make_vulnerability():
    return {
        "identifier": "CVE-DEMO-001",
        "severity": "HIGH",
        "exploitability": "HIGH",
        "package": "demo-package",
        "installed_version": "1.0.0",
        "fixed_version": "1.0.1",
    }


def make_attack_path():
    return {
        "external_exposure": True,
        "target_criticality": "CRITICAL",
        "path_length": 1,
    }


def test_complete_security_pipeline():

    vulnerability = make_vulnerability()
    attack_path = make_attack_path()

    # ---------------------------------------------------------
    # 1. Risk Engine
    # ---------------------------------------------------------

    risk = assess_risk(
        vulnerability=vulnerability,
        attack_path=attack_path,
    )

    assert risk.score == 96
    assert risk.level == "CRITICAL"

    # ---------------------------------------------------------
    # 2. Decision Engine
    # ---------------------------------------------------------

    decision_engine = DecisionEngine()

    decision = decision_engine.decide(risk)

    assert decision["action"] == "IMMEDIATE_REMEDIATION"
    assert decision["priority"] == "P0"
    assert decision["automated"] is True

    # ---------------------------------------------------------
    # 3. Remediation Planner
    # ---------------------------------------------------------

    planner = RemediationPlanner()

    remediation = planner.plan(
        vulnerability=vulnerability,
        decision=decision,
    )

    assert remediation["vulnerability"] == "CVE-DEMO-001"
    assert remediation["remediation_action"] == "UPGRADE_PACKAGE"
    assert remediation["package"] == "demo-package"
    assert remediation["installed_version"] == "1.0.0"
    assert remediation["fixed_version"] == "1.0.1"
    assert remediation["priority"] == "P0"

    # ---------------------------------------------------------
    # 4. Remediation Executor
    # ---------------------------------------------------------

    executor = RemediationExecutor(
        dry_run=True,
        simulate_success=True,
    )

    result = executor.execute(
        remediation=remediation,
        approved=True,
    )

    # ---------------------------------------------------------
    # 5. Final verification
    # ---------------------------------------------------------

    assert result["status"] == "EXECUTED"
    assert result["executed"] is True
    assert result["simulated"] is True
    assert result["package"] == "demo-package"
    assert result["current_version"] == "1.0.1"