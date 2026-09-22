from backend.remediation.remediation_planner import RemediationPlanner


def make_vulnerability():
    return {
        "identifier": "CVE-DEMO-001",
        "package": "demo-package",
        "installed_version": "1.0.0",
        "fixed_version": "1.0.1",
    }


def test_immediate_remediation_plan():

    planner = RemediationPlanner()

    decision = {
        "action": "IMMEDIATE_REMEDIATION",
        "priority": "P0",
        "automated": True,
        "reason": "Critical risk detected.",
    }

    result = planner.plan(
        vulnerability=make_vulnerability(),
        decision=decision,
    )

    assert result["vulnerability"] == "CVE-DEMO-001"
    assert result["remediation_action"] == "UPGRADE_PACKAGE"
    assert result["package"] == "demo-package"
    assert result["installed_version"] == "1.0.0"
    assert result["fixed_version"] == "1.0.1"
    assert result["priority"] == "P0"
    assert result["automated"] is True


def test_prioritized_remediation_plan():

    planner = RemediationPlanner()

    decision = {
        "action": "PRIORITIZE_REMEDIATION",
        "priority": "P1",
        "automated": False,
        "reason": "High risk detected.",
    }

    result = planner.plan(
        vulnerability=make_vulnerability(),
        decision=decision,
    )

    assert result["remediation_action"] == "UPGRADE_PACKAGE"
    assert result["priority"] == "P1"
    assert result["automated"] is False


def test_scheduled_remediation_plan():

    planner = RemediationPlanner()

    decision = {
        "action": "SCHEDULE_REMEDIATION",
        "priority": "P2",
        "automated": False,
        "reason": "Medium risk detected.",
    }

    result = planner.plan(
        vulnerability=make_vulnerability(),
        decision=decision,
    )

    assert result["remediation_action"] == "UPGRADE_PACKAGE"
    assert result["priority"] == "P2"


def test_monitor_plan():

    planner = RemediationPlanner()

    decision = {
        "action": "MONITOR",
        "priority": "P3",
        "automated": False,
        "reason": "Low risk detected.",
    }

    result = planner.plan(
        vulnerability=make_vulnerability(),
        decision=decision,
    )

    assert result["remediation_action"] == "MONITOR"
    assert result["priority"] == "P3"


def test_missing_fixed_version():

    planner = RemediationPlanner()

    vulnerability = make_vulnerability()
    vulnerability["fixed_version"] = ""

    decision = {
        "action": "IMMEDIATE_REMEDIATION",
        "priority": "P0",
        "automated": True,
        "reason": "Critical risk detected.",
    }

    result = planner.plan(
        vulnerability=vulnerability,
        decision=decision,
    )

    assert result["remediation_action"] == "UNKNOWN"
    assert result["fixed_version"] == ""