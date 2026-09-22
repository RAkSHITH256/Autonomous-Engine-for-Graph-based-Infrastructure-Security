from types import SimpleNamespace

from backend.orchestration.security_loop import SecurityLoop


def test_security_loop_dry_run():

    vulnerability = {
        "asset_id": "asset-003",
        "asset_name": "Backend",
        "vulnerability_id": "vuln-001",
        "identifier": "CVE-DEMO-001",
        "severity": "HIGH",
        "cvss_score": 8.5,
        "exploitability": "HIGH",
        "package": "demo-package",
        "installed_version": "1.2.0",
        "fixed_version": "1.2.5",
    }

    # Use the same structure expected by the existing
    # DecisionEngine / RemediationEngine.
    risk = SimpleNamespace(
        score=96,
        level="CRITICAL",
        factors={
            "vulnerability_severity": 30,
            "exploitability": 20,
            "external_exposure": 20,
            "target_criticality": 20,
            "path_proximity": 6,
        },
        explanation=(
            "Risk is CRITICAL because the asset has a HIGH "
            "vulnerability with HIGH exploitability and the "
            "attack path reaches a CRITICAL target."
        ),
    )

    loop = SecurityLoop(dry_run=True)

    result = loop.process(
        vulnerability=vulnerability,
        risk=risk,
        approved=True,
    )

    # Decision
    assert result["decision"]["action"] == "IMMEDIATE_REMEDIATION"
    assert result["decision"]["priority"] == "P0"

    # Remediation
    assert (
        result["remediation"]["remediation_action"]
        == "UPGRADE_PACKAGE"
    )

    assert (
        result["remediation"]["fixed_version"]
        == "1.2.5"
    )

    # Execution
    assert result["execution"]["status"] == "DRY_RUN"
    assert result["execution"]["executed"] is False
    assert result["execution"]["dry_run"] is True

    # Verification
    assert result["verification"]["status"] == "NOT_VERIFIED"
    assert result["verification"]["verified"] is False

    # Reassessment
    assert result["reassessment"]["status"] == "WAITING"
    assert (
        result["reassessment"]["action"]
        == "WAIT_FOR_REMEDIATION"
    )

    # Complete lifecycle
    assert result["loop_status"] == "WAITING"