from types import SimpleNamespace
from unittest.mock import MagicMock

from backend.graph.graph_builder import GraphBuilder
from backend.models.asset import Asset
from backend.models.finding import Finding
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

def test_security_loop_graph_integration():

    loop = SecurityLoop(
        dry_run=True
    )

    # ---------------------------------------------------------
    # Mock graph builder
    # ---------------------------------------------------------

    client = MagicMock()

    graph_builder = GraphBuilder(
        client
    )

    # ---------------------------------------------------------
    # Infrastructure asset
    # ---------------------------------------------------------

    asset = Asset(
        asset_id="app-001",
        asset_type="APPLICATION",
        name="AEGIS API",
        environment="production",
        metadata={
            "image": "aegis-api:latest",
        },
    )

    # ---------------------------------------------------------
    # Realistic Trivy-style finding
    # ---------------------------------------------------------

    finding = Finding(
        finding_id="trivy-CVE-001-openssl",
        category="container_vulnerability",
        severity="HIGH",
        title="CVE-001 in openssl",
        description="Test vulnerability",
        asset_id="aegis-api:latest",
        metadata={
            "source": "trivy",
            "vulnerability_id": "CVE-001",
            "package": "openssl",
            "installed_version": "1.0.0",
            "fixed_version": "1.1.0",
        },
    )

    # ---------------------------------------------------------
    # Integrate
    # ---------------------------------------------------------

    result = loop.integrate_findings_with_graph(
        findings=[finding],
        assets=[asset],
        graph_builder=graph_builder,
    )

    # ---------------------------------------------------------
    # Validate
    # ---------------------------------------------------------

    assert result["status"] == "success"

    assert result["total_findings"] == 1

    assert result["correlated_findings"] == 1

    assert result["unmatched_findings"] == 0

    assert result["correlations"][
        "trivy-CVE-001-openssl"
    ] == "app-001"