from types import SimpleNamespace
from unittest.mock import MagicMock, patch

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

    assert result["decision"]["action"] == "IMMEDIATE_REMEDIATION"
    assert result["decision"]["priority"] == "P0"

    assert (
        result["remediation"]["remediation_action"]
        == "UPGRADE_PACKAGE"
    )

    assert (
        result["remediation"]["fixed_version"]
        == "1.2.5"
    )

    assert result["execution"]["status"] == "DRY_RUN"
    assert result["execution"]["executed"] is False
    assert result["execution"]["dry_run"] is True

    assert result["verification"]["status"] == "NOT_VERIFIED"
    assert result["verification"]["verified"] is False

    assert result["reassessment"]["status"] == "WAITING"
    assert (
        result["reassessment"]["action"]
        == "WAIT_FOR_REMEDIATION"
    )

    assert result["loop_status"] == "WAITING"


def test_security_loop_graph_integration():

    loop = SecurityLoop(
        dry_run=True
    )

    client = MagicMock()

    graph_builder = GraphBuilder(
        client
    )

    asset = Asset(
        asset_id="app-001",
        asset_type="APPLICATION",
        name="AEGIS API",
        environment="production",
        metadata={
            "image": "aegis-api:latest",
        },
    )

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

    result = loop.integrate_findings_with_graph(
        findings=[finding],
        assets=[asset],
        graph_builder=graph_builder,
    )

    assert result["status"] == "success"

    assert result["total_findings"] == 1

    assert result["correlated_findings"] == 1

    assert result["unmatched_findings"] == 0

    assert result["correlations"][
        "trivy-CVE-001-openssl"
    ] == "app-001"


def test_security_loop_docker_discovery():

    loop = SecurityLoop()

    client = MagicMock()

    graph_builder = GraphBuilder(
        client
    )

    docker_assets = [
        Asset(
            asset_id="docker-container:abc123",
            asset_type="CONTAINER",
            name="test-container",
            metadata={
                "source": "docker",
                "image": "test-image:latest",
                "state": "RUNNING",
            },
        ),
        Asset(
            asset_id="docker-image:def456",
            asset_type="CONTAINER_IMAGE",
            name="test-image:latest",
            metadata={
                "source": "docker",
                "image_id": "def456",
            },
        ),
    ]

    docker_relationships = [
        {
            "source": "docker-container:abc123",
            "target": "docker-image:def456",
            "relationship": "RUNS_IMAGE",
        }
    ]

    with patch(
        "backend.orchestration.security_loop.DockerDiscovery"
    ) as mock_discovery:

        mock_discovery.return_value.discover.return_value = {
            "assets": docker_assets,
            "relationships": docker_relationships,
        }

        result = loop.discover_and_import_docker(
            graph_builder=graph_builder
        )

    assert result["status"] == "success"

    assert result["assets_discovered"] == 2

    assert result["relationships_discovered"] == 1

    assert (
        result["relationships"][0]["relationship"]
        == "RUNS_IMAGE"
    )

    mock_discovery.return_value.discover.assert_called_once()