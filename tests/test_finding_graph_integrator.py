from unittest.mock import MagicMock

from backend.graph.finding_graph_integrator import (
    FindingGraphIntegrator,
)
from backend.graph.graph_builder import GraphBuilder
from backend.models.asset import Asset
from backend.models.finding import Finding


def make_integrator():

    client = MagicMock()

    builder = GraphBuilder(
        client
    )

    return FindingGraphIntegrator(
        graph_builder=builder
    )


def test_correlate_finding_by_asset_id():

    integrator = make_integrator()

    asset = Asset(
        asset_id="app-001",
        asset_type="APPLICATION",
        name="AEGIS API",
        environment="production",
    )

    finding = Finding(
        finding_id="TRIVY-001",
        category="container_vulnerability",
        severity="HIGH",
        title="Test vulnerability",
        description="Test vulnerability",
        asset_id="app-001",
        metadata={
            "source": "TRIVY",
        },
    )

    correlations = integrator.correlate(
        findings=[finding],
        assets=[asset],
    )

    assert len(correlations) == 1
    assert correlations["TRIVY-001"] == asset


def test_correlate_finding_by_image():

    integrator = make_integrator()

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
        finding_id="TRIVY-002",
        category="container_vulnerability",
        severity="HIGH",
        title="Image vulnerability",
        description="Container vulnerability",
        asset_id="aegis-api:latest",
        metadata={
            "source": "TRIVY",
        },
    )

    correlations = integrator.correlate(
        findings=[finding],
        assets=[asset],
    )

    assert len(correlations) == 1
    assert correlations["TRIVY-002"] == asset


def test_unmatched_finding():

    integrator = make_integrator()

    asset = Asset(
        asset_id="app-001",
        asset_type="APPLICATION",
        name="AEGIS API",
    )

    finding = Finding(
        finding_id="TRIVY-003",
        category="container_vulnerability",
        severity="HIGH",
        title="Unknown asset",
        description="Cannot correlate",
        asset_id="unknown-image",
        metadata={
            "source": "TRIVY",
        },
    )

    result = integrator.integrate(
        findings=[finding],
        assets=[asset],
    )

    assert result["total_findings"] == 1
    assert result["correlated_findings"] == 0
    assert result["unmatched_findings"] == 1
    assert result["unmatched"] == [
        "TRIVY-003"
    ]
