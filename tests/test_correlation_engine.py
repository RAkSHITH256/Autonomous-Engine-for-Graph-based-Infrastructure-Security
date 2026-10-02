from backend.correlation.correlation_engine import CorrelationEngine
from backend.models.asset import Asset
from backend.models.finding import Finding


def test_direct_asset_id_correlation():

    engine = CorrelationEngine()

    asset = Asset(
        asset_id="asset-001",
        asset_type="CONTAINER",
        name="AEGIS API",
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
        asset_id="asset-001",
        metadata={
            "source": "TRIVY",
            "vulnerability_id": "CVE-001",
            "package": "openssl",
            "installed_version": "1.0.0",
            "fixed_version": "1.1.0",
        },
    )

    result = engine.correlate_finding(
        finding=finding,
        assets=[asset],
    )

    assert result is asset
    assert result.asset_id == "asset-001"


def test_image_based_correlation():

    engine = CorrelationEngine()

    asset = Asset(
        asset_id="container-001",
        asset_type="CONTAINER",
        name="AEGIS API",
        metadata={
            "image": "aegis-api:latest",
        },
    )

    finding = Finding(
        finding_id="trivy-CVE-002-openssl",
        category="container_vulnerability",
        severity="HIGH",
        title="CVE-002 in openssl",
        description="Test vulnerability",
        asset_id="aegis-api:latest",
        metadata={
            "source": "TRIVY",
            "vulnerability_id": "CVE-002",
            "package": "openssl",
        },
    )

    result = engine.correlate_finding(
        finding=finding,
        assets=[asset],
    )

    assert result is asset
    assert result.asset_id == "container-001"


def test_no_correlation():

    engine = CorrelationEngine()

    asset = Asset(
        asset_id="container-001",
        asset_type="CONTAINER",
        name="AEGIS API",
        metadata={
            "image": "aegis-api:latest",
        },
    )

    finding = Finding(
        finding_id="trivy-CVE-003-openssl",
        category="container_vulnerability",
        severity="HIGH",
        title="CVE-003 in openssl",
        description="Test vulnerability",
        asset_id="unknown-image:latest",
        metadata={
            "source": "TRIVY",
            "vulnerability_id": "CVE-003",
            "package": "openssl",
        },
    )

    result = engine.correlate_finding(
        finding=finding,
        assets=[asset],
    )

    assert result is None


def test_multiple_findings_correlation():

    engine = CorrelationEngine()

    asset = Asset(
        asset_id="container-001",
        asset_type="CONTAINER",
        name="AEGIS API",
        metadata={
            "image": "aegis-api:latest",
        },
    )

    findings = [
        Finding(
            finding_id="trivy-CVE-001-openssl",
            category="container_vulnerability",
            severity="HIGH",
            title="CVE-001 in openssl",
            description="Test vulnerability",
            asset_id="aegis-api:latest",
            metadata={
                "source": "TRIVY",
                "vulnerability_id": "CVE-001",
                "package": "openssl",
            },
        ),
        Finding(
            finding_id="trivy-CVE-002-curl",
            category="container_vulnerability",
            severity="MEDIUM",
            title="CVE-002 in curl",
            description="Test vulnerability",
            asset_id="aegis-api:latest",
            metadata={
                "source": "TRIVY",
                "vulnerability_id": "CVE-002",
                "package": "curl",
            },
        ),
    ]

    result = engine.correlate_findings(
        findings=findings,
        assets=[asset],
    )

    assert len(result) == 2

    assert (
        result["trivy-CVE-001-openssl"].asset_id
        == "container-001"
    )

    assert (
        result["trivy-CVE-002-curl"].asset_id
        == "container-001"
    )

def test_docker_image_id_correlation():

    engine = CorrelationEngine()

    asset = Asset(
        asset_id="docker-image:abcdef123456",
        asset_type="CONTAINER_IMAGE",
        name="aegis-api:latest",
        metadata={
            "source": "docker",
            "image_id": "abcdef123456",
            "image_reference": "aegis-api:latest",
        },
    )

    finding = Finding(
        finding_id="trivy-CVE-100-openssl",
        category="container_vulnerability",
        severity="CRITICAL",
        title="CVE-100 in openssl",
        description="Test Docker vulnerability",
        asset_id="aegis-api:latest",
        metadata={
            "source": "TRIVY",
            "vulnerability_id": "CVE-100",
            "package": "openssl",
            "image_id": "sha256:abcdef123456",
        },
    )

    result = engine.correlate_finding(
        finding=finding,
        assets=[asset],
    )

    assert result is asset

    assert (
        result.asset_id
        == "docker-image:abcdef123456"
    )