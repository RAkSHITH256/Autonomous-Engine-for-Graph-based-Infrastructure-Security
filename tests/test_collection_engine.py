from backend.collection.collection_engine import CollectionEngine
from backend.models.finding import Finding


def make_trivy_finding():
    return Finding(
        finding_id="TRIVY-001",
        category="VULNERABILITY",
        severity="HIGH",
        title="Test vulnerability",
        description="Test Trivy vulnerability",
        asset_id="asset-001",
        metadata={
            "source": "TRIVY",
            "package": "openssl",
        },
    )


def make_semgrep_finding():
    return Finding(
        finding_id="SEMGREP-001",
        category="CODE_SECURITY",
        severity="HIGH",
        title="Test code issue",
        description="Test Semgrep finding",
        asset_id="asset-001",
        metadata={
            "source": "SEMGREP",
        },
    )


def test_collection_engine_collects_all_sources():

    engine = CollectionEngine()

    sbom_dependencies = [
        {
            "name": "requests",
            "version": "2.31.0",
            "type": "library",
        }
    ]

    findings = engine.collect(
        trivy_findings=[
            make_trivy_finding()
        ],
        semgrep_findings=[
            make_semgrep_finding()
        ],
        sbom_dependencies=sbom_dependencies,
        asset_id="asset-001",
    )

    assert len(findings) == 3

    sources = {
        finding.metadata.get("source")
        for finding in findings
    }

    assert "TRIVY" in sources
    assert "SEMGREP" in sources
    assert "SBOM" in sources


def test_collection_engine_trivy_only():

    engine = CollectionEngine()

    findings = engine.collect(
        trivy_findings=[
            make_trivy_finding()
        ]
    )

    assert len(findings) == 1
    assert findings[0].finding_id == "TRIVY-001"


def test_collection_engine_semgrep_only():

    engine = CollectionEngine()

    findings = engine.collect(
        semgrep_findings=[
            make_semgrep_finding()
        ]
    )

    assert len(findings) == 1
    assert findings[0].finding_id == "SEMGREP-001"


def test_collection_engine_sbom_requires_asset():

    engine = CollectionEngine()

    dependencies = [
        {
            "name": "requests",
            "version": "2.31.0",
        }
    ]

    try:
        engine.collect(
            sbom_dependencies=dependencies
        )

        assert False, "Expected ValueError"

    except ValueError as exc:
        assert "asset_id is required" in str(exc)


def test_collection_engine_empty():

    engine = CollectionEngine()

    findings = engine.collect()

    assert findings == []
