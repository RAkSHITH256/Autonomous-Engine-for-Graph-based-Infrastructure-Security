from backend.correlation.sbom_finding_adapter import (
    SBOMFindingAdapter,
)

from backend.models.finding import Finding


def test_dependency_to_finding():

    dependency = {
        "name": "requests",
        "version": "2.31.0",
        "type": "library",
        "purl": "pkg:pypi/requests@2.31.0",
        "scope": "required",
    }

    adapter = SBOMFindingAdapter()

    finding = adapter.to_finding(
        dependency=dependency,
        asset_id="asset-001",
    )

    assert isinstance(finding, Finding)

    assert finding.finding_id == (
        "SBOM-asset-001-requests-2.31.0"
    )

    assert finding.category == "DEPENDENCY"

    assert finding.severity == "INFO"

    assert finding.asset_id == "asset-001"

    assert finding.status == "OPEN"

    assert finding.metadata["source"] == "SBOM"

    assert finding.metadata["dependency_name"] == "requests"

    assert finding.metadata["version"] == "2.31.0"

    assert finding.metadata["type"] == "library"

    assert finding.metadata["purl"] == (
        "pkg:pypi/requests@2.31.0"
    )

    assert finding.metadata["scope"] == "required"


def test_multiple_dependencies_to_findings():

    dependencies = [
        {
            "name": "requests",
            "version": "2.31.0",
        },
        {
            "name": "fastapi",
            "version": "0.115.0",
        },
    ]

    adapter = SBOMFindingAdapter()

    findings = adapter.to_findings(
        dependencies=dependencies,
        asset_id="asset-001",
    )

    assert len(findings) == 2

    assert all(
        isinstance(finding, Finding)
        for finding in findings
    )

    assert findings[0].finding_id == (
        "SBOM-asset-001-requests-2.31.0"
    )

    assert findings[1].finding_id == (
        "SBOM-asset-001-fastapi-0.115.0"
    )

    assert findings[0].category == "DEPENDENCY"
    assert findings[1].category == "DEPENDENCY"

    assert findings[0].asset_id == "asset-001"
    assert findings[1].asset_id == "asset-001"


def test_missing_asset_id():

    adapter = SBOMFindingAdapter()

    dependency = {
        "name": "requests",
        "version": "2.31.0",
    }

    try:

        adapter.to_finding(
            dependency=dependency,
            asset_id="",
        )

        assert False, (
            "Expected ValueError for missing asset_id"
        )

    except ValueError as exc:

        assert str(exc) == "asset_id is required"


def test_missing_asset_id_for_multiple_dependencies():

    adapter = SBOMFindingAdapter()

    dependencies = [
        {
            "name": "requests",
            "version": "2.31.0",
        }
    ]

    try:

        adapter.to_findings(
            dependencies=dependencies,
            asset_id="",
        )

        assert False, (
            "Expected ValueError for missing asset_id"
        )

    except ValueError as exc:

        assert str(exc) == "asset_id is required"


def test_dependency_with_missing_optional_fields():

    dependency = {
        "name": "requests",
        "version": "2.31.0",
    }

    adapter = SBOMFindingAdapter()

    finding = adapter.to_finding(
        dependency=dependency,
        asset_id="asset-001",
    )

    assert finding.finding_id == (
        "SBOM-asset-001-requests-2.31.0"
    )

    assert finding.category == "DEPENDENCY"

    assert finding.metadata["source"] == "SBOM"

    assert finding.metadata["dependency_name"] == "requests"

    assert finding.metadata["version"] == "2.31.0"

    assert finding.metadata["type"] == "library"

    assert finding.metadata["purl"] is None

    assert finding.metadata["scope"] is None