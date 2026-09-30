from backend.correlation.sbom_finding_adapter import SBOMFindingAdapter
from backend.models.finding import Finding


def test_multi_source_findings():

    # ---------------------------------------------------------
    # 1. SBOM source
    # ---------------------------------------------------------

    dependencies = [
        {
            "name": "requests",
            "version": "2.31.0",
            "type": "library",
            "purl": "pkg:pypi/requests@2.31.0",
            "scope": "required",
        },
        {
            "name": "fastapi",
            "version": "0.115.0",
            "type": "library",
        },
    ]

    adapter = SBOMFindingAdapter()

    sbom_findings = adapter.to_findings(
        dependencies=dependencies,
        asset_id="asset-001",
    )

    # ---------------------------------------------------------
    # 2. Validate SBOM findings
    # ---------------------------------------------------------

    assert len(sbom_findings) == 2

    assert all(
        isinstance(finding, Finding)
        for finding in sbom_findings
    )

    assert all(
        finding.category == "DEPENDENCY"
        for finding in sbom_findings
    )

    assert all(
        finding.metadata["source"] == "SBOM"
        for finding in sbom_findings
    )

    # ---------------------------------------------------------
    # 3. Verify asset correlation information
    # ---------------------------------------------------------

    assert all(
        finding.asset_id == "asset-001"
        for finding in sbom_findings
    )

    # ---------------------------------------------------------
    # 4. Verify package information
    # ---------------------------------------------------------

    packages = {
        finding.metadata["package"]
        for finding in sbom_findings
    }

    assert packages == {
        "requests",
        "fastapi",
    }
