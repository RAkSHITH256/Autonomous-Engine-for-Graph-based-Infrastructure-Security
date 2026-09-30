from backend.orchestration.security_loop import SecurityLoop
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
        severity="MEDIUM",
        title="Test code issue",
        description="Test Semgrep finding",
        asset_id="asset-001",
        metadata={
            "source": "SEMGREP",
        },
    )


def test_security_loop_collection():

    loop = SecurityLoop()

    result = loop.collect_and_summarize(
        trivy_findings=[
            make_trivy_finding()
        ],
        semgrep_findings=[
            make_semgrep_finding()
        ],
        sbom_dependencies=[
            {
                "name": "requests",
                "version": "2.31.0",
            }
        ],
        asset_id="asset-001",
    )

    assert result["status"] == "success"

    assert len(result["findings"]) == 3

    assert result["summary"]["total"] == 3

    assert result["summary"]["sources"]["TRIVY"] == 1
    assert result["summary"]["sources"]["SEMGREP"] == 1
    assert result["summary"]["sources"]["SBOM"] == 1


def test_security_loop_empty_collection():

    loop = SecurityLoop()

    result = loop.collect_and_summarize()

    assert result["status"] == "success"
    assert result["findings"] == []
    assert result["summary"]["total"] == 0


def test_security_loop_trivy_collection():

    loop = SecurityLoop()

    result = loop.collect_and_summarize(
        trivy_findings=[
            make_trivy_finding()
        ]
    )

    assert len(result["findings"]) == 1
    assert result["findings"][0].finding_id == "TRIVY-001"


def test_security_loop_sbom_collection():

    loop = SecurityLoop()

    result = loop.collect_and_summarize(
        sbom_dependencies=[
            {
                "name": "fastapi",
                "version": "0.115.0",
            }
        ],
        asset_id="asset-001",
    )

    assert len(result["findings"]) == 1

    finding = result["findings"][0]

    assert finding.metadata["source"] == "SBOM"
    assert finding.metadata["package"] == "fastapi"