from backend.collectors.trivy.trivy_parser import TrivyParser
from backend.models.evidence import Evidence


def test_trivy_parser():

    evidence = Evidence(
        evidence_id="evidence-trivy-001",
        source="trivy",
        metadata={
            "image": "aegis-demo:1.0",
        },
        raw_data={
            "SchemaVersion": 2,
            "ArtifactName": "aegis-demo:1.0",
            "ArtifactType": "container_image",
            "Results": [
                {
                    "Target": "aegis-demo",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-DEMO-001",
                            "PkgName": "demo-package",
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.0.1",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ],
        },
    )

    parser = TrivyParser()

    findings = parser.parse(evidence)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.finding_id == (
        "trivy-CVE-DEMO-001-demo-package"
    )

    assert finding.category == "container_vulnerability"

    assert finding.severity == "HIGH"

    assert finding.title == (
        "CVE-DEMO-001 in demo-package"
    )

    assert finding.asset_id == "aegis-demo:1.0"

    assert finding.metadata["vulnerability_id"] == (
        "CVE-DEMO-001"
    )

    assert finding.metadata["package"] == (
        "demo-package"
    )

    assert finding.metadata["installed_version"] == (
        "1.0.0"
    )

    assert finding.metadata["fixed_version"] == (
        "1.0.1"
    )
