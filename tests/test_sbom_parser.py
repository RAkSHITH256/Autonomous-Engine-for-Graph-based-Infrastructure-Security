from backend.collectors.sbom.sbom_parser import SBOMParser


def test_parse_cyclonedx_components():

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": (
                    "pkg:pypi/requests@2.31.0"
                ),
            },
            {
                "type": "library",
                "name": "fastapi",
                "version": "0.115.0",
                "purl": (
                    "pkg:pypi/fastapi@0.115.0"
                ),
            },
        ],
    }

    parser = SBOMParser()

    dependencies = parser.parse(sbom)

    assert len(dependencies) == 2

    assert dependencies[0]["name"] == "requests"
    assert dependencies[0]["version"] == "2.31.0"

    assert dependencies[1]["name"] == "fastapi"
    assert dependencies[1]["version"] == "0.115.0"


def test_missing_version():

    sbom = {
        "components": [
            {
                "name": "demo-package",
            }
        ]
    }

    parser = SBOMParser()

    dependencies = parser.parse(sbom)

    assert len(dependencies) == 1
    assert dependencies[0]["name"] == "demo-package"
    assert dependencies[0]["version"] == "UNKNOWN"


def test_invalid_components():

    sbom = {
        "components": "invalid"
    }

    parser = SBOMParser()

    try:
        parser.parse(sbom)
        assert False
    except ValueError:
        assert True