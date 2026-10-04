import json

import pytest

from backend.models.build_provenance import BuildProvenance
from backend.provenance.provenance_parser import ProvenanceParser


def sample_provenance():
    return {
        "provider": "github-actions",
        "repository": "rakshith/AEGIS",
        "workflow": "AEGIS Security Pipeline",
        "run_id": "123456789",
        "run_number": 42,
        "commit_sha": "abc123def456",
        "branch": "main",
        "image": "aegis:abc123def456",
        "image_id": "sha256:1234567890abcdef",
        "created": "2026-10-04T06:04:08Z",
    }


def test_parse_provenance():
    parser = ProvenanceParser()

    provenance = parser.parse(
        sample_provenance()
    )

    assert isinstance(
        provenance,
        BuildProvenance,
    )

    assert provenance.provider == "github-actions"
    assert provenance.repository == "rakshith/AEGIS"
    assert provenance.workflow == "AEGIS Security Pipeline"
    assert provenance.run_id == "123456789"
    assert provenance.run_number == 42
    assert provenance.commit_sha == "abc123def456"
    assert provenance.branch == "main"
    assert provenance.image == "aegis:abc123def456"
    assert provenance.image_id == "sha256:1234567890abcdef"


def test_parse_provenance_file(tmp_path):
    provenance_file = (
        tmp_path / "build-provenance.json"
    )

    provenance_file.write_text(
        json.dumps(sample_provenance()),
        encoding="utf-8",
    )

    parser = ProvenanceParser()

    provenance = parser.parse_file(
        provenance_file
    )

    assert provenance.repository == "rakshith/AEGIS"
    assert provenance.commit_sha == "abc123def456"


def test_missing_provenance_file():
    parser = ProvenanceParser()

    with pytest.raises(FileNotFoundError):
        parser.parse_file(
            "/tmp/does-not-exist/build-provenance.json"
        )


def test_invalid_provenance():
    parser = ProvenanceParser()

    invalid_data = {
        "provider": "github-actions",
        "repository": "rakshith/AEGIS",
    }

    with pytest.raises(Exception):
        parser.parse(invalid_data)
