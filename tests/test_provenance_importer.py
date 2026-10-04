from unittest.mock import MagicMock

import pytest

from backend.models.build_provenance import BuildProvenance
from backend.provenance.provenance_importer import (
    ProvenanceImporter,
)


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


def test_import_provenance_file(tmp_path):
    provenance_file = (
        tmp_path / "build-provenance.json"
    )

    import json

    provenance_file.write_text(
        json.dumps(sample_provenance()),
        encoding="utf-8",
    )

    graph_builder = MagicMock()

    importer = ProvenanceImporter(
        graph_builder=graph_builder
    )

    result = importer.import_file(
        provenance_file
    )

    assert isinstance(
        result,
        BuildProvenance,
    )

    assert (
        result.repository
        == "rakshith/AEGIS"
    )

    assert (
        result.commit_sha
        == "abc123def456"
    )

    graph_builder.add_build_provenance.assert_called_once_with(
        result
    )


def test_import_returns_validated_provenance(
    tmp_path,
):
    provenance_file = (
        tmp_path / "build-provenance.json"
    )

    import json

    provenance_file.write_text(
        json.dumps(sample_provenance()),
        encoding="utf-8",
    )

    graph_builder = MagicMock()

    importer = ProvenanceImporter(
        graph_builder=graph_builder
    )

    result = importer.import_file(
        provenance_file
    )

    assert result.provider == "github-actions"
    assert result.workflow == "AEGIS Security Pipeline"
    assert result.run_number == 42
    assert result.branch == "main"


def test_import_missing_file():
    graph_builder = MagicMock()

    importer = ProvenanceImporter(
        graph_builder=graph_builder
    )

    with pytest.raises(FileNotFoundError):
        importer.import_file(
            "/tmp/does-not-exist/build-provenance.json"
        )


def test_graph_builder_receives_provenance(
    tmp_path,
):
    provenance_file = (
        tmp_path / "build-provenance.json"
    )

    import json

    provenance_file.write_text(
        json.dumps(sample_provenance()),
        encoding="utf-8",
    )

    graph_builder = MagicMock()

    importer = ProvenanceImporter(
        graph_builder=graph_builder
    )

    importer.import_file(
        provenance_file
    )

    call = (
        graph_builder
        .add_build_provenance
        .call_args
    )

    provenance = call.args[0]

    assert isinstance(
        provenance,
        BuildProvenance,
    )

    assert (
        provenance.image_id
        == "sha256:1234567890abcdef"
    )
