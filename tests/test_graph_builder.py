from unittest.mock import MagicMock

import pytest

from backend.graph.graph_builder import GraphBuilder
from backend.graph.neo4j_client import Neo4jClient
from backend.models.build_provenance import BuildProvenance


# ============================================================
# TEST HELPERS
# ============================================================

def make_builder():
    """
    Create a GraphBuilder with a mocked Neo4j driver.

    No real Neo4j connection is used during unit tests.
    """
    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()

    return GraphBuilder(client)


def get_session(builder):
    """
    Return the mocked Neo4j session.

    GraphBuilder uses:

        with self.client.driver.session() as session:

    Therefore the actual session is the return value
    of __enter__().
    """
    return (
        builder.client.driver
        .session.return_value
        .__enter__
        .return_value
    )


def get_last_query(session):
    """
    Extract the query string and keyword arguments from
    the most recent session.run(...) call.

    MagicMock.call_args has the form:

        call((query,), kwargs)

    Therefore args[0] is the actual query string.
    """
    args, kwargs = session.run.call_args

    query = args[0]

    return query, kwargs


# ============================================================
# ADD ASSET
# ============================================================

def test_add_asset():
    builder = make_builder()

    builder.add_asset(
        asset_id="web-001",
        name="Web Server",
        asset_type="WEB_SERVER",
        criticality="HIGH",
    )

    session = get_session(builder)

    session.run.assert_called_once()

    query, kwargs = get_last_query(session)

    assert "MERGE (asset:Asset" in query

    assert kwargs["asset_id"] == "web-001"
    assert kwargs["name"] == "Web Server"
    assert kwargs["asset_type"] == "WEB_SERVER"
    assert kwargs["criticality"] == "HIGH"


# ============================================================
# CONNECT ASSETS
# ============================================================

def test_connect_assets():
    builder = make_builder()

    builder.connect_assets(
        source_asset_id="internet-001",
        target_asset_id="web-001",
    )

    session = get_session(builder)

    session.run.assert_called_once()

    query, kwargs = get_last_query(session)

    assert "MERGE (source)-[:CONNECTS_TO]->(target)" in query

    assert kwargs["source_asset_id"] == "internet-001"
    assert kwargs["target_asset_id"] == "web-001"


# ============================================================
# INVALID RELATIONSHIP
# ============================================================

def test_invalid_relationship():
    builder = make_builder()

    with pytest.raises(ValueError):
        builder.connect_assets(
            source_asset_id="a",
            target_asset_id="b",
            relationship="DELETE_DATABASE",
        )


# ============================================================
# ADD VULNERABILITY
# ============================================================

def test_add_vulnerability():
    builder = make_builder()

    builder.add_vulnerability(
        asset_id="app-001",
        vulnerability={
            "vulnerability_id": "CVE-DEMO-001",
            "identifier": "CVE-DEMO-001",
            "severity": "HIGH",
            "exploitability": "HIGH",
            "package": "requests",
            "installed_version": "2.31.0",
            "fixed_version": "2.32.0",
        },
    )

    session = get_session(builder)

    session.run.assert_called_once()

    query, kwargs = get_last_query(session)

    assert "HAS_VULNERABILITY" in query

    assert kwargs["asset_id"] == "app-001"
    assert kwargs["vulnerability_id"] == "CVE-DEMO-001"
    assert kwargs["severity"] == "HIGH"


# ============================================================
# CLEAR GRAPH
# ============================================================

def test_clear_graph():
    builder = make_builder()

    builder.clear_graph()

    session = get_session(builder)

    session.run.assert_called_once()

    query, _ = get_last_query(session)

    assert "DETACH DELETE" in query


# ============================================================
# DEMO GRAPH
# ============================================================

def test_build_demo_graph():
    builder = make_builder()

    # Mock internal methods so this test verifies orchestration.
    builder.add_asset = MagicMock()
    builder.connect_assets = MagicMock()
    builder.add_vulnerability = MagicMock()

    builder.build_demo_graph()

    # Internet
    # Web Server
    # Application Server
    # Production DB
    assert builder.add_asset.call_count == 4

    # Internet -> Web
    # Web -> Application
    # Application -> DB
    assert builder.connect_assets.call_count == 3

    # Demo vulnerability
    assert builder.add_vulnerability.call_count == 1


# ============================================================
# CUSTOM GRAPH
# ============================================================

def test_build_custom_graph():
    builder = make_builder()

    builder.add_asset = MagicMock()
    builder.connect_assets = MagicMock()
    builder.add_vulnerability = MagicMock()

    builder.build_graph(
        assets=[
            {
                "asset_id": "web-001",
                "name": "Web Server",
                "type": "WEB_SERVER",
                "criticality": "HIGH",
            },
            {
                "asset_id": "db-001",
                "name": "Production DB",
                "type": "DATABASE",
                "criticality": "CRITICAL",
            },
        ],
        relationships=[
            {
                "source": "web-001",
                "target": "db-001",
                "relationship": "DEPENDS_ON",
            }
        ],
        vulnerabilities=[
            {
                "asset_id": "web-001",
                "vulnerability_id": "CVE-001",
                "identifier": "CVE-001",
                "severity": "HIGH",
            }
        ],
    )

    # Two assets
    assert builder.add_asset.call_count == 2

    # One relationship
    builder.connect_assets.assert_called_once_with(
        source_asset_id="web-001",
        target_asset_id="db-001",
        relationship="DEPENDS_ON",
    )

    # One vulnerability
    builder.add_vulnerability.assert_called_once()


# ============================================================
# RUNS_IMAGE RELATIONSHIP
# ============================================================

def test_connect_assets_allows_runs_image():
    builder = make_builder()

    builder.connect_assets(
        source_asset_id="container-001",
        target_asset_id="image-001",
        relationship="RUNS_IMAGE",
    )

    session = get_session(builder)

    session.run.assert_called_once()

    query, kwargs = get_last_query(session)

    assert "MERGE (source)-[:RUNS_IMAGE]->(target)" in query

    assert kwargs["source_asset_id"] == "container-001"
    assert kwargs["target_asset_id"] == "image-001"


# ============================================================
# BUILDS RELATIONSHIP
# ============================================================

def test_connect_assets_allows_builds():
    builder = make_builder()

    builder.connect_assets(
        source_asset_id="repository-001",
        target_asset_id="image-001",
        relationship="BUILDS",
    )

    session = get_session(builder)

    session.run.assert_called_once()

    query, kwargs = get_last_query(session)

    assert "MERGE (source)-[:BUILDS]->(target)" in query

    assert kwargs["source_asset_id"] == "repository-001"
    assert kwargs["target_asset_id"] == "image-001"


# ============================================================
# SOURCE REPOSITORY
# ============================================================

def test_add_repository():
    builder = make_builder()

    builder.add_repository(
        repository_id="github:rakshith/AEGIS",
        name="AEGIS",
        url="https://github.com/rakshith/AEGIS",
        branch="main",
        commit_sha="abc123",
    )

    session = get_session(builder)

    session.run.assert_called_once()

    query, kwargs = get_last_query(session)

    assert "MERGE (asset:Asset" in query

    assert kwargs["asset_id"] == "github:rakshith/AEGIS"
    assert kwargs["name"] == "AEGIS"
    assert kwargs["asset_type"] == "SOURCE_REPOSITORY"
    assert kwargs["criticality"] == "HIGH"

    assert '"provider": "github"' in kwargs["metadata"]
    assert '"branch": "main"' in kwargs["metadata"]
    assert '"commit_sha": "abc123"' in kwargs["metadata"]
    assert '"url": "https://github.com/rakshith/AEGIS"' in kwargs["metadata"]


# ============================================================
# REPOSITORY BUILDS IMAGE
# ============================================================

def test_repository_builds_image():
    builder = make_builder()

    # 1. Repository
    builder.add_repository(
        repository_id="github:rakshith/AEGIS",
        name="AEGIS",
        branch="main",
        commit_sha="abc123",
    )

    # 2. Container image
    builder.add_asset(
        asset_id="docker-image:aegis",
        name="aegis:latest",
        asset_type="CONTAINER_IMAGE",
    )

    # 3. Repository -> Image
    builder.connect_assets(
        source_asset_id="github:rakshith/AEGIS",
        target_asset_id="docker-image:aegis",
        relationship="BUILDS",
    )

    session = get_session(builder)

    calls = session.run.call_args_list

    assert len(calls) == 3

    build_args, build_kwargs = calls[-1]

    build_query = build_args[0]

    assert "MERGE (source)-[:BUILDS]->(target)" in build_query

    assert (
        build_kwargs["source_asset_id"]
        == "github:rakshith/AEGIS"
    )

    assert (
        build_kwargs["target_asset_id"]
        == "docker-image:aegis"
    )


# ============================================================
# BUILD PROVENANCE
# ============================================================

def test_add_build_provenance():
    """
    Verify that validated CI/CD provenance creates:

        Repository -[:BUILDS]-> ContainerImage
    """

    builder = make_builder()

    provenance = BuildProvenance(
        provider="github-actions",
        repository="rakshith/AEGIS",
        workflow="AEGIS Security Pipeline",
        run_id="123456789",
        run_number=42,
        commit_sha="abc123def456",
        branch="main",
        image="aegis:abc123def456",
        image_id="sha256:1234567890abcdef",
        created="2026-10-04T06:04:08Z",
    )

    # Mock the lower-level graph operations.
    builder.add_repository = MagicMock()
    builder.add_asset = MagicMock()
    builder.connect_assets = MagicMock()

    builder.add_build_provenance(
        provenance
    )

    # --------------------------------------------------------
    # Repository
    # --------------------------------------------------------

    builder.add_repository.assert_called_once()

    repository_kwargs = (
        builder.add_repository.call_args.kwargs
    )

    assert (
        repository_kwargs["repository_id"]
        == "github:rakshith/AEGIS"
    )

    assert (
        repository_kwargs["name"]
        == "rakshith/AEGIS"
    )

    assert (
        repository_kwargs["branch"]
        == "main"
    )

    assert (
        repository_kwargs["commit_sha"]
        == "abc123def456"
    )

    assert (
        repository_kwargs["provider"]
        == "github-actions"
    )

    assert (
        repository_kwargs["url"]
        == "https://github.com/rakshith/AEGIS"
    )

    # --------------------------------------------------------
    # Container image
    # --------------------------------------------------------

    builder.add_asset.assert_called_once()

    image_kwargs = (
        builder.add_asset.call_args.kwargs
    )

    assert (
        image_kwargs["asset_id"]
        == "docker-image:1234567890abcdef"
    )

    assert (
        image_kwargs["name"]
        == "aegis:abc123def456"
    )

    assert (
        image_kwargs["asset_type"]
        == "CONTAINER_IMAGE"
    )

    assert (
        image_kwargs["criticality"]
        == "HIGH"
    )

    # --------------------------------------------------------
    # BUILDS relationship
    # --------------------------------------------------------

    builder.connect_assets.assert_called_once_with(
        source_asset_id="github:rakshith/AEGIS",
        target_asset_id="docker-image:1234567890abcdef",
        relationship="BUILDS",
    )


# ============================================================
# BUILD PROVENANCE METADATA
# ============================================================

def test_build_provenance_metadata():
    """
    Verify that important CI/CD provenance fields are stored
    as image metadata.
    """

    builder = make_builder()

    provenance = BuildProvenance(
        provider="github-actions",
        repository="rakshith/AEGIS",
        workflow="AEGIS Security Pipeline",
        run_id="987654321",
        run_number=55,
        commit_sha="deadbeef1234",
        branch="develop",
        image="aegis:deadbeef1234",
        image_id="sha256:abcdef123456",
        created="2026-10-04T07:00:00Z",
    )

    builder.add_repository = MagicMock()
    builder.add_asset = MagicMock()
    builder.connect_assets = MagicMock()

    builder.add_build_provenance(
        provenance
    )

    image_kwargs = (
        builder.add_asset.call_args.kwargs
    )

    metadata = image_kwargs["metadata"]

    assert metadata["image"] == "aegis:deadbeef1234"

    assert (
        metadata["image_id"]
        == "sha256:abcdef123456"
    )

    assert (
        metadata["commit_sha"]
        == "deadbeef1234"
    )

    assert (
        metadata["repository"]
        == "rakshith/AEGIS"
    )

    assert (
        metadata["workflow"]
        == "AEGIS Security Pipeline"
    )

    assert metadata["run_id"] == "987654321"

    assert metadata["run_number"] == 55

    assert (
        metadata["created"]
        == "2026-10-04T07:00:00Z"
    )

def test_build_graph_uses_type_for_relationship():
    client = MagicMock()
    builder = GraphBuilder(client)

    builder.add_asset = MagicMock()
    builder.connect_assets = MagicMock()
    builder.add_vulnerability = MagicMock()

    builder.build_graph(
        assets=[
            {
                "asset_id": "container-001",
                "name": "aegis-runtime",
                "type": "CONTAINER",
            },
            {
                "asset_id": "image-001",
                "name": "aegis-image",
                "type": "CONTAINER_IMAGE",
            },
        ],
        relationships=[
            {
                "source": "container-001",
                "target": "image-001",
                "type": "RUNS_IMAGE",
            }
        ],
        vulnerabilities=[],
    )

    builder.connect_assets.assert_called_once_with(
        source_asset_id="container-001",
        target_asset_id="image-001",
        relationship="RUNS_IMAGE",
    )