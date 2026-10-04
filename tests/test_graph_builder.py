from unittest.mock import MagicMock

import pytest

from backend.graph.graph_builder import GraphBuilder
from backend.graph.neo4j_client import Neo4jClient


def make_builder():
    """
    Create a GraphBuilder with a mocked Neo4j driver.

    We use __new__ so the real Neo4j connection is never created
    during unit tests.
    """
    client = Neo4jClient.__new__(Neo4jClient)
    client.driver = MagicMock()

    return GraphBuilder(client)


def get_session(builder):
    """
    Return the mocked Neo4j session used by GraphBuilder.

    GraphBuilder uses:

        with self.client.driver.session() as session:

    Therefore the actual mock session is the return value
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

    MagicMock.call_args has this structure:

        call((query,), kwargs)

    Therefore the query itself is args[0].
    """
    args, kwargs = session.run.call_args

    query = args[0]

    return query, kwargs


# ============================================================
# add_asset
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
# connect_assets
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
# Invalid relationship
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
# add_vulnerability
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
# clear_graph
# ============================================================

def test_clear_graph():
    builder = make_builder()

    builder.clear_graph()

    session = get_session(builder)

    session.run.assert_called_once()

    query, _ = get_last_query(session)

    assert "DETACH DELETE" in query


# ============================================================
# build_demo_graph
# ============================================================

def test_build_demo_graph():
    builder = make_builder()

    # Mock GraphBuilder methods so we only test the orchestration
    builder.add_asset = MagicMock()
    builder.connect_assets = MagicMock()
    builder.add_vulnerability = MagicMock()

    builder.build_demo_graph()

    # Four demo assets:
    # Internet
    # Web Server
    # Application Server
    # Production DB
    assert builder.add_asset.call_count == 4

    # Internet -> Web
    # Web -> Application
    # Application -> DB
    assert builder.connect_assets.call_count == 3

    # One demo vulnerability on the application server
    assert builder.add_vulnerability.call_count == 1


# ============================================================
# build_graph with custom data
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

    # Two assets should be created
    assert builder.add_asset.call_count == 2

    # One relationship should be created
    builder.connect_assets.assert_called_once_with(
        source_asset_id="web-001",
        target_asset_id="db-001",
        relationship="DEPENDS_ON",
    )

    # One vulnerability should be created
    builder.add_vulnerability.assert_called_once()


# ============================================================
# RUNS_IMAGE relationship
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
# BUILDS relationship
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
# SOURCE_REPOSITORY
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

    # Metadata is stored as JSON
    assert '"provider": "github"' in kwargs["metadata"]
    assert '"branch": "main"' in kwargs["metadata"]
    assert '"commit_sha": "abc123"' in kwargs["metadata"]
    assert '"url": "https://github.com/rakshith/AEGIS"' in kwargs["metadata"]


# ============================================================
# Repository -> Image BUILDS relationship
# ============================================================

def test_repository_builds_image():
    builder = make_builder()

    # 1. Add repository
    builder.add_repository(
        repository_id="github:rakshith/AEGIS",
        name="AEGIS",
        branch="main",
        commit_sha="abc123",
    )

    # 2. Add container image
    builder.add_asset(
        asset_id="docker-image:aegis",
        name="aegis:latest",
        asset_type="CONTAINER_IMAGE",
    )

    # 3. Connect repository -> image
    builder.connect_assets(
        source_asset_id="github:rakshith/AEGIS",
        target_asset_id="docker-image:aegis",
        relationship="BUILDS",
    )

    session = get_session(builder)

    # Three Neo4j operations:
    #
    # 1. Repository
    # 2. Image
    # 3. BUILDS relationship
    calls = session.run.call_args_list

    assert len(calls) == 3

    # Last call is the BUILDS relationship
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