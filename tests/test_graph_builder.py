from unittest.mock import MagicMock
from unittest.mock import MagicMock

import pytest

from backend.graph.graph_builder import GraphBuilder
from backend.graph.neo4j_client import Neo4jClient


def make_builder():

    client = Neo4jClient.__new__(
        Neo4jClient
    )

    client.driver = MagicMock()

    return GraphBuilder(client)


def test_add_asset():

    builder = make_builder()

    builder.add_asset(
        asset_id="web-001",
        name="Web Server",
        asset_type="WEB_SERVER",
        criticality="HIGH",
    )

    session = (
        builder.client.driver
        .session.return_value
        .__enter__
        .return_value
    )

    session.run.assert_called_once()


def test_connect_assets():

    builder = make_builder()

    builder.connect_assets(
        source_asset_id="internet-001",
        target_asset_id="web-001",
    )

    session = (
        builder.client.driver
        .session.return_value
        .__enter__
        .return_value
    )

    session.run.assert_called_once()


def test_invalid_relationship():

    builder = make_builder()

    with pytest.raises(ValueError):

        builder.connect_assets(
            source_asset_id="a",
            target_asset_id="b",
            relationship="DELETE_DATABASE",
        )


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

    session = (
        builder.client.driver
        .session.return_value
        .__enter__
        .return_value
    )

    session.run.assert_called_once()


def test_clear_graph():

    builder = make_builder()

    builder.clear_graph()

    session = (
        builder.client.driver
        .session.return_value
        .__enter__
        .return_value
    )

    session.run.assert_called_once()


def test_build_demo_graph():

    builder = make_builder()

    builder.add_asset = MagicMock()
    builder.connect_assets = MagicMock()
    builder.add_vulnerability = MagicMock()

    builder.build_demo_graph()

    assert builder.add_asset.call_count == 4

    assert builder.connect_assets.call_count == 3

    assert builder.add_vulnerability.call_count == 1


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
                "type": "CONNECTS_TO",
            }
        ],
        vulnerabilities=[
            {
                "asset_id": "web-001",
                "vulnerability": {
                    "vulnerability_id": "CVE-001",
                    "identifier": "CVE-001",
                    "severity": "HIGH",
                },
            }
        ],
    )

    assert builder.add_asset.call_count == 2
    assert builder.connect_assets.call_count == 1
    assert builder.add_vulnerability.call_count == 1

def test_connect_assets_allows_runs_image():
    client = MagicMock()

    builder = GraphBuilder(client)

    builder.connect_assets(
        source_asset_id="docker-container:abc123",
        target_asset_id="docker-image:def456",
        relationship="RUNS_IMAGE",
    )

    session = client.driver.session.return_value.__enter__.return_value

    session.run.assert_called_once()

    query = session.run.call_args[0][0]

    assert "RUNS_IMAGE" in query