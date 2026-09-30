from unittest.mock import MagicMock

from backend.graph.neo4j_client import Neo4jClient


def make_client():

    client = Neo4jClient.__new__(
        Neo4jClient
    )

    client.driver = MagicMock()

    return client


def test_connection():

    client = make_client()

    record = MagicMock()

    record.__getitem__.return_value = 1

    session = client.driver.session.return_value.__enter__.return_value

    session.run.return_value.single.return_value = record

    assert client.test_connection() is True


def test_create_asset():

    client = make_client()

    client.create_asset(
        asset_id="asset-001",
        name="Production DB",
        asset_type="DATABASE",
        criticality="CRITICAL",
    )

    session = (
        client.driver
        .session.return_value
        .__enter__
        .return_value
    )

    session.run.assert_called_once()


def test_create_vulnerability():

    client = make_client()

    vulnerability = {
        "vulnerability_id": "CVE-DEMO-001",
        "identifier": "CVE-DEMO-001",
        "severity": "HIGH",
        "exploitability": "HIGH",
        "package": "requests",
        "installed_version": "2.31.0",
        "fixed_version": "2.32.0",
    }

    client.create_vulnerability(
        asset_id="asset-001",
        vulnerability=vulnerability,
    )

    session = (
        client.driver
        .session.return_value
        .__enter__
        .return_value
    )

    session.run.assert_called_once()


def test_find_attack_path_none():

    client = make_client()

    session = (
        client.driver
        .session.return_value
        .__enter__
        .return_value
    )

    session.run.return_value.single.return_value = None

    result = client.find_attack_path()

    assert result is None


def test_find_vulnerabilities_empty():

    client = make_client()

    session = (
        client.driver
        .session.return_value
        .__enter__
        .return_value
    )

    session.run.return_value = []

    result = client.find_vulnerabilities_on_path()

    assert result == []

