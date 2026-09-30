from unittest.mock import MagicMock

from backend.graph.neo4j_client import Neo4jClient
from backend.risk.risk_engine import (
    assess_attack_path_risks,
    assess_attack_path_risk,
)


def make_client():
    """
    Create a Neo4jClient without connecting
    to a real Neo4j server.
    """

    client = Neo4jClient.__new__(
        Neo4jClient
    )

    client.driver = MagicMock()

    return client


def test_attack_path_risk_integration():

    client = make_client()

    # ---------------------------------------------------------
    # Simulated graph attack path
    # ---------------------------------------------------------

    client.find_attack_path = MagicMock(
        return_value={
            "path_length": 1,
            "nodes": [
                {
                    "asset_id": "internet-001",
                    "name": "Internet",
                    "type": "EXTERNAL",
                    "criticality": "HIGH",
                },
                {
                    "asset_id": "db-001",
                    "name": "Production DB",
                    "type": "DATABASE",
                    "criticality": "CRITICAL",
                },
            ],
        }
    )

    # ---------------------------------------------------------
    # Vulnerability stored in graph
    # ---------------------------------------------------------

    client.find_vulnerabilities_on_path = MagicMock(
        return_value=[
            {
                "asset_id": "db-001",
                "asset_name": "Production DB",
                "vulnerability_id": "CVE-DEMO-001",
                "identifier": "CVE-DEMO-001",
                "severity": "HIGH",
                "cvss_score": 8.5,
                "exploitability": "HIGH",
                "package": "demo-package",
                "installed_version": "1.0.0",
                "fixed_version": "1.0.1",
            }
        ]
    )

    # ---------------------------------------------------------
    # Run graph → risk pipeline
    # ---------------------------------------------------------

    assessments = assess_attack_path_risks(
        client
    )

    # ---------------------------------------------------------
    # Validate
    # ---------------------------------------------------------

    assert len(assessments) == 1

    assessment = assessments[0]

    vulnerability = assessment["vulnerability"]
    risk = assessment["risk"]
    attack_path = assessment["attack_path"]

    # Vulnerability came from Neo4j
    assert vulnerability["vulnerability_id"] == (
        "CVE-DEMO-001"
    )

    assert vulnerability["package"] == (
        "demo-package"
    )

    # Attack path came from Neo4j
    assert attack_path["path_length"] == 1

    # Risk engine used graph properties
    assert risk.factors["external_exposure"] == 20
    assert risk.factors["target_criticality"] == 20
    assert risk.factors["path_proximity"] == 6

    # HIGH + HIGH + external + critical target
    # = 30 + 20 + 20 + 20 + 6 = 96
    assert risk.score == 96

    assert risk.level == "CRITICAL"


def test_highest_attack_path_risk():

    client = make_client()

    client.find_attack_path = MagicMock(
        return_value={
            "path_length": 2,
            "nodes": [
                {
                    "asset_id": "internet-001",
                    "name": "Internet",
                    "type": "EXTERNAL",
                    "criticality": "HIGH",
                },
                {
                    "asset_id": "server-001",
                    "name": "Application Server",
                    "type": "SERVER",
                    "criticality": "HIGH",
                },
                {
                    "asset_id": "db-001",
                    "name": "Production DB",
                    "type": "DATABASE",
                    "criticality": "CRITICAL",
                },
            ],
        }
    )

    client.find_vulnerabilities_on_path = MagicMock(
        return_value=[
            {
                "asset_id": "server-001",
                "asset_name": "Application Server",
                "vulnerability_id": "CVE-LOW-001",
                "identifier": "CVE-LOW-001",
                "severity": "MEDIUM",
                "cvss_score": 5.0,
                "exploitability": "MEDIUM",
                "package": "package-a",
                "installed_version": "1.0.0",
                "fixed_version": "1.1.0",
            },
            {
                "asset_id": "db-001",
                "asset_name": "Production DB",
                "vulnerability_id": "CVE-HIGH-001",
                "identifier": "CVE-HIGH-001",
                "severity": "HIGH",
                "cvss_score": 9.0,
                "exploitability": "HIGH",
                "package": "package-b",
                "installed_version": "2.0.0",
                "fixed_version": "2.1.0",
            },
        ]
    )

    result = assess_attack_path_risk(
        client
    )

    assert result is not None

    # The HIGH vulnerability should produce
    # the higher risk score.
    assert result.level == "CRITICAL"
    assert result.score > 80


def test_no_attack_path():

    client = make_client()

    client.find_attack_path = MagicMock(
        return_value=None
    )

    result = assess_attack_path_risks(
        client
    )

    assert result == []


def test_no_vulnerabilities():

    client = make_client()

    client.find_attack_path = MagicMock(
        return_value={
            "path_length": 1,
            "nodes": [
                {
                    "asset_id": "internet-001",
                    "name": "Internet",
                    "type": "EXTERNAL",
                    "criticality": "HIGH",
                },
                {
                    "asset_id": "db-001",
                    "name": "Production DB",
                    "type": "DATABASE",
                    "criticality": "CRITICAL",
                },
            ],
        }
    )

    client.find_vulnerabilities_on_path = MagicMock(
        return_value=[]
    )

    result = assess_attack_path_risks(
        client
    )

    assert result == []
