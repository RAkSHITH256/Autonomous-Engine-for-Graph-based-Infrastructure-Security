from unittest.mock import MagicMock

from backend.graph.graph_builder import GraphBuilder
from backend.risk.risk_engine import assess_attack_path_risks
from backend.decision.decision_engine import DecisionEngine
from backend.remediation.remediation_engine import RemediationEngine
from backend.remediation.remediation_executor import RemediationExecutor
from backend.remediation.verification_engine import VerificationEngine
from backend.reassessment.reassessment_engine import ReassessmentEngine


def make_graph_client():
    """
    Create a mocked Neo4j client.

    The test validates the AEGIS pipeline without
    requiring a running Neo4j server.
    """

    client = MagicMock()

    client.find_attack_path.return_value = {
        "path_length": 3,
        "nodes": [
            {
                "asset_id": "internet-001",
                "name": "Internet",
                "type": "EXTERNAL",
                "criticality": "HIGH",
            },
            {
                "asset_id": "web-001",
                "name": "Web Server",
                "type": "WEB_SERVER",
                "criticality": "HIGH",
            },
            {
                "asset_id": "app-001",
                "name": "Application Server",
                "type": "APPLICATION",
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

    client.find_vulnerabilities_on_path.return_value = [
        {
            "asset_id": "app-001",
            "asset_name": "Application Server",
            "vulnerability_id": "CVE-AEGIS-001",
            "identifier": "CVE-AEGIS-001",
            "severity": "HIGH",
            "cvss_score": 8.5,
            "exploitability": "HIGH",
            "package": "demo-package",
            "installed_version": "1.0.0",
            "fixed_version": "1.0.1",
        }
    ]

    return client


def test_full_aegis_security_pipeline():
    """
    Validate the complete AEGIS security lifecycle:

        Graph
          ↓
        Risk
          ↓
        Decision
          ↓
        Remediation
          ↓
        Execution
          ↓
        Verification
          ↓
        Reassessment
    """

    # =========================================================
    # 1. GRAPH
    # =========================================================

    client = make_graph_client()

    assessments = assess_attack_path_risks(client)

    assert len(assessments) == 1

    assessment = assessments[0]

    vulnerability = assessment["vulnerability"]
    risk = assessment["risk"]

    assert vulnerability["vulnerability_id"] == (
        "CVE-AEGIS-001"
    )

    assert vulnerability["package"] == (
        "demo-package"
    )

    assert risk.score > 0

    assert risk.level in {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    # =========================================================
    # 2. DECISION
    # =========================================================

    decision_engine = DecisionEngine()

    decision = decision_engine.decide(risk)

    assert decision is not None

    # =========================================================
    # 3. REMEDIATION PLANNING
    # =========================================================

    remediation_engine = RemediationEngine()

    remediation = (
        remediation_engine.generate_recommendation(
            vulnerability=vulnerability,
            decision=decision,
        )
    )

    assert remediation is not None

    # The vulnerability contains a fixed version,
    # so package remediation should be possible.
    assert remediation["package"] == (
        "demo-package"
    )

    # =========================================================
    # 4. REMEDIATION EXECUTION
    # =========================================================

    executor = RemediationExecutor(
        dry_run=True,
        simulate_success=True,
    )

    execution = executor.execute(
        remediation=remediation,
        approved=True,
    )

    assert execution["status"] == "EXECUTED"
    assert execution["executed"] is True
    assert execution["simulated"] is True

    # =========================================================
    # 5. VERIFICATION
    # =========================================================

    verification_engine = VerificationEngine()

    verification = verification_engine.verify(
        vulnerability=vulnerability,
        remediation=execution,
    )

    assert verification is not None

    # =========================================================
    # 6. REASSESSMENT
    # =========================================================

    reassessment_engine = ReassessmentEngine()

    reassessment = reassessment_engine.reassess(
        vulnerability=vulnerability,
        verification=verification,
        current_risk=risk,
    )

    assert reassessment is not None

    assert "status" in reassessment


def test_graph_builder_and_risk_pipeline():

    """
    Validate that GraphBuilder can construct the expected
    AEGIS graph structure before risk assessment.
    """

    client = MagicMock()

    builder = GraphBuilder(client)

    builder.add_asset = MagicMock()
    builder.connect_assets = MagicMock()
    builder.add_vulnerability = MagicMock()

    builder.build_demo_graph()

    # Four assets:
    #
    # Internet
    # Web Server
    # Application Server
    # Production DB

    assert builder.add_asset.call_count == 4

    # Three network relationships:

    assert builder.connect_assets.call_count == 3

    # One vulnerability:

    assert builder.add_vulnerability.call_count == 1