from typing import Any
import os

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from backend.graph.neo4j_client import Neo4jClient
from backend.risk.risk_engine import assess_attack_path_risks
from backend.decision.decision_engine import DecisionEngine
from backend.remediation.remediation_engine import RemediationEngine
from backend.remediation.remediation_executor import RemediationExecutor
from backend.remediation.verification_engine import VerificationEngine
from backend.orchestration.security_loop import SecurityLoop


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="AEGIS",
    description="Autonomous Engine for Graph-based Infrastructure Security",
    version="0.1.0",
)


# ============================================================
# CONFIGURATION
# ============================================================

NEO4J_URI = os.getenv(
    "NEO4J_URI",
    "bolt://localhost:7687",
)

NEO4J_USERNAME = os.getenv(
    "NEO4J_USERNAME",
    "neo4j",
)

NEO4J_PASSWORD = os.getenv(
    "NEO4J_PASSWORD",
    "aegisdev",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# HELPERS
# ============================================================


def create_neo4j_client() -> Neo4jClient:
    """
    Create a Neo4j client using the current AEGIS configuration.
    """

    return Neo4jClient(
        NEO4J_URI,
        NEO4J_USERNAME,
        NEO4J_PASSWORD,
    )


def serialize_risk(risk: Any) -> dict[str, Any]:
    """
    Convert RiskScore into a JSON-compatible dictionary.
    """

    return {
        "score": risk.score,
        "level": risk.level,
        "factors": risk.factors,
        "explanation": risk.explanation,
    }


def analyze_assessments(
    assessments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Run the AEGIS decision and remediation planning stages
    for every vulnerability assessment.

    Execution is intentionally NOT performed here.
    """

    decision_engine = DecisionEngine()
    remediation_engine = RemediationEngine()

    results = []

    for assessment in assessments:

        vulnerability = assessment["vulnerability"]
        risk = assessment["risk"]
        attack_path = assessment["attack_path"]

        # ----------------------------------------------------
        # Risk -> Decision
        # ----------------------------------------------------

        decision = decision_engine.decide(risk)

        # ----------------------------------------------------
        # Decision -> Remediation
        # ----------------------------------------------------

        remediation = (
            remediation_engine.generate_recommendation(
                vulnerability=vulnerability,
                decision=decision,
            )
        )

        results.append(
            {
                "vulnerability": vulnerability,
                "risk": serialize_risk(risk),
                "decision": decision,
                "remediation": remediation,
                "attack_path": attack_path,
            }
        )

    return results


# ============================================================
# HEALTH CHECK
# ============================================================


@app.get("/health")
def health_check():
    """
    Basic AEGIS service health check.
    """

    return {
        "status": "healthy",
        "service": "AEGIS",
        "version": "0.1.0",
    }


# ============================================================
# RISK ANALYSIS
# ============================================================


@app.get("/risk")
def assess_risk():
    """
    Run the AEGIS risk-analysis pipeline.

    Graph
        ↓
    Attack Path
        ↓
    Vulnerability
        ↓
    Risk
        ↓
    Decision
        ↓
    Remediation
    """

    client = create_neo4j_client()

    try:

        # ----------------------------------------------------
        # Attack path + vulnerability assessment
        # ----------------------------------------------------

        assessments = assess_attack_path_risks(client)

        if not assessments:

            return {
                "status": "no_risk_assessment",
                "message": "No vulnerable attack path was found.",
                "finding_count": 0,
            }

        # ----------------------------------------------------
        # Decision + remediation planning
        # ----------------------------------------------------

        results = analyze_assessments(
            assessments
        )

        # ----------------------------------------------------
        # Highest risk
        # ----------------------------------------------------

        highest = max(
            results,
            key=lambda item: item["risk"]["score"],
        )

        # ----------------------------------------------------
        # Response
        # ----------------------------------------------------

        return {
            "status": "success",
            "attack_path": {
                "path_length": assessments[0][
                    "attack_path"
                ]["path_length"],
                "nodes": assessments[0][
                    "attack_path"
                ]["nodes"],
            },
            "overall_risk": highest["risk"],
            "findings": results,
            "finding_count": len(results),
        }

    finally:

        client.close()


@app.get("/dashboard")
def dashboard():
    """
    Dynamic AEGIS dashboard.

    The dashboard is generated directly from:

    Neo4j
        ↓
    Attack Path
        ↓
    Vulnerability
        ↓
    Risk Engine
        ↓
    Decision Engine
        ↓
    Remediation Engine
    """

    client = Neo4jClient(
        "bolt://localhost:7687",
        "neo4j",
        "aegisdev",
    )

    try:

        # ========================================================
        # 1. RUN REAL AEGIS RISK ENGINE
        # ========================================================

        assessments = assess_attack_path_risks(client)

        # ========================================================
        # 2. NO FINDINGS
        # ========================================================

        if not assessments:
            return {
                "status": "success",

                "summary": {
                    "overall_risk": 0,
                    "risk_level": "LOW",
                    "finding_count": 0,
                },

                "risk": {
                    "score": 0,
                    "level": "LOW",
                    "factors": [],
                    "explanation": "No vulnerable attack path found.",
                },

                "attack_path": None,

                "findings": [],

                "lifecycle": [
                    {
                        "title": "DETECT",
                        "description": "No findings detected",
                    }
                ],
            }

        # ========================================================
        # 3. INITIALIZE ENGINES
        # ========================================================

        decision_engine = DecisionEngine()
        remediation_engine = RemediationEngine()

        findings = []

        # ========================================================
        # 4. PROCESS EVERY REAL ASSESSMENT
        # ========================================================

        for assessment in assessments:

            vulnerability = assessment["vulnerability"]

            risk = assessment["risk"]

            attack_path = assessment["attack_path"]

            # ----------------------------------------------------
            # Risk → Decision
            # ----------------------------------------------------

            decision = decision_engine.decide(risk)

            # ----------------------------------------------------
            # Decision → Remediation
            # ----------------------------------------------------

            remediation = (
                remediation_engine.generate_recommendation(
                    vulnerability=vulnerability,
                    decision=decision,
                )
            )

            # ----------------------------------------------------
            # DYNAMIC FINDING
            # ----------------------------------------------------

            finding = {
                "vulnerability_id":
                    vulnerability.get(
                        "identifier",
                        vulnerability.get(
                            "vulnerability_id",
                            "UNKNOWN"
                        )
                    ),

                "asset":
                    vulnerability.get(
                        "asset_name",
                        vulnerability.get(
                            "asset_id",
                            "UNKNOWN"
                        )
                    ),

                "asset_id":
                    vulnerability.get(
                        "asset_id"
                    ),

                "severity":
                    vulnerability.get(
                        "severity",
                        "UNKNOWN"
                    ),

                "cvss":
                    vulnerability.get(
                        "cvss_score"
                    ),

                "exploitability":
                    vulnerability.get(
                        "exploitability"
                    ),

                "package":
                    vulnerability.get(
                        "package"
                    ),

                "installed_version":
                    vulnerability.get(
                        "installed_version"
                    ),

                "fixed_version":
                    vulnerability.get(
                        "fixed_version"
                    ),

                "risk_score":
                    risk.score,

                "risk_level":
                    risk.level,

                # IMPORTANT:
                # Keep the actual factors generated by
                # the risk engine.
                "risk_factors":
                    risk.factors,

                "risk_explanation":
                    risk.explanation,

                "decision":
                    decision.get(
                        "action",
                        "UNKNOWN"
                    ),

                "priority":
                    decision.get(
                        "priority",
                        "P3"
                    ),

                "decision_reason":
                    decision.get(
                        "reason"
                    ),

                "remediation":
                    remediation.get(
                        "recommendation",
                        "No recommendation available."
                    ),

                "attack_path":
                    attack_path,
            }

            findings.append(finding)

        # ========================================================
        # 5. FIND HIGHEST RISK
        # ========================================================

        highest = max(
            findings,
            key=lambda item: item["risk_score"],
        )

        # ========================================================
        # 6. EXTRACT REAL RISK DATA
        # ========================================================

        highest_risk = {
            "score":
                highest["risk_score"],

            "level":
                highest["risk_level"],

            "factors":
                highest.get(
                    "risk_factors",
                    []
                ),

            "explanation":
                highest.get(
                    "risk_explanation",
                    ""
                ),
        }

        # ========================================================
        # 7. RETURN COMPLETE DYNAMIC DASHBOARD
        # ========================================================

        return {

            "status": "success",

            # ----------------------------------------------------
            # Summary
            # ----------------------------------------------------

            "summary": {

                "overall_risk":
                    highest["risk_score"],

                "risk_level":
                    highest["risk_level"],

                "finding_count":
                    len(findings),

                "risk_description":
                    highest_risk[
                        "explanation"
                    ],
            },

            # ----------------------------------------------------
            # Complete risk engine output
            # ----------------------------------------------------

            "risk": highest_risk,

            # ----------------------------------------------------
            # Real Neo4j attack path
            # ----------------------------------------------------

            "attack_path":
                highest["attack_path"],

            # ----------------------------------------------------
            # Real findings
            # ----------------------------------------------------

            "findings":
                findings,

            # ----------------------------------------------------
            # Security lifecycle
            # ----------------------------------------------------

            "lifecycle": [

                {
                    "title": "DETECT",
                    "description":
                        "Vulnerability discovered"
                },

                {
                    "title": "ANALYZE",
                    "description":
                        "Risk calculated"
                },

                {
                    "title": "DECIDE",
                    "description":
                        "Priority determined"
                },

                {
                    "title": "REMEDIATE",
                    "description":
                        "Remediation generated"
                },

                {
                    "title": "VERIFY",
                    "description":
                        "Remediation verification"
                },

                {
                    "title": "REASSESS",
                    "description":
                        "Risk reassessment"
                },
            ],
        }

    finally:

        client.close()