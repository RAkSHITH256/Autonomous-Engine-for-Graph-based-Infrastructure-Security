from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.graph.neo4j_client import Neo4jClient
from backend.risk.risk_engine import assess_attack_path_risks
from backend.decision.decision_engine import DecisionEngine
from backend.remediation.remediation_engine import RemediationEngine
from backend.remediation.remediation_executor import RemediationExecutor
from backend.remediation.verification_engine import VerificationEngine


app = FastAPI(
    title="AEGIS",
    description="Autonomous Engine for Graph-based Infrastructure Security",
    version="0.1.0",
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
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AEGIS",
        "version": "0.1.0",
    }


# ============================================================
# COMPLETE AEGIS RISK ANALYSIS
# ============================================================

@app.get("/risk")
def assess_risk():
    """
    Run the complete AEGIS security assessment.

    Pipeline:

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
       ↓
    Execution
       ↓
    Verification
    """

    client = Neo4jClient(
        "bolt://localhost:7687",
        "neo4j",
        "aegisdev",
    )

    try:

        # --------------------------------------------------------
        # 1. Attack path + vulnerability assessment
        # --------------------------------------------------------

        assessments = assess_attack_path_risks(client)

        if not assessments:
            return {
                "status": "no_risk_assessment",
                "message": "No vulnerable attack path was found.",
            }

        # --------------------------------------------------------
        # 2. Initialize engines
        # --------------------------------------------------------

        decision_engine = DecisionEngine()
        remediation_engine = RemediationEngine()

        # Safe mode:
        # No real infrastructure changes are performed.
        executor = RemediationExecutor(
            dry_run=True
        )

        verification_engine = VerificationEngine()

        vulnerability_results = []

        # --------------------------------------------------------
        # 3. Process every vulnerability
        # --------------------------------------------------------

        for assessment in assessments:

            vulnerability = assessment["vulnerability"]

            risk = assessment["risk"]

            attack_path = assessment["attack_path"]

            # ----------------------------------------------------
            # Risk → Decision
            # ----------------------------------------------------

            decision = decision_engine.decide(risk)

            # ----------------------------------------------------
            # Decision → Remediation Recommendation
            # ----------------------------------------------------

            remediation = (
                remediation_engine.generate_recommendation(
                    vulnerability=vulnerability,
                    decision=decision,
                )
            )

            # ----------------------------------------------------
            # Remediation → Executor
            #
            # We intentionally require approval.
            # ----------------------------------------------------

            execution = executor.execute(
                remediation=remediation,
                approved=False,
            )

            # ----------------------------------------------------
            # Executor → Verification
            # ----------------------------------------------------

            verification = verification_engine.verify(
                vulnerability=vulnerability,
                remediation=execution,
            )

            # ----------------------------------------------------
            # Store complete result
            # ----------------------------------------------------

            vulnerability_results.append({

                "vulnerability": vulnerability,

                "risk": {
                    "score": risk.score,
                    "level": risk.level,
                    "factors": risk.factors,
                    "explanation": risk.explanation,
                },

                "decision": decision,

                "remediation": remediation,

                "execution": execution,

                "verification": verification,

                "attack_path": attack_path,
            })

        # --------------------------------------------------------
        # 4. Determine overall risk
        # --------------------------------------------------------

        highest = max(
            vulnerability_results,
            key=lambda item: item["risk"]["score"],
        )

        # --------------------------------------------------------
        # 5. Return complete AEGIS response
        # --------------------------------------------------------

        return {
            "status": "success",

            "attack_path": {
                "path_length": assessments[0]["attack_path"]["path_length"],
                "nodes": assessments[0]["attack_path"]["nodes"],
            },

            "overall_risk": highest["risk"],

            "findings": vulnerability_results,

            "finding_count": len(vulnerability_results),
        }

    finally:

        client.close()


# ============================================================
# DASHBOARD API
# ============================================================

@app.get("/dashboard")
def dashboard():
    """
    Return a dashboard-friendly AEGIS security summary.
    """

    client = Neo4jClient(
        "bolt://localhost:7687",
        "neo4j",
        "aegisdev",
    )

    try:

        assessments = assess_attack_path_risks(client)

        # --------------------------------------------------------
        # No findings
        # --------------------------------------------------------

        if not assessments:

            return {
                "status": "success",

                "summary": {
                    "overall_risk": 0,
                    "risk_level": "LOW",
                    "finding_count": 0,
                },

                "attack_path": None,

                "findings": [],
            }

        # --------------------------------------------------------
        # Initialize engines
        # --------------------------------------------------------

        decision_engine = DecisionEngine()

        remediation_engine = RemediationEngine()

        findings = []

        # --------------------------------------------------------
        # Process findings
        # --------------------------------------------------------

        for assessment in assessments:

            vulnerability = assessment["vulnerability"]

            risk = assessment["risk"]

            attack_path = assessment["attack_path"]

            # Decision

            decision = decision_engine.decide(
                risk
            )

            # Remediation

            remediation = (
                remediation_engine.generate_recommendation(
                    vulnerability=vulnerability,
                    decision=decision,
                )
            )

            # Dashboard finding

            findings.append({

                "vulnerability_id":
                    vulnerability["identifier"],

                "asset":
                    vulnerability["asset_name"],

                "severity":
                    vulnerability["severity"],

                "cvss":
                    vulnerability["cvss_score"],

                "risk_score":
                    risk.score,

                "risk_level":
                    risk.level,

                "decision":
                    decision["action"],

                "priority":
                    decision["priority"],

                "remediation":
                    remediation["recommendation"],

            })

        # --------------------------------------------------------
        # Highest risk
        # --------------------------------------------------------

        highest = max(
            findings,
            key=lambda item: item["risk_score"],
        )

        # --------------------------------------------------------
        # Dashboard response
        # --------------------------------------------------------

        return {

            "status": "success",

            "summary": {

                "overall_risk":
                    highest["risk_score"],

                "risk_level":
                    highest["risk_level"],

                "finding_count":
                    len(findings),

            },

            "attack_path":
                attack_path,

            "findings":
                findings,

        }

    finally:

        client.close()

# ============================================================
# REMEDIATION EXECUTION API
# ============================================================

from fastapi import Query


@app.post("/remediate")
def remediate(
    vulnerability_id: str = Query(...),
    approved: bool = Query(False),
):
    """
    Execute remediation for a specific vulnerability.

    Safety:
    - Explicit approval is required.
    - Real execution remains disabled by default.
    - Verification runs after execution.
    """

    client = Neo4jClient(
        "bolt://localhost:7687",
        "neo4j",
        "aegisdev",
    )

    try:
        assessments = assess_attack_path_risks(client)

        if not assessments:
            return {
                "status": "no_risk_assessment",
                "message": "No vulnerable attack path was found.",
            }

        selected = None

        for assessment in assessments:
            vulnerability = assessment["vulnerability"]

            if vulnerability.get("identifier") == vulnerability_id:
                selected = assessment
                break

        if selected is None:
            return {
                "status": "not_found",
                "message": (
                    f"Vulnerability {vulnerability_id} "
                    "was not found."
                ),
            }

        vulnerability = selected["vulnerability"]
        risk = selected["risk"]

        decision_engine = DecisionEngine()
        remediation_engine = RemediationEngine()

        executor = RemediationExecutor(
            dry_run=True
        )

        verification_engine = VerificationEngine()

        # --------------------------------------------------------
        # Risk → Decision
        # --------------------------------------------------------

        decision = decision_engine.decide(risk)

        # --------------------------------------------------------
        # Decision → Remediation
        # --------------------------------------------------------

        remediation = (
            remediation_engine.generate_recommendation(
                vulnerability=vulnerability,
                decision=decision,
            )
        )

        # --------------------------------------------------------
        # Remediation → Executor
        # --------------------------------------------------------

        execution = executor.execute(
            remediation=remediation,
            approved=approved,
        )

        # --------------------------------------------------------
        # Executor → Verification
        # --------------------------------------------------------

        verification = verification_engine.verify(
            vulnerability=vulnerability,
            remediation=execution,
        )

        return {
            "status": "success",

            "vulnerability": vulnerability,

            "risk": {
                "score": risk.score,
                "level": risk.level,
                "factors": risk.factors,
                "explanation": risk.explanation,
            },

            "decision": decision,

            "remediation": remediation,

            "execution": execution,

            "verification": verification,
        }

    finally:
        client.close()