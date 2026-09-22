from backend.models.risk import RiskScore
from backend.graph.neo4j_client import Neo4jClient


def calculate_risk(
    vulnerability_severity: str,
    exploitability: str,
    externally_reachable: bool,
    target_criticality: str,
    path_length: int,
) -> RiskScore:
    """
    Core AEGIS risk calculation engine.
    """

    score = 0.0
    factors = {}

    # ---------------------------------------------------------
    # 1. Vulnerability severity
    # ---------------------------------------------------------

    severity_scores = {
        "LOW": 10,
        "MEDIUM": 20,
        "HIGH": 30,
        "CRITICAL": 40,
    }

    vulnerability_score = severity_scores.get(
        vulnerability_severity.upper(),
        0,
    )

    score += vulnerability_score
    factors["vulnerability_severity"] = vulnerability_score

    # ---------------------------------------------------------
    # 2. Exploitability
    # ---------------------------------------------------------

    exploitability_scores = {
        "LOW": 5,
        "MEDIUM": 10,
        "HIGH": 20,
        "CRITICAL": 20,
    }

    exploitability_score = exploitability_scores.get(
        exploitability.upper(),
        0,
    )

    score += exploitability_score
    factors["exploitability"] = exploitability_score

    # ---------------------------------------------------------
    # 3. External exposure
    # ---------------------------------------------------------

    exposure_score = 20 if externally_reachable else 0

    score += exposure_score
    factors["external_exposure"] = exposure_score

    # ---------------------------------------------------------
    # 4. Target criticality
    # ---------------------------------------------------------

    criticality_scores = {
        "LOW": 5,
        "MEDIUM": 10,
        "HIGH": 15,
        "CRITICAL": 20,
    }

    criticality_score = criticality_scores.get(
        target_criticality.upper(),
        0,
    )

    score += criticality_score
    factors["target_criticality"] = criticality_score

    # ---------------------------------------------------------
    # 5. Attack-path proximity
    # ---------------------------------------------------------

    path_score = max(0, 7 - path_length)

    score += path_score
    factors["path_proximity"] = path_score

    # ---------------------------------------------------------
    # 6. Normalize
    # ---------------------------------------------------------

    score = min(score, 100)

    # ---------------------------------------------------------
    # 7. Risk level
    # ---------------------------------------------------------

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    # ---------------------------------------------------------
    # 8. Explanation
    # ---------------------------------------------------------

    explanation = (
        f"Risk is {level} because the asset has a "
        f"{vulnerability_severity} vulnerability with "
        f"{exploitability} exploitability and the attack path "
        f"reaches a {target_criticality} target."
    )

    return RiskScore(
        score=score,
        level=level,
        factors=factors,
        explanation=explanation,
    )


def assess_risk(
    vulnerability: dict,
    attack_path: dict,
) -> RiskScore:
    """
    Public risk-assessment interface.

    Accepts the vulnerability and attack-path dictionaries
    used throughout AEGIS.
    """

    vulnerability_severity = vulnerability.get(
        "severity",
        "UNKNOWN",
    )

    exploitability = vulnerability.get(
        "exploitability",
        "UNKNOWN",
    )

    externally_reachable = attack_path.get(
        "external_exposure",
        False,
    )

    target_criticality = attack_path.get(
        "target_criticality",
        "UNKNOWN",
    )

    path_length = attack_path.get(
        "path_length",
        0,
    )

    return calculate_risk(
        vulnerability_severity=vulnerability_severity,
        exploitability=exploitability,
        externally_reachable=externally_reachable,
        target_criticality=target_criticality,
        path_length=path_length,
    )


def assess_attack_path_risks(client: Neo4jClient):
    """
    Calculate risk independently for every vulnerability
    found on the attack path.
    """

    attack_path = client.find_attack_path()

    if attack_path is None:
        return []

    vulnerabilities = client.find_vulnerabilities_on_path()

    if not vulnerabilities:
        return []

    target = attack_path["nodes"][-1]

    target_criticality = (
        target.get("criticality") or "UNKNOWN"
    )

    externally_reachable = (
        attack_path["nodes"][0].get("type") == "EXTERNAL"
    )

    assessments = []

    for vulnerability in vulnerabilities:

        risk = assess_risk(
            vulnerability=vulnerability,
            attack_path={
                "external_exposure": externally_reachable,
                "target_criticality": target_criticality,
                "path_length": attack_path["path_length"],
            },
        )

        assessments.append({
            "vulnerability": vulnerability,
            "risk": risk,
            "attack_path": attack_path,
        })

    return assessments


def assess_attack_path_risk(client: Neo4jClient):
    """
    Backward-compatible helper.

    Returns the highest-risk vulnerability so existing
    callers continue to work.
    """

    assessments = assess_attack_path_risks(client)

    if not assessments:
        return None

    highest = max(
        assessments,
        key=lambda item: item["risk"].score,
    )

    return highest["risk"]