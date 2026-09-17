from backend.models.risk import RiskScore


def calculate_risk(
    vulnerability_severity: str,
    exploitability: str,
    externally_reachable: bool,
    target_criticality: str,
    path_length: int,
) -> RiskScore:

    score = 0.0
    factors = {}

    # Vulnerability severity
    severity_scores = {
        "LOW": 10,
        "MEDIUM": 20,
        "HIGH": 30,
        "CRITICAL": 40,
    }

    vulnerability_score = severity_scores.get(
        vulnerability_severity.upper(), 0
    )

    score += vulnerability_score
    factors["vulnerability_severity"] = vulnerability_score

    # Exploitability
    exploitability_scores = {
        "LOW": 5,
        "MEDIUM": 10,
        "HIGH": 20,
    }

    exploitability_score = exploitability_scores.get(
        exploitability.upper(), 0
    )

    score += exploitability_score
    factors["exploitability"] = exploitability_score

    # External exposure
    exposure_score = 20 if externally_reachable else 0

    score += exposure_score
    factors["external_exposure"] = exposure_score

    # Target criticality
    criticality_scores = {
        "LOW": 5,
        "MEDIUM": 10,
        "HIGH": 15,
        "CRITICAL": 20,
    }

    criticality_score = criticality_scores.get(
        target_criticality.upper(), 0
    )

    score += criticality_score
    factors["target_criticality"] = criticality_score

    # Shorter attack paths are generally easier to traverse
    path_score = max(0, 10 - path_length)

    score += path_score
    factors["path_proximity"] = path_score

    # Keep score within 0-100
    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

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

from backend.graph.neo4j_client import Neo4jClient


def assess_attack_path_risk(client: Neo4jClient):
    attack_path = client.find_attack_path()

    if attack_path is None:
        return None

    vulnerabilities = client.find_vulnerabilities_on_path()

    if not vulnerabilities:
        return None

    vulnerability = vulnerabilities[0]

    target = attack_path["nodes"][-1]

    target_criticality = target.get("criticality") or "UNKNOWN"

    externally_reachable = (
        attack_path["nodes"][0].get("type") == "EXTERNAL"
    )

    risk = calculate_risk(
        vulnerability_severity=vulnerability["severity"],
        exploitability=vulnerability["exploitability"],
        externally_reachable=externally_reachable,
        target_criticality=target_criticality,
        path_length=attack_path["path_length"],
    )

    return risk