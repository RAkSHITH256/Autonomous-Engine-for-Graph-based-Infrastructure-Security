from typing import Any

from backend.models.risk import RiskScore
from backend.graph.neo4j_client import Neo4jClient


# =============================================================
# RISK CALCULATION
# =============================================================

def calculate_risk(
    vulnerability_severity: str,
    exploitability: str,
    externally_reachable: bool,
    target_criticality: str,
    path_length: int,
) -> RiskScore:
    """
    Calculate contextual AEGIS risk.

    Factors:
        - vulnerability severity
        - exploitability
        - external exposure
        - target criticality
        - attack-path proximity
    """

    score = 0.0
    factors: dict[str, float] = {}

    # ---------------------------------------------------------
    # Vulnerability severity
    # ---------------------------------------------------------

    severity_scores = {
        "LOW": 10,
        "MEDIUM": 20,
        "HIGH": 30,
        "CRITICAL": 40,
    }

    severity_value = (
        str(vulnerability_severity).upper()
        if vulnerability_severity is not None
        else "UNKNOWN"
    )

    vulnerability_score = severity_scores.get(
        severity_value,
        0,
    )

    score += vulnerability_score

    factors["vulnerability_severity"] = float(
        vulnerability_score
    )

    # ---------------------------------------------------------
    # Exploitability
    # ---------------------------------------------------------

    exploitability_scores = {
        "LOW": 5,
        "MEDIUM": 10,
        "HIGH": 20,
        "CRITICAL": 20,
    }

    exploitability_value = (
        str(exploitability).upper()
        if exploitability is not None
        else "UNKNOWN"
    )

    exploitability_score = exploitability_scores.get(
        exploitability_value,
        0,
    )

    score += exploitability_score

    factors["exploitability"] = float(
        exploitability_score
    )

    # ---------------------------------------------------------
    # External exposure
    # ---------------------------------------------------------

    exposure_score = (
        20
        if externally_reachable
        else 0
    )

    score += exposure_score

    factors["external_exposure"] = float(
        exposure_score
    )

    # ---------------------------------------------------------
    # Target criticality
    # ---------------------------------------------------------

    criticality_scores = {
        "LOW": 5,
        "MEDIUM": 10,
        "HIGH": 15,
        "CRITICAL": 20,
    }

    criticality_value = (
        str(target_criticality).upper()
        if target_criticality is not None
        else "UNKNOWN"
    )

    criticality_score = criticality_scores.get(
        criticality_value,
        0,
    )

    score += criticality_score

    factors["target_criticality"] = float(
        criticality_score
    )

    # ---------------------------------------------------------
    # Path proximity
    # ---------------------------------------------------------

    path_score = max(
        0,
        7 - path_length,
    )

    score += path_score

    factors["path_proximity"] = float(
        path_score
    )

    # ---------------------------------------------------------
    # Maximum score
    # ---------------------------------------------------------

    score = min(
        score,
        100,
    )

    # ---------------------------------------------------------
    # Risk level
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
    # Explanation
    # ---------------------------------------------------------

    exposure_description = (
        "is externally reachable"
        if externally_reachable
        else "is not externally reachable"
    )

    explanation = (
        f"Risk is {level} because the asset has a "
        f"{severity_value} vulnerability "
        f"with {exploitability_value} exploitability "
        f"and the attack path {exposure_description}."
    )

    if criticality_value != "UNKNOWN":
        explanation += (
            f" The attack path reaches a "
            f"{criticality_value} target."
        )

    return RiskScore(
        score=score,
        level=level,
        factors=factors,
        explanation=explanation,
    )


# =============================================================
# SINGLE VULNERABILITY ASSESSMENT
# =============================================================

def assess_risk(
    vulnerability: dict[str, Any],
    attack_path: dict[str, Any],
) -> RiskScore:
    """
    Assess one vulnerability in attack-path context.

    Supports both:

    1. Legacy/test attack-path format:

        {
            "external_exposure": True,
            "target_criticality": "CRITICAL",
            "path_length": 1
        }

    2. Graph-derived AEGIS attack-path format:

        {
            "path_length": 4,
            "nodes": [...]
        }
    """

    # ---------------------------------------------------------
    # PATH LENGTH
    # ---------------------------------------------------------

    path_length = attack_path.get(
        "path_length",
        0,
    )

    # Ensure path length is numeric
    try:
        path_length = int(path_length)
    except (TypeError, ValueError):
        path_length = 0

    # ---------------------------------------------------------
    # EXTERNAL EXPOSURE
    # ---------------------------------------------------------

    if "external_exposure" in attack_path:

        # Preserve existing AEGIS/test behaviour.
        externally_reachable = bool(
            attack_path.get(
                "external_exposure"
            )
        )

    else:

        # Derive exposure from the graph.
        nodes = attack_path.get(
            "nodes",
            [],
        )

        externally_reachable = False

        if nodes:
            externally_reachable = (
                nodes[0].get("type")
                == "EXTERNAL"
            )

    # ---------------------------------------------------------
    # TARGET CRITICALITY
    # ---------------------------------------------------------

    if "target_criticality" in attack_path:

        # Preserve existing AEGIS/test behaviour.
        target_criticality = (
            attack_path.get(
                "target_criticality"
            )
            or "UNKNOWN"
        )

    else:

        nodes = attack_path.get(
            "nodes",
            [],
        )

        target_criticality = "UNKNOWN"

        # Prefer the asset carrying the vulnerability.
        vulnerable_asset_id = vulnerability.get(
            "asset_id"
        )

        for node in nodes:

            if (
                node.get("asset_id")
                == vulnerable_asset_id
            ):
                target_criticality = (
                    node.get(
                        "criticality"
                    )
                    or "UNKNOWN"
                )
                break

        # If the vulnerable asset has no criticality,
        # use the final known critical target as fallback.
        if target_criticality == "UNKNOWN":

            for node in reversed(nodes):

                criticality = node.get(
                    "criticality"
                )

                if criticality:
                    target_criticality = criticality
                    break

    # ---------------------------------------------------------
    # CALCULATE
    # ---------------------------------------------------------

    return calculate_risk(
        vulnerability_severity=(
            vulnerability.get(
                "severity",
                "UNKNOWN",
            )
        ),
        exploitability=(
            vulnerability.get(
                "exploitability",
                "UNKNOWN",
            )
        ),
        externally_reachable=(
            externally_reachable
        ),
        target_criticality=(
            target_criticality
        ),
        path_length=(
            path_length
        ),
    )


# =============================================================
# LEGACY ATTACK-PATH ANALYSIS
# =============================================================

def _assess_legacy_attack_path(
    client: Neo4jClient,
) -> list[dict[str, Any]]:
    """
    Compatibility path for the original AEGIS graph API.

    This preserves existing tests and older integrations.

        find_attack_path()
                ↓
        find_vulnerabilities_on_path()
                ↓
        assess_risk()
    """

    attack_path = client.find_attack_path()

    if not attack_path:
        return []

    vulnerabilities = (
        client.find_vulnerabilities_on_path()
    )

    assessments: list[
        dict[str, Any]
    ] = []

    for vulnerability in vulnerabilities:

        risk = assess_risk(
            vulnerability=vulnerability,
            attack_path=attack_path,
        )

        assessments.append(
            {
                "vulnerability": vulnerability,
                "risk": risk,
                "attack_path": attack_path,
            }
        )

    return assessments


# =============================================================
# DYNAMIC ATTACK-PATH ANALYSIS
# =============================================================

def assess_attack_path_risks(
    client: Neo4jClient,
) -> list[dict[str, Any]]:
    """
    Primary AEGIS risk-analysis function.

    First attempts dynamic discovery:

        Internet
            ↓
        reachable assets
            ↓
        vulnerable assets
            ↓
        vulnerabilities
            ↓
        risk

    If no dynamically discovered vulnerable path exists,
    falls back to the original AEGIS attack-path implementation.

    This keeps backward compatibility while allowing AEGIS
    to analyze real infrastructure dynamically.
    """

    # =========================================================
    # 1. DYNAMIC DISCOVERY
    # =========================================================

    discovered_paths = (
        client.find_vulnerable_attack_paths()
    )

    assessments: list[
        dict[str, Any]
    ] = []

    # ---------------------------------------------------------
    # Process dynamic paths
    # ---------------------------------------------------------

    for discovered in discovered_paths:

        attack_path = discovered[
            "attack_path"
        ]

        vulnerabilities = (
            client.find_vulnerabilities_for_path(
                attack_path
            )
        )

        for vulnerability in vulnerabilities:

            risk = assess_risk(
                vulnerability=vulnerability,
                attack_path=attack_path,
            )

            assessments.append(
                {
                    "vulnerability": vulnerability,
                    "risk": risk,
                    "attack_path": attack_path,
                }
            )

    # =========================================================
    # 2. FALLBACK TO LEGACY GRAPH
    # =========================================================

    if not assessments:

        assessments = (
            _assess_legacy_attack_path(
                client
            )
        )

    # =========================================================
    # 3. DEDUPLICATE
    # =========================================================

    unique: dict[
        tuple[str, tuple[str, ...]],
        dict[str, Any],
    ] = {}

    for assessment in assessments:

        vulnerability = assessment[
            "vulnerability"
        ]

        attack_path = assessment[
            "attack_path"
        ]

        vulnerability_id = (
            vulnerability.get(
                "vulnerability_id",
                vulnerability.get(
                    "identifier",
                    "UNKNOWN",
                ),
            )
        )

        path_nodes = tuple(
            node.get(
                "asset_id",
                "",
            )
            for node in attack_path.get(
                "nodes",
                [],
            )
        )

        key = (
            vulnerability_id,
            path_nodes,
        )

        existing = unique.get(key)

        if existing is None:

            unique[key] = assessment

        elif (
            assessment["risk"].score
            > existing["risk"].score
        ):

            unique[key] = assessment

    # =========================================================
    # 4. SORT HIGHEST RISK FIRST
    # =========================================================

    return sorted(
        unique.values(),
        key=lambda item: (
            item["risk"].score
        ),
        reverse=True,
    )


# =============================================================
# SINGLE HIGHEST-RISK RESULT
# =============================================================

def assess_attack_path_risk(
    client: Neo4jClient,
):
    """
    Backward-compatible single-risk API.

    Returns the highest-risk RiskScore object.

    The plural assess_attack_path_risks() API returns
    detailed assessment dictionaries.
    """

    assessments = assess_attack_path_risks(
        client
    )

    if not assessments:
        return None

    return assessments[0]["risk"]