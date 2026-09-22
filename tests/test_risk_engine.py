from backend.risk.risk_engine import assess_risk


def test_critical_risk():

    vulnerability = {
        "severity": "HIGH",
        "exploitability": "HIGH",
    }

    attack_path = {
        "external_exposure": True,
        "target_criticality": "CRITICAL",
        "path_length": 1,
    }

    risk = assess_risk(
        vulnerability=vulnerability,
        attack_path=attack_path,
    )

    assert risk.score == 96
    assert risk.level == "CRITICAL"


def test_risk_contains_factors():

    vulnerability = {
        "severity": "HIGH",
        "exploitability": "HIGH",
    }

    attack_path = {
        "external_exposure": True,
        "target_criticality": "CRITICAL",
        "path_length": 1,
    }

    risk = assess_risk(
        vulnerability=vulnerability,
        attack_path=attack_path,
    )

    assert "vulnerability_severity" in risk.factors
    assert "exploitability" in risk.factors
    assert "external_exposure" in risk.factors
    assert "target_criticality" in risk.factors
    assert "path_proximity" in risk.factors