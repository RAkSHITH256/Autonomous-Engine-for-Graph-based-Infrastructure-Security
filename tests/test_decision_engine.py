from backend.decision.decision_engine import DecisionEngine
from backend.models.risk import RiskScore


def make_risk(level):
    return RiskScore(
        score=90,
        level=level,
        factors={},
        explanation="Test risk",
    )


def test_critical_decision():
    engine = DecisionEngine()

    result = engine.decide(make_risk("CRITICAL"))

    assert result["action"] == "IMMEDIATE_REMEDIATION"
    assert result["priority"] == "P0"
    assert result["automated"] is True


def test_high_decision():
    engine = DecisionEngine()

    result = engine.decide(make_risk("HIGH"))

    assert result["action"] == "PRIORITIZE_REMEDIATION"
    assert result["priority"] == "P1"
    assert result["automated"] is False


def test_medium_decision():
    engine = DecisionEngine()

    result = engine.decide(make_risk("MEDIUM"))

    assert result["action"] == "SCHEDULE_REMEDIATION"
    assert result["priority"] == "P2"
    assert result["automated"] is False


def test_low_decision():
    engine = DecisionEngine()

    result = engine.decide(make_risk("LOW"))

    assert result["action"] == "MONITOR"
    assert result["priority"] == "P3"
    assert result["automated"] is False