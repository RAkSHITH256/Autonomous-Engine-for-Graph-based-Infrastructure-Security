from types import SimpleNamespace

from backend.reassessment.reassessment_engine import ReassessmentEngine


def vulnerability():
    return {
        "identifier": "CVE-TEST-001",
        "package": "demo-package",
        "installed_version": "1.0.0",
        "fixed_version": "1.0.1",
    }


def risk():
    return SimpleNamespace(
        score=52.0,
        level="MEDIUM",
    )


def test_resolved_verification_closes_finding():
    result = ReassessmentEngine().reassess(
        vulnerability(),
        {
            "status": "RESOLVED",
            "verified": True,
        },
        risk(),
    )

    assert result["status"] == "RESOLVED"
    assert result["action"] == "CLOSE_FINDING"
    assert result["current_risk"] == 0
    assert result["risk_level"] == "RESOLVED"


def test_not_verified_waits_for_remediation():
    result = ReassessmentEngine().reassess(
        vulnerability(),
        {
            "status": "NOT_VERIFIED",
            "verified": False,
        },
        risk(),
    )

    assert result["status"] == "WAITING"
    assert result["action"] == "WAIT_FOR_REMEDIATION"
    assert result["current_risk"] == 52.0


def test_failed_verification_requires_reassessment():
    result = ReassessmentEngine().reassess(
        vulnerability(),
        {
            "status": "VERIFICATION_FAILED",
            "verified": False,
        },
        risk(),
    )

    assert result["status"] == "REASSESS_REQUIRED"
    assert result["action"] == "REASSESS_RISK"
