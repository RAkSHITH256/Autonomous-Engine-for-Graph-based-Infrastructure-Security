from backend.remediation.verification_engine import VerificationEngine


def vulnerability():
    return {
        "identifier": "CVE-TEST-001",
        "package": "demo-package",
        "installed_version": "1.0.0",
        "fixed_version": "1.0.1",
    }


def test_pending_approval_is_not_verified():
    result = VerificationEngine().verify(
        vulnerability(),
        {"status": "PENDING_APPROVAL"},
    )

    assert result["status"] == "NOT_VERIFIED"
    assert result["verified"] is False


def test_failed_remediation_fails_verification():
    result = VerificationEngine().verify(
        vulnerability(),
        {"status": "FAILED"},
    )

    assert result["status"] == "VERIFICATION_FAILED"
    assert result["verified"] is False


def test_executed_fixed_version_is_resolved():
    result = VerificationEngine().verify(
        vulnerability(),
        {
            "status": "EXECUTED",
            "current_version": "1.0.1",
        },
    )

    assert result["status"] == "RESOLVED"
    assert result["verified"] is True
    assert result["current_version"] == "1.0.1"


def test_executed_wrong_version_fails_verification():
    result = VerificationEngine().verify(
        vulnerability(),
        {
            "status": "EXECUTED",
            "current_version": "1.0.0",
        },
    )

    assert result["status"] == "VERIFICATION_FAILED"
    assert result["verified"] is False


def test_unknown_status_is_unknown():
    result = VerificationEngine().verify(
        vulnerability(),
        {"status": "SOMETHING_UNKNOWN"},
    )

    assert result["status"] == "UNKNOWN"
    assert result["verified"] is False
