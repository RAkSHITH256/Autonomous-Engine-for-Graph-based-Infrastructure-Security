from backend.remediation.remediation_executor import RemediationExecutor


def make_remediation():
    return {
        "vulnerability": "CVE-DEMO-001",
        "remediation_action": "UPGRADE_PACKAGE",
        "package": "demo-package",
        "installed_version": "1.0.0",
        "fixed_version": "1.0.1",
        "priority": "P0",
    }


def test_requires_approval():

    executor = RemediationExecutor(dry_run=True)

    result = executor.execute(
        make_remediation(),
        approved=False,
    )

    assert result["status"] == "PENDING_APPROVAL"
    assert result["executed"] is False


def test_dry_run_upgrade():

    executor = RemediationExecutor(dry_run=True)

    result = executor.execute(
        make_remediation(),
        approved=True,
    )

    assert result["status"] == "DRY_RUN"
    assert result["executed"] is False
    assert result["dry_run"] is True
    assert result["simulated"] is False

    assert result["package"] == "demo-package"
    assert result["installed_version"] == "1.0.0"
    assert result["fixed_version"] == "1.0.1"


def test_simulated_success():

    executor = RemediationExecutor(
        dry_run=True,
        simulate_success=True,
    )

    result = executor.execute(
        make_remediation(),
        approved=True,
    )

    assert result["status"] == "EXECUTED"
    assert result["executed"] is True
    assert result["simulated"] is True
    assert result["current_version"] == "1.0.1"


def test_missing_fixed_version():

    executor = RemediationExecutor(dry_run=True)

    remediation = make_remediation()
    remediation["fixed_version"] = ""

    result = executor.execute(
        remediation,
        approved=True,
    )

    assert result["status"] == "FAILED"
    assert result["executed"] is False


def test_unsupported_action():

    executor = RemediationExecutor(dry_run=True)

    remediation = make_remediation()
    remediation["remediation_action"] = "DELETE_DATABASE"

    result = executor.execute(
        remediation,
        approved=True,
    )

    assert result["status"] == "UNSUPPORTED_ACTION"
    assert result["executed"] is False