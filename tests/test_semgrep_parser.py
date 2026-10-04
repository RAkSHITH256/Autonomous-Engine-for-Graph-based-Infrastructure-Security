from backend.collectors.semgrep.semgrep_parser import (
    parse_semgrep_results,
)
from backend.models.finding import Finding


def test_semgrep_parser():

    semgrep_output = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "app.py",
                "start": {
                    "line": 10,
                },
                "end": {
                    "line": 10,
                },
                "extra": {
                    "message": "Detected use of eval().",
                    "severity": "WARNING",
                    "metadata": {
                        "category": "security",
                    },
                },
            }
        ]
    }

    findings = parse_semgrep_results(
        semgrep_output,
        asset_id="aegis-application",
    )

    assert len(findings) == 1

    finding = findings[0]

    assert isinstance(finding, Finding)
    assert finding.category == "code_security"
    assert finding.severity == "WARNING"
    assert finding.title == (
        "python.lang.security.audit.eval-detected"
    )
    assert finding.description == "Detected use of eval()."
    assert finding.asset_id == "aegis-application"

    assert finding.metadata["source"] == "SEMGREP"
    assert finding.metadata["rule_id"] == (
        "python.lang.security.audit.eval-detected"
    )
    assert finding.metadata["file"] == "app.py"
    assert finding.metadata["start_line"] == 10
    assert finding.metadata["end_line"] == 10


def test_semgrep_parser_empty():

    findings = parse_semgrep_results(
        {
            "results": []
        },
        asset_id="aegis-application",
    )

    assert findings == []