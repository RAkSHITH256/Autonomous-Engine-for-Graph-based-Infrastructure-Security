from backend.collectors.semgrep.semgrep_parser import (
    parse_semgrep_results,
)


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
        semgrep_output
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding["source"] == "semgrep"
    assert finding["vulnerability_id"] == (
        "python.lang.security.audit.eval-detected"
    )
    assert finding["file"] == "app.py"
    assert finding["start_line"] == 10
    assert finding["severity"] == "WARNING"


def test_semgrep_parser_empty():

    findings = parse_semgrep_results(
        {
            "results": []
        }
    )

    assert findings == []