from typing import Any


def parse_semgrep_results(
    semgrep_output: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Convert raw Semgrep findings into normalized AEGIS
    vulnerability records.
    """

    findings = []

    for result in semgrep_output.get("results", []):

        check_id = result.get(
            "check_id",
            "UNKNOWN",
        )

        message = (
            result.get("extra", {})
            .get("message", "")
        )

        severity = (
            result.get("extra", {})
            .get("severity", "INFO")
            .upper()
        )

        metadata = (
            result.get("extra", {})
            .get("metadata", {})
        )

        start = result.get(
            "start",
            {},
        )

        end = result.get(
            "end",
            {},
        )

        finding = {
            "source": "semgrep",
            "vulnerability_id": check_id,
            "identifier": check_id,
            "severity": severity,
            "message": message,
            "file": result.get(
                "path",
                "UNKNOWN",
            ),
            "start_line": start.get(
                "line",
                0,
            ),
            "end_line": end.get(
                "line",
                0,
            ),
            "metadata": metadata,
        }

        findings.append(finding)

    return findings