from typing import Any

from backend.models.finding import Finding


def parse_semgrep_results(
    semgrep_output: dict[str, Any],
    asset_id: str = "aegis-application",
) -> list[Finding]:
    """
    Convert raw Semgrep results into normalized AEGIS Finding objects.

    Semgrep is a source-code security scanner, so Semgrep-specific
    information such as rule ID, file path, and source location is
    preserved in the finding metadata.
    """

    findings: list[Finding] = []

    for index, result in enumerate(
        semgrep_output.get("results", [])
    ):
        check_id = result.get(
            "check_id",
            "UNKNOWN",
        )

        extra = result.get(
            "extra",
            {},
        )

        message = extra.get(
            "message",
            "",
        )

        severity = str(
            extra.get(
                "severity",
                "INFO",
            )
        ).upper()

        metadata = extra.get(
            "metadata",
            {},
        )

        start = result.get(
            "start",
            {},
        )

        end = result.get(
            "end",
            {},
        )

        file_path = result.get(
            "path",
            "UNKNOWN",
        )

        start_line = start.get(
            "line",
            0,
        )

        end_line = end.get(
            "line",
            0,
        )

        # Use the result index to guarantee uniqueness even when
        # the same Semgrep rule appears multiple times.
        finding_id = (
            f"semgrep-{check_id}-"
            f"{file_path}-{start_line}-{index}"
        )

        finding = Finding(
            finding_id=finding_id,
            category="code_security",
            severity=severity,
            title=check_id,
            description=(
                message
                or f"Semgrep rule {check_id} detected a security issue."
            ),
            asset_id=asset_id,
            metadata={
                "source": "SEMGREP",
                "rule_id": check_id,
                "file": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "semgrep_metadata": metadata,
            },
        )

        findings.append(finding)

    return findings