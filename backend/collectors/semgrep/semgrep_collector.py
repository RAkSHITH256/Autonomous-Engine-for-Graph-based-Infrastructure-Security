import json
import subprocess
from typing import Any


class SemgrepCollector:
    """
    Runs Semgrep against a source-code target and returns
    the raw Semgrep JSON results.
    """

    def __init__(
        self,
        target: str = ".",
        config: str = "auto",
    ):
        self.target = target
        self.config = config

    def scan(self) -> dict[str, Any]:
        """
        Execute Semgrep and return its JSON output.
        """

        command = [
            "semgrep",
            "--json",
            "--config",
            self.config,
            self.target,
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        if not process.stdout.strip():
            return {
                "results": [],
                "errors": [
                    process.stderr.strip()
                ] if process.stderr.strip() else [],
            }

        try:
            result = json.loads(process.stdout)
        except json.JSONDecodeError:
            return {
                "results": [],
                "errors": [
                    "Semgrep returned invalid JSON.",
                    process.stderr.strip(),
                ],
            }

        return result
