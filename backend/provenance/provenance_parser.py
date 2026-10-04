import json
from pathlib import Path
from typing import Any

from backend.models.build_provenance import BuildProvenance


class ProvenanceParser:
    """
    Parses CI/CD build provenance produced by the AEGIS pipeline.
    """

    def parse_file(
        self,
        path: str | Path,
    ) -> BuildProvenance:
        """
        Parse a build-provenance.json file.
        """

        provenance_path = Path(path)

        if not provenance_path.exists():
            raise FileNotFoundError(
                f"Build provenance file not found: {provenance_path}"
            )

        with provenance_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data: dict[str, Any] = json.load(file)

        return self.parse(data)

    def parse(
        self,
        data: dict[str, Any],
    ) -> BuildProvenance:
        """
        Validate and normalize provenance data.
        """

        return BuildProvenance.model_validate(data)
