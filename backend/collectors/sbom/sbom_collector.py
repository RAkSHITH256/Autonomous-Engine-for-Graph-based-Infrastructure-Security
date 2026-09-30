from pathlib import Path
from typing import Any


class SBOMCollector:
    """
    Loads an existing CycloneDX or SPDX SBOM file.

    The collector intentionally does not generate an SBOM itself.
    Generation can be added later using Syft or another SBOM tool.
    """

    SUPPORTED_FORMATS = {
        ".json",
        ".xml",
    }

    def collect(self, sbom_path: str | Path) -> dict[str, Any]:
        path = Path(sbom_path)

        if not path.exists():
            raise FileNotFoundError(
                f"SBOM file not found: {path}"
            )

        if not path.is_file():
            raise ValueError(
                f"SBOM path is not a file: {path}"
            )

        if path.suffix.lower() not in self.SUPPORTED_FORMATS:
            raise ValueError(
                f"Unsupported SBOM format: {path.suffix}"
            )

        return {
            "path": str(path),
            "format": path.suffix.lower().lstrip("."),
        }