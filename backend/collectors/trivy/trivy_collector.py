import json
import subprocess
from datetime import datetime, timezone

from backend.models.evidence import SecurityEvidence


class TrivyCollector:

    def scan_image(self, image: str) -> SecurityEvidence:
        command = [
            "trivy",
            "image",
            "--format",
            "json",
            image,
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )

        raw_data = json.loads(result.stdout)

        return SecurityEvidence(
            evidence_id=f"trivy-{image.replace('/', '-').replace(':', '-')}",
            source="trivy",
            evidence_type="container_vulnerability_scan",
            timestamp=datetime.now(timezone.utc),
            raw_data=raw_data,
            metadata={
                "image": image,
            },
        )