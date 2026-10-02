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

        image_id = self._get_docker_image_id(image)

        return SecurityEvidence(
            evidence_id=f"trivy-{image.replace('/', '-').replace(':', '-')}",
            source="trivy",
            evidence_type="container_vulnerability_scan",
            timestamp=datetime.now(timezone.utc),
            raw_data=raw_data,
            metadata={
                "image": image,
                "image_id": image_id,
            },
        )

    def _get_docker_image_id(self, image: str) -> str | None:
        command = [
            "docker",
            "inspect",
            "--format",
            "{{.Id}}",
            image,
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            return None

        image_id = result.stdout.strip()

        if image_id.startswith("sha256:"):
            image_id = image_id[len("sha256:"):]

        return image_id or None