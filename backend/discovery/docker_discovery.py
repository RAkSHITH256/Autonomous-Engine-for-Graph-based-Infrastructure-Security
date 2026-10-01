import json
import subprocess
from typing import Any

from backend.models.asset import Asset


class DockerDiscovery:
    """
    Discovers Docker images and containers from the local Docker Engine
    and converts them into AEGIS assets and infrastructure relationships.
    """

    def __init__(self, docker_command: str = "docker"):
        self.docker_command = docker_command

    # ------------------------------------------------------------------
    # IMAGE DISCOVERY
    # ------------------------------------------------------------------

    def discover_images(self) -> list[Asset]:
        """
        Discover all Docker images available locally.
        """

        command = [
            self.docker_command,
            "image",
            "ls",
            "--format",
            "{{json .}}",
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        if process.returncode != 0:
            error = (
                process.stderr.strip()
                or "Docker image discovery failed."
            )
            raise RuntimeError(error)

        assets: list[Asset] = []

        for line in process.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                image = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Docker returned invalid JSON: {line}"
                ) from exc

            repository = image.get("Repository", "<none>")
            tag = image.get("Tag", "<none>")
            image_id = image.get("ID", "")

            if not image_id:
                continue

            image_reference = f"{repository}:{tag}"

            assets.append(
                Asset(
                    asset_id=f"docker-image:{image_id}",
                    asset_type="CONTAINER_IMAGE",
                    name=image_reference,
                    environment="unknown",
                    metadata={
                        "source": "docker",
                        "image_id": image_id,
                        "repository": repository,
                        "tag": tag,
                        "digest": image.get("Digest"),
                        "size": image.get("Size"),
                        "created_at": image.get("CreatedAt"),
                        "created_since": image.get("CreatedSince"),
                        "containers": self._parse_container_count(
                            image.get("Containers")
                        ),
                        "image_reference": image_reference,
                    },
                )
            )

        return assets

    # ------------------------------------------------------------------
    # CONTAINER IMAGE ID
    # ------------------------------------------------------------------

    def get_container_image_id(
        self,
        container_id: str,
    ) -> str | None:
        """
        Retrieve the immutable image ID used by a Docker container.

        Docker normally returns:

            sha256:<full-image-id>
        """

        command = [
            self.docker_command,
            "inspect",
            "--format",
            "{{.Image}}",
            container_id,
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        if process.returncode != 0:
            return None

        image_id = process.stdout.strip()

        if not image_id:
            return None

        return image_id

    # ------------------------------------------------------------------
    # CONTAINER DISCOVERY
    # ------------------------------------------------------------------

    def discover_containers(
        self,
        include_stopped: bool = True,
    ) -> list[Asset]:
        """
        Discover Docker containers and convert them into AEGIS assets.
        """

        command = [
            self.docker_command,
            "ps",
            "--format",
            "{{json .}}",
        ]

        if include_stopped:
            command.insert(2, "-a")

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        if process.returncode != 0:
            error = (
                process.stderr.strip()
                or "Docker container discovery failed."
            )
            raise RuntimeError(error)

        assets: list[Asset] = []

        for line in process.stdout.splitlines():
            line = line.strip()

            if not line:
                continue

            try:
                container = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Docker returned invalid JSON: {line}"
                ) from exc

            container_id = container.get("ID", "")

            if not container_id:
                continue

            name = container.get(
                "Names",
                container_id,
            )

            image = container.get(
                "Image",
                "<unknown>",
            )

            status = container.get(
                "Status",
                "",
            )

            state = self._derive_container_state(
                status
            )

            # Get the immutable Docker image ID.
            image_id = self.get_container_image_id(
                container_id
            )

            assets.append(
                Asset(
                    asset_id=f"docker-container:{container_id}",
                    asset_type="CONTAINER",
                    name=name,
                    environment="unknown",
                    metadata={
                        "source": "docker",
                        "container_id": container_id,
                        "container_name": name,
                        "image": image,
                        "image_id": image_id,
                        "status": status,
                        "state": state,
                        "ports": container.get(
                            "Ports",
                            "",
                        ),
                        "created_at": container.get(
                            "CreatedAt",
                            "",
                        ),
                        "running_for": container.get(
                            "RunningFor",
                            "",
                        ),
                        "command": container.get(
                            "Command",
                            "",
                        ),
                        "labels": container.get(
                            "Labels",
                            "",
                        ),
                    },
                )
            )

        return assets

    # ------------------------------------------------------------------
    # RELATIONSHIP DISCOVERY
    # ------------------------------------------------------------------

    def discover_relationships(
        self,
        containers: list[Asset],
        images: list[Asset],
    ) -> list[dict[str, str]]:
        """
        Discover infrastructure relationships between Docker containers
        and Docker images.

        Relationship:

            CONTAINER --RUNS_IMAGE--> CONTAINER_IMAGE

        Matching is performed using Docker image IDs.

        Docker image ls normally returns a short image ID.

        docker inspect normally returns:

            sha256:<full-image-id>

        Therefore prefix matching is used.
        """

        relationships: list[dict[str, str]] = []

        for container in containers:
            container_image_id = container.metadata.get(
                "image_id"
            )

            if not container_image_id:
                continue

            normalized_container_id = (
                self._normalize_image_id(
                    str(container_image_id)
                )
            )

            for image in images:
                image_id = image.metadata.get(
                    "image_id"
                )

                if not image_id:
                    continue

                normalized_image_id = (
                    self._normalize_image_id(
                        str(image_id)
                    )
                )

                # Match Docker short ID with full ID.
                if (
                    normalized_container_id.startswith(
                        normalized_image_id
                    )
                    or normalized_image_id.startswith(
                        normalized_container_id
                    )
                ):
                    relationships.append(
                        {
                            "source": container.asset_id,
                            "target": image.asset_id,
                            "relationship": "RUNS_IMAGE",
                        }
                    )

                    break

        return relationships

    # ------------------------------------------------------------------
    # COMPLETE DISCOVERY
    # ------------------------------------------------------------------

    def discover(self) -> dict[str, Any]:
        """
        Perform complete Docker discovery.

        Returns:

            {
                "assets": [...],
                "relationships": [...]
            }
        """

        images = self.discover_images()

        containers = self.discover_containers(
            include_stopped=True
        )

        all_assets = containers + images

        relationships = self.discover_relationships(
            containers=containers,
            images=images,
        )

        return {
            "assets": all_assets,
            "relationships": relationships,
        }

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_image_id(
        image_id: str,
    ) -> str:
        """
        Remove the sha256: prefix from Docker image IDs.
        """

        normalized = image_id.strip()

        if normalized.startswith("sha256:"):
            normalized = normalized[
                len("sha256:") :
            ]

        return normalized

    @staticmethod
    def _derive_container_state(
        status: str,
    ) -> str:
        """
        Convert Docker's human-readable status
        into a normalized state.
        """

        normalized = status.lower()

        if normalized.startswith("up"):
            return "RUNNING"

        if normalized.startswith("created"):
            return "CREATED"

        if normalized.startswith("exited"):
            return "STOPPED"

        if normalized.startswith("restarting"):
            return "RESTARTING"

        if normalized.startswith("paused"):
            return "PAUSED"

        return "UNKNOWN"

    @staticmethod
    def _parse_container_count(
        value: Any,
    ) -> int:
        """
        Convert Docker's Containers field into an integer.
        """

        try:
            return int(value)
        except (TypeError, ValueError):
            return 0