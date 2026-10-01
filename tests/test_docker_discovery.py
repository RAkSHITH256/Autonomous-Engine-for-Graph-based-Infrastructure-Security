import json

from backend.discovery.docker_discovery import DockerDiscovery
from backend.models.asset import Asset


def test_discover_images(monkeypatch):
    docker_output = "\n".join(
        [
            json.dumps(
                {
                    "Containers": "0",
                    "CreatedAt": "2026-08-18 12:33:27 +0530 IST",
                    "Digest": "<none>",
                    "ID": "6256e7ad8af8",
                    "Repository": "raks25/secure-supply-chain-demo",
                    "Size": "205MB",
                    "Tag": "test",
                }
            ),
            json.dumps(
                {
                    "Containers": "1",
                    "CreatedAt": "2026-05-28 22:05:50 +0530 IST",
                    "Digest": "<none>",
                    "ID": "dc8a44e2d159",
                    "Repository": "notes-app-backend",
                    "Size": "1.95GB",
                    "Tag": "latest",
                }
            ),
        ]
    )

    class MockProcess:
        returncode = 0
        stdout = docker_output
        stderr = ""

    monkeypatch.setattr(
        "backend.discovery.docker_discovery.subprocess.run",
        lambda *args, **kwargs: MockProcess(),
    )

    discovery = DockerDiscovery()

    assets = discovery.discover_images()

    assert len(assets) == 2

    assert assets[0].asset_id == "docker-image:6256e7ad8af8"
    assert assets[0].asset_type == "CONTAINER_IMAGE"
    assert assets[0].name == "raks25/secure-supply-chain-demo:test"

    assert assets[1].asset_id == "docker-image:dc8a44e2d159"
    assert assets[1].name == "notes-app-backend:latest"

    assert assets[1].metadata["repository"] == "notes-app-backend"
    assert assets[1].metadata["tag"] == "latest"
    assert assets[1].metadata["containers"] == 1


def test_discover_images_handles_empty_output(monkeypatch):
    class MockProcess:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        "backend.discovery.docker_discovery.subprocess.run",
        lambda *args, **kwargs: MockProcess(),
    )

    discovery = DockerDiscovery()

    assets = discovery.discover_images()

    assert assets == []


def test_discover_images_raises_when_docker_fails(monkeypatch):
    class MockProcess:
        returncode = 1
        stdout = ""
        stderr = "Cannot connect to the Docker daemon"

    monkeypatch.setattr(
        "backend.discovery.docker_discovery.subprocess.run",
        lambda *args, **kwargs: MockProcess(),
    )

    discovery = DockerDiscovery()

    try:
        discovery.discover_images()
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "Cannot connect to the Docker daemon" in str(exc)


def test_discover_images_skips_missing_image_id(monkeypatch):
    docker_output = json.dumps(
        {
            "Containers": "0",
            "Repository": "broken-image",
            "Tag": "latest",
            "ID": "",
        }
    )

    class MockProcess:
        returncode = 0
        stdout = docker_output
        stderr = ""

    monkeypatch.setattr(
        "backend.discovery.docker_discovery.subprocess.run",
        lambda *args, **kwargs: MockProcess(),
    )

    discovery = DockerDiscovery()

    assets = discovery.discover_images()

    assert assets == []


def test_discover_running_containers(monkeypatch):
    docker_output = json.dumps(
        {
            "ID": "abc123",
            "Names": "notes-backend",
            "Image": "notes-app-backend:latest",
            "Status": "Up 2 hours",
            "Ports": "0.0.0.0:8000->8000/tcp",
            "CreatedAt": "2026-09-30 10:00:00",
            "RunningFor": "2 hours",
            "Command": "python app.py",
            "Labels": "app=notes",
        }
    )

    class MockProcess:
        returncode = 0
        stdout = docker_output
        stderr = ""

    monkeypatch.setattr(
        "backend.discovery.docker_discovery.subprocess.run",
        lambda *args, **kwargs: MockProcess(),
    )

    discovery = DockerDiscovery()

    assets = discovery.discover_containers(include_stopped=False)

    assert len(assets) == 1

    asset = assets[0]

    assert asset.asset_id == "docker-container:abc123"
    assert asset.asset_type == "CONTAINER"
    assert asset.name == "notes-backend"

    assert asset.metadata["image"] == "notes-app-backend:latest"
    assert asset.metadata["state"] == "RUNNING"
    assert asset.metadata["ports"] == "0.0.0.0:8000->8000/tcp"


def test_discover_stopped_container(monkeypatch):
    docker_output = json.dumps(
        {
            "ID": "def456",
            "Names": "old-notes-backend",
            "Image": "notes-app-backend:latest",
            "Status": "Exited (0) 3 days ago",
            "Ports": "",
            "CreatedAt": "2026-09-27 10:00:00",
            "RunningFor": "3 days",
            "Command": "python app.py",
            "Labels": "",
        }
    )

    class MockProcess:
        returncode = 0
        stdout = docker_output
        stderr = ""

    monkeypatch.setattr(
        "backend.discovery.docker_discovery.subprocess.run",
        lambda *args, **kwargs: MockProcess(),
    )

    discovery = DockerDiscovery()

    assets = discovery.discover_containers(include_stopped=True)

    assert len(assets) == 1

    asset = assets[0]

    assert asset.asset_id == "docker-container:def456"
    assert asset.metadata["state"] == "STOPPED"


def test_discover_containers_empty(monkeypatch):
    class MockProcess:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(
        "backend.discovery.docker_discovery.subprocess.run",
        lambda *args, **kwargs: MockProcess(),
    )

    discovery = DockerDiscovery()

    assets = discovery.discover_containers()

    assert assets == []


def test_discover_containers_raises_when_docker_fails(monkeypatch):
    class MockProcess:
        returncode = 1
        stdout = ""
        stderr = "Docker daemon unavailable"

    monkeypatch.setattr(
        "backend.discovery.docker_discovery.subprocess.run",
        lambda *args, **kwargs: MockProcess(),
    )

    discovery = DockerDiscovery()

    try:
        discovery.discover_containers()
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "Docker daemon unavailable" in str(exc)


def test_discover_relationships():
    discovery = DockerDiscovery()

    images = [
        Asset(
            asset_id="docker-image:abc123",
            asset_type="CONTAINER_IMAGE",
            name="notes-app-backend:latest",
            environment="unknown",
            metadata={
                "repository": "notes-app-backend",
                "tag": "latest",
                "image_id": "abc123",
            },
        )
    ]

    containers = [
        Asset(
            asset_id="docker-container:def456",
            asset_type="CONTAINER",
            name="notes-backend",
            environment="unknown",
            metadata={
                "image": "notes-app-backend:latest",
                "image_id": "sha256:abc123456789",
            },
        )
    ]

    relationships = discovery.discover_relationships(
        containers=containers,
        images=images,
    )

    assert len(relationships) == 1

    assert relationships[0] == {
        "source": "docker-container:def456",
        "target": "docker-image:abc123",
        "relationship": "RUNS_IMAGE",
    }

def test_discover_relationships_ignores_unknown_image():
    discovery = DockerDiscovery()

    images = []

    containers = [
        Asset(
            asset_id="docker-container:def456",
            asset_type="CONTAINER",
            name="unknown-container",
            environment="unknown",
            metadata={
                "image": "unknown-image:latest",
            },
        )
    ]

    relationships = discovery.discover_relationships(
        containers=containers,
        images=images,
    )

    assert relationships == []

def test_discover_returns_assets_and_relationships(monkeypatch):
    image_output = json.dumps(
        {
            "Containers": "1",
            "CreatedAt": "2026-05-28 22:05:50 +0530 IST",
            "Digest": "<none>",
            "ID": "image123",
            "Repository": "notes-app-backend",
            "Size": "500MB",
            "Tag": "latest",
        }
    )

    container_output = json.dumps(
        {
            "ID": "container123",
            "Names": "notes-backend",
            "Image": "notes-app-backend",
            "Status": "Up 2 hours",
            "Ports": "8000/tcp",
            "CreatedAt": "2026-09-30 10:00:00",
            "RunningFor": "2 hours",
            "Command": "python app.py",
            "Labels": "",
        }
    )

    class MockProcess:
        def __init__(self, stdout):
            self.returncode = 0
            self.stdout = stdout
            self.stderr = ""

    def mock_run(command, *args, **kwargs):
        if "image" in command:
            return MockProcess(image_output)

        if "inspect" in command:
            return MockProcess("sha256:image123456789")

        return MockProcess(container_output)

    monkeypatch.setattr(
        "backend.discovery.docker_discovery.subprocess.run",
        mock_run,
    )

    discovery = DockerDiscovery()

    result = discovery.discover()

    assert "assets" in result
    assert "relationships" in result

    assert len(result["assets"]) == 2
    assert len(result["relationships"]) == 1

    relationship = result["relationships"][0]

    assert relationship["source"] == "docker-container:container123"
    assert relationship["target"] == "docker-image:image123"
    assert relationship["relationship"] == "RUNS_IMAGE"

def test_container_state_created():
    assert (
        DockerDiscovery._derive_container_state("Created")
        == "CREATED"
    )


def test_container_state_restarting():
    assert (
        DockerDiscovery._derive_container_state("Restarting (1)")
        == "RESTARTING"
    )


def test_container_state_paused():
    assert (
        DockerDiscovery._derive_container_state("Paused")
        == "PAUSED"
    )


def test_container_state_unknown():
    assert (
        DockerDiscovery._derive_container_state("Something unexpected")
        == "UNKNOWN"
    )


def test_parse_container_count():
    assert DockerDiscovery._parse_container_count("5") == 5
    assert DockerDiscovery._parse_container_count(3) == 3
    assert DockerDiscovery._parse_container_count(None) == 0
    assert DockerDiscovery._parse_container_count("invalid") == 0