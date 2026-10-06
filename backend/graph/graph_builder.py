import json
from typing import Any

from backend.graph.neo4j_client import Neo4jClient
from backend.models.build_provenance import BuildProvenance


class GraphBuilder:
    """
    Builds and manages the AEGIS security graph.

    Supported graph structures:

        Asset -[:CONNECTS_TO]-> Asset
        Asset -[:DEPENDS_ON]-> Asset
        Asset -[:HOSTS]-> Asset
        Asset -[:COMMUNICATES_WITH]-> Asset
        Asset -[:RUNS_IMAGE]-> ContainerImage
        Repository -[:BUILDS]-> ContainerImage

    Vulnerabilities are represented as:

        Asset -[:HAS_VULNERABILITY]-> Vulnerability

    CI/CD provenance can establish:

        SourceRepository -[:BUILDS]-> ContainerImage
    """

    # ============================================================
    # INITIALIZATION
    # ============================================================

    def __init__(self, client: Neo4jClient):
        self.client = client

    # ============================================================
    # CLEAR GRAPH
    # ============================================================

    def clear_graph(self) -> None:
        """
        Remove all nodes and relationships from the graph.
        """

        query = """
        MATCH (n)
        DETACH DELETE n
        """

        with self.client.driver.session() as session:
            session.run(query)

    # ============================================================
    # ADD ASSET
    # ============================================================

    def add_asset(
        self,
        asset_id: str,
        name: str,
        asset_type: str,
        criticality: str = "UNKNOWN",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Add or update an infrastructure asset.

        Assets may represent:

        - containers
        - container images
        - repositories
        - databases
        - APIs
        - servers
        - Kubernetes resources
        - external systems
        - Internet
        """

        metadata = metadata or {}

        metadata_json = json.dumps(
            metadata,
            default=str,
        )

        query = """
        MERGE (asset:Asset {
            asset_id: $asset_id
        })

        SET
            asset.name = $name,
            asset.type = $asset_type,
            asset.criticality = $criticality,
            asset.metadata = $metadata
        """

        with self.client.driver.session() as session:
            session.run(
                query,
                asset_id=asset_id,
                name=name,
                asset_type=asset_type,
                criticality=criticality,
                metadata=metadata_json,
            )

    # ============================================================
    # ADD SOURCE REPOSITORY
    # ============================================================

    def add_repository(
        self,
        repository_id: str,
        name: str,
        url: str | None = None,
        branch: str = "main",
        commit_sha: str | None = None,
        provider: str = "github",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Add a source repository to the AEGIS graph.

        A repository is represented as an Asset with:

            type = SOURCE_REPOSITORY
        """

        metadata = metadata or {}

        metadata.update(
            {
                "provider": provider,
                "branch": branch,
                "commit_sha": commit_sha,
            }
        )

        if url is not None:
            metadata["url"] = url

        self.add_asset(
            asset_id=repository_id,
            name=name,
            asset_type="SOURCE_REPOSITORY",
            criticality="HIGH",
            metadata=metadata,
        )

    # ============================================================
    # ADD BUILD PROVENANCE
    # ============================================================

    def add_build_provenance(
        self,
        provenance: BuildProvenance,
    ) -> None:
        """
        Add CI/CD build provenance to the AEGIS graph.

        Valid provenance creates:

            SourceRepository -[:BUILDS]-> ContainerImage

        The relationship is based on validated CI/CD evidence.

        Example:

            GitHub repository
                    |
                  BUILDS
                    |
                    v
              Container Image
        """

        # --------------------------------------------------------
        # Repository identity
        # --------------------------------------------------------

        repository_id = (
            f"github:{provenance.repository}"
        )

        # --------------------------------------------------------
        # Image identity
        #
        # Remove the sha256: prefix because the graph asset ID
        # already identifies the type as docker-image.
        # --------------------------------------------------------

        normalized_image_id = (
            provenance.image_id.removeprefix(
                "sha256:"
            )
        )

        image_id = (
            f"docker-image:{normalized_image_id}"
        )

        # --------------------------------------------------------
        # Repository asset
        # --------------------------------------------------------

        repository_metadata = {
            "workflow": provenance.workflow,
            "run_id": provenance.run_id,
            "run_number": provenance.run_number,
        }

        repository_url = (
            f"https://github.com/"
            f"{provenance.repository}"
        )

        self.add_repository(
            repository_id=repository_id,
            name=provenance.repository,
            url=repository_url,
            branch=provenance.branch,
            commit_sha=provenance.commit_sha,
            provider=provenance.provider,
            metadata=repository_metadata,
        )

        # --------------------------------------------------------
        # Container image asset
        # --------------------------------------------------------

        image_metadata = {
            "image": provenance.image,
            "image_id": provenance.image_id,
            "commit_sha": provenance.commit_sha,
            "repository": provenance.repository,
            "workflow": provenance.workflow,
            "run_id": provenance.run_id,
            "run_number": provenance.run_number,
            "created": provenance.created,
        }

        self.add_asset(
            asset_id=image_id,
            name=provenance.image,
            asset_type="CONTAINER_IMAGE",
            criticality="HIGH",
            metadata=image_metadata,
        )

        # --------------------------------------------------------
        # Evidence-backed BUILD relationship
        # --------------------------------------------------------

        self.connect_assets(
            source_asset_id=repository_id,
            target_asset_id=image_id,
            relationship="BUILDS",
        )

    # ============================================================
    # CONNECT ASSETS
    # ============================================================

    def connect_assets(
        self,
        source_asset_id: str,
        target_asset_id: str,
        relationship: str = "CONNECTS_TO",
    ) -> None:
        """
        Create a relationship between two assets.

        Supported relationships:

        - CONNECTS_TO
        - DEPENDS_ON
        - HOSTS
        - COMMUNICATES_WITH
        - RUNS_IMAGE
        - BUILDS
        """

        allowed_relationships = {
            "CONNECTS_TO",
            "DEPENDS_ON",
            "HOSTS",
            "COMMUNICATES_WITH",
            "RUNS_IMAGE",
            "BUILDS",
        }

        if relationship not in allowed_relationships:
            raise ValueError(
                f"Unsupported relationship type: {relationship}"
            )

        query = f"""
        MATCH (source:Asset {{
            asset_id: $source_asset_id
        }})

        MATCH (target:Asset {{
            asset_id: $target_asset_id
        }})

        MERGE (source)-[:{relationship}]->(target)
        """

        with self.client.driver.session() as session:
            session.run(
                query,
                source_asset_id=source_asset_id,
                target_asset_id=target_asset_id,
            )

    # ============================================================
    # ADD VULNERABILITY
    # ============================================================

    def add_vulnerability(
        self,
        asset_id: str,
        vulnerability: dict[str, Any],
    ) -> None:
        """
        Attach a vulnerability to an asset.

        Creates:

            Asset -[:HAS_VULNERABILITY]-> Vulnerability
        """

        query = """
        MATCH (asset:Asset {
            asset_id: $asset_id
        })

        MERGE (v:Vulnerability {
            vulnerability_id: $vulnerability_id
        })

        SET
            v.identifier = $identifier,
            v.severity = $severity,
            v.cvss_score = $cvss_score,
            v.exploitability = $exploitability,
            v.package = $package,
            v.installed_version = $installed_version,
            v.fixed_version = $fixed_version

        MERGE (asset)-[:HAS_VULNERABILITY]->(v)
        """

        vulnerability_id = vulnerability.get(
            "vulnerability_id",
            vulnerability.get(
                "identifier",
                "UNKNOWN",
            ),
        )

        with self.client.driver.session() as session:
            session.run(
                query,
                asset_id=asset_id,
                vulnerability_id=vulnerability_id,
                identifier=vulnerability.get(
                    "identifier",
                    "UNKNOWN",
                ),
                severity=vulnerability.get(
                    "severity",
                    "UNKNOWN",
                ),
                cvss_score=vulnerability.get(
                    "cvss_score"
                ),
                exploitability=vulnerability.get(
                    "exploitability",
                    "UNKNOWN",
                ),
                package=vulnerability.get(
                    "package",
                    "UNKNOWN",
                ),
                installed_version=vulnerability.get(
                    "installed_version",
                    "UNKNOWN",
                ),
                fixed_version=vulnerability.get(
                    "fixed_version",
                    "",
                ),
            )

    # ============================================================
    # BUILD GRAPH
    # ============================================================

    def build_graph(
        self,
        assets: list[dict[str, Any]],
        relationships: list[dict[str, Any]],
        vulnerabilities: list[dict[str, Any]] | None = None,
    ) -> None:
        """
        Build a graph from supplied asset, relationship,
        and vulnerability data.
        """

        # --------------------------------------------------------
        # Assets
        # --------------------------------------------------------

        for asset in assets:
            self.add_asset(
                asset_id=asset["asset_id"],
                name=asset["name"],
                asset_type=asset.get(
                    "type",
                    asset.get(
                        "asset_type",
                        "UNKNOWN",
                    ),
                ),
                criticality=asset.get(
                    "criticality",
                    "UNKNOWN",
                ),
                metadata=asset.get(
                    "metadata",
                    {},
                ),
            )

        # --------------------------------------------------------
        # Relationships
        # --------------------------------------------------------

        for relationship in relationships:
          self.connect_assets(
                 source_asset_id=relationship["source"],
                 target_asset_id=relationship["target"],
                 relationship=relationship.get(
            "type",
            relationship.get(
                "relationship",
                "CONNECTS_TO",
            ),
        ),
    )
        # --------------------------------------------------------
        # Vulnerabilities
        # --------------------------------------------------------

        for vulnerability in vulnerabilities or []:
            self.add_vulnerability(
                asset_id=vulnerability["asset_id"],
                vulnerability=vulnerability,
            )

    # ============================================================
    # DEMO GRAPH
    # ============================================================

    def build_demo_graph(self) -> None:
        """
        Build a small demonstration attack-path graph.

        Internet
            |
            v
        Web Server
            |
            v
        Application Server
            |
            v
        Production DB
        """

        # --------------------------------------------------------
        # Internet
        # --------------------------------------------------------

        self.add_asset(
            asset_id="internet-001",
            name="Internet",
            asset_type="INTERNET",
            criticality="HIGH",
        )

        # --------------------------------------------------------
        # Web server
        # --------------------------------------------------------

        self.add_asset(
            asset_id="web-001",
            name="Web Server",
            asset_type="WEB_SERVER",
            criticality="HIGH",
        )

        # --------------------------------------------------------
        # Application server
        # --------------------------------------------------------

        self.add_asset(
            asset_id="app-001",
            name="Application Server",
            asset_type="APPLICATION_SERVER",
            criticality="HIGH",
        )

        # --------------------------------------------------------
        # Production database
        # --------------------------------------------------------

        self.add_asset(
            asset_id="db-001",
            name="Production DB",
            asset_type="DATABASE",
            criticality="CRITICAL",
        )

        # --------------------------------------------------------
        # Internet -> Web
        # --------------------------------------------------------

        self.connect_assets(
            source_asset_id="internet-001",
            target_asset_id="web-001",
            relationship="CONNECTS_TO",
        )

        # --------------------------------------------------------
        # Web -> Application
        # --------------------------------------------------------

        self.connect_assets(
            source_asset_id="web-001",
            target_asset_id="app-001",
            relationship="CONNECTS_TO",
        )

        # --------------------------------------------------------
        # Application -> Database
        # --------------------------------------------------------

        self.connect_assets(
            source_asset_id="app-001",
            target_asset_id="db-001",
            relationship="CONNECTS_TO",
        )

        # --------------------------------------------------------
        # Demo vulnerability
        # --------------------------------------------------------

        self.add_vulnerability(
            asset_id="app-001",
            vulnerability={
                "vulnerability_id": "CVE-DEMO-001",
                "identifier": "CVE-DEMO-001",
                "severity": "HIGH",
                "cvss_score": 8.5,
                "exploitability": "HIGH",
                "package": "demo-package",
                "installed_version": "1.0.0",
                "fixed_version": "1.0.1",
            },
        )