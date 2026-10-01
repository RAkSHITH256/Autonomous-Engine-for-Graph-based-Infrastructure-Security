from typing import Any

from backend.graph.neo4j_client import Neo4jClient


class GraphBuilder:
    """
    Builds the AEGIS infrastructure security graph.

    Graph structure can contain:

        Asset -[:CONNECTS_TO]-> Asset
        Asset -[:DEPENDS_ON]-> Asset
        Asset -[:HOSTS]-> Asset
        Asset -[:COMMUNICATES_WITH]-> Asset
        Container -[:RUNS_IMAGE]-> ContainerImage

    Vulnerabilities are attached to assets using:

        Asset -[:HAS_VULNERABILITY]-> Vulnerability
    """

    def __init__(self, client: Neo4jClient):
        self.client = client

    # =========================================================
    # CLEAR GRAPH
    # =========================================================

    def clear_graph(self) -> None:
        """
        Delete all nodes and relationships.

        Intended for development/testing only.
        """

        query = """
        MATCH (n)
        DETACH DELETE n
        """

        with self.client.driver.session() as session:
            session.run(query)

    # =========================================================
    # CREATE ASSET
    # =========================================================

    def add_asset(
        self,
        asset_id: str,
        name: str,
        asset_type: str,
        criticality: str = "UNKNOWN",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Create or update an infrastructure asset.
        """

        metadata = metadata or {}

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
                metadata=metadata,
            )

    # =========================================================
    # CONNECT ASSETS
    # =========================================================

    def connect_assets(
        self,
        source_asset_id: str,
        target_asset_id: str,
        relationship: str = "CONNECTS_TO",
    ) -> None:
        """
        Create a relationship between two assets.

        Supported relationships:

            CONNECTS_TO
            DEPENDS_ON
            HOSTS
            COMMUNICATES_WITH
            RUNS_IMAGE
        """

        allowed_relationships = {
            "CONNECTS_TO",
            "DEPENDS_ON",
            "HOSTS",
            "COMMUNICATES_WITH",
            "RUNS_IMAGE",
        }

        if relationship not in allowed_relationships:
            raise ValueError(
                f"Unsupported relationship type: "
                f"{relationship}"
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

    # =========================================================
    # ADD VULNERABILITY
    # =========================================================

    def add_vulnerability(
        self,
        asset_id: str,
        vulnerability: dict[str, Any],
    ) -> None:
        """
        Attach a vulnerability to an asset.
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

    # =========================================================
    # BUILD DEMO AEGIS GRAPH
    # =========================================================

    def build_demo_graph(self) -> None:
        """
        Build a deterministic demonstration graph.

        Useful for:

            - development
            - demonstrations
            - integration testing
            - Neo4j visualization
        """

        # -----------------------------------------------------
        # Assets
        # -----------------------------------------------------

        self.add_asset(
            asset_id="internet-001",
            name="Internet",
            asset_type="EXTERNAL",
            criticality="HIGH",
        )

        self.add_asset(
            asset_id="web-001",
            name="Web Server",
            asset_type="WEB_SERVER",
            criticality="HIGH",
        )

        self.add_asset(
            asset_id="app-001",
            name="Application Server",
            asset_type="APPLICATION",
            criticality="HIGH",
        )

        self.add_asset(
            asset_id="db-001",
            name="Production DB",
            asset_type="DATABASE",
            criticality="CRITICAL",
        )

        # -----------------------------------------------------
        # Network relationships
        # -----------------------------------------------------

        self.connect_assets(
            source_asset_id="internet-001",
            target_asset_id="web-001",
        )

        self.connect_assets(
            source_asset_id="web-001",
            target_asset_id="app-001",
        )

        self.connect_assets(
            source_asset_id="app-001",
            target_asset_id="db-001",
        )

        # -----------------------------------------------------
        # Vulnerability on application server
        # -----------------------------------------------------

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

    # =========================================================
    # BUILD CUSTOM GRAPH
    # =========================================================

    def build_graph(
        self,
        assets: list[dict[str, Any]],
        relationships: list[dict[str, str]],
        vulnerabilities: list[dict[str, Any]],
    ) -> None:
        """
        Build an arbitrary AEGIS graph.

        assets:

            [
                {
                    "asset_id": "web-001",
                    "name": "Web Server",
                    "type": "WEB_SERVER",
                    "criticality": "HIGH"
                }
            ]

        relationships:

            [
                {
                    "source": "internet-001",
                    "target": "web-001",
                    "type": "CONNECTS_TO"
                },
                {
                    "source": "container-001",
                    "target": "image-001",
                    "type": "RUNS_IMAGE"
                }
            ]

        vulnerabilities:

            [
                {
                    "asset_id": "web-001",
                    "vulnerability": {...}
                }
            ]
        """

        # -----------------------------------------------------
        # Assets
        # -----------------------------------------------------

        for asset in assets:

            self.add_asset(
                asset_id=asset["asset_id"],
                name=asset["name"],
                asset_type=asset["type"],
                criticality=asset.get(
                    "criticality",
                    "UNKNOWN",
                ),
                metadata=asset.get(
                    "metadata",
                    {},
                ),
            )

        # -----------------------------------------------------
        # Relationships
        # -----------------------------------------------------

        for relationship in relationships:

            self.connect_assets(
                source_asset_id=relationship[
                    "source"
                ],
                target_asset_id=relationship[
                    "target"
                ],
                relationship=relationship.get(
                    "type",
                    "CONNECTS_TO",
                ),
            )

        # -----------------------------------------------------
        # Vulnerabilities
        # -----------------------------------------------------

        for item in vulnerabilities:

            self.add_vulnerability(
                asset_id=item["asset_id"],
                vulnerability=item[
                    "vulnerability"
                ],
            )