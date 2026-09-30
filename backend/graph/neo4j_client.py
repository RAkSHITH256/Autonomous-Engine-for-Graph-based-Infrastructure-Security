from typing import Any

from neo4j import GraphDatabase


class Neo4jClient:
    """
    AEGIS Neo4j database client.

    Responsible for:
        - Database connectivity
        - Asset storage
        - Finding/vulnerability storage
        - Attack-path discovery
        - Vulnerability discovery on attack paths
    """

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
    ):
        self.driver = GraphDatabase.driver(
            uri,
            auth=(username, password),
        )

    # =============================================================
    # CONNECTION
    # =============================================================

    def close(self) -> None:
        self.driver.close()

    def test_connection(self) -> bool:
        """
        Verify that Neo4j is reachable.
        """

        with self.driver.session() as session:

            result = session.run(
                "RETURN 1 AS result"
            )

            record = result.single()

            return record is not None and record["result"] == 1

    # =============================================================
    # ASSET
    # =============================================================

    def create_asset(
        self,
        asset_id: str,
        name: str,
        asset_type: str,
        criticality: str = "UNKNOWN",
    ) -> None:
        """
        Create or update an AEGIS Asset node.
        """

        query = """
        MERGE (asset:Asset {
            asset_id: $asset_id
        })

        SET
            asset.name = $name,
            asset.type = $asset_type,
            asset.criticality = $criticality
        """

        with self.driver.session() as session:

            session.run(
                query,
                asset_id=asset_id,
                name=name,
                asset_type=asset_type,
                criticality=criticality,
            )

    # =============================================================
    # VULNERABILITY
    # =============================================================

    def create_vulnerability(
        self,
        asset_id: str,
        vulnerability: dict[str, Any],
    ) -> None:
        """
        Create a vulnerability and connect it to an asset.
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

        with self.driver.session() as session:

            session.run(
                query,

                asset_id=asset_id,

                vulnerability_id=vulnerability.get(
                    "vulnerability_id",
                    vulnerability.get(
                        "identifier",
                        "UNKNOWN",
                    ),
                ),

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

    # =============================================================
    # ATTACK PATH
    # =============================================================

    def find_attack_path(self):

        query = """
        MATCH path =
            (start:Asset {name: 'Internet'})
            -[*1..6]->
            (target:Asset {name: 'Production DB'})

        RETURN path
        LIMIT 1
        """

        with self.driver.session() as session:

            result = session.run(query)

            record = result.single()

            if record is None:
                return None

            path = record["path"]

            nodes = []

            for node in path.nodes:

                nodes.append({
                    "asset_id": node.get("asset_id"),
                    "name": node.get("name"),
                    "type": node.get("type"),
                    "criticality": node.get(
                        "criticality"
                    ),
                })

            return {
                "path_length": len(
                    path.relationships
                ),
                "nodes": nodes,
            }

    # =============================================================
    # VULNERABILITIES ON ATTACK PATH
    # =============================================================

    def find_vulnerabilities_on_path(self):

        query = """
        MATCH path =
            (start:Asset {name: 'Internet'})
            -[*1..6]->
            (target:Asset {name: 'Production DB'})

        MATCH
            (asset:Asset)
            -[:HAS_VULNERABILITY]->
            (v:Vulnerability)

        WHERE asset IN nodes(path)

        RETURN
            asset.asset_id AS asset_id,
            asset.name AS asset_name,

            v.vulnerability_id
                AS vulnerability_id,

            v.identifier
                AS identifier,

            v.severity
                AS severity,

            v.cvss_score
                AS cvss_score,

            v.exploitability
                AS exploitability,

            v.package
                AS package,

            v.installed_version
                AS installed_version,

            v.fixed_version
                AS fixed_version
        """

        with self.driver.session() as session:

            result = session.run(query)

            vulnerabilities = []

            for record in result:

                vulnerabilities.append({
                    "asset_id": record["asset_id"],
                    "asset_name": record["asset_name"],

                    "vulnerability_id": (
                        record["vulnerability_id"]
                    ),

                    "identifier": (
                        record["identifier"]
                    ),

                    "severity": (
                        record["severity"]
                    ),

                    "cvss_score": (
                        record["cvss_score"]
                    ),

                    "exploitability": (
                        record["exploitability"]
                    ),

                    "package": (
                        record["package"]
                    ),

                    "installed_version": (
                        record["installed_version"]
                    ),

                    "fixed_version": (
                        record["fixed_version"]
                    ),
                })

            return vulnerabilities

    # =============================================================
    # CLOSE
    # =============================================================

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ):
        self.close()