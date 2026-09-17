from neo4j import GraphDatabase


class Neo4jClient:

    def __init__(self, uri: str, username: str, password: str):
        self.driver = GraphDatabase.driver(
            uri,
            auth=(username, password)
        )

    def close(self):
        self.driver.close()

    def test_connection(self):
        with self.driver.session() as session:
            result = session.run("RETURN 1 AS result")
            record = result.single()

            return record["result"]

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
                    "criticality": node.get("criticality")
                })

            return {
                "path_length": len(path.relationships),
                "nodes": nodes
            }

    def find_vulnerabilities_on_path(self):
        query = """
        MATCH path =
          (start:Asset {name: 'Internet'})
          -[*1..6]->
          (target:Asset {name: 'Production DB'})

        MATCH (asset:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)

        WHERE asset IN nodes(path)

        RETURN
            asset.asset_id AS asset_id,
            asset.name AS asset_name,
            v.vulnerability_id AS vulnerability_id,
            v.identifier AS identifier,
            v.severity AS severity,
            v.cvss_score AS cvss_score,
            v.exploitability AS exploitability,
            v.package AS package,
            v.installed_version AS installed_version,
            v.fixed_version AS fixed_version
        """

        with self.driver.session() as session:
            result = session.run(query)

            vulnerabilities = []

            for record in result:
                vulnerabilities.append({
                    "asset_id": record["asset_id"],
                    "asset_name": record["asset_name"],
                    "vulnerability_id": record["vulnerability_id"],
                    "identifier": record["identifier"],
                    "severity": record["severity"],
                    "cvss_score": record["cvss_score"],
                    "exploitability": record["exploitability"],
                    "package": record["package"],
                    "installed_version": record["installed_version"],
                    "fixed_version": record["fixed_version"]
                })

            return vulnerabilities