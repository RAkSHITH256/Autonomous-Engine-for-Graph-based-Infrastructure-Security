import os

from backend.discovery.docker_discovery import DockerDiscovery
from backend.graph.graph_builder import GraphBuilder
from backend.graph.neo4j_client import Neo4jClient


def main() -> None:
    # ---------------------------------------------------------
    # 1. Discover real Docker infrastructure
    # ---------------------------------------------------------

    discovery = DockerDiscovery()

    result = discovery.discover()

    assets = result["assets"]
    relationships = result["relationships"]

    print(f"Discovered assets: {len(assets)}")
    print(f"Discovered relationships: {len(relationships)}")

    # ---------------------------------------------------------
    # 2. Connect to Neo4j
    # ---------------------------------------------------------

    uri = os.getenv(
        "NEO4J_URI",
        "bolt://localhost:7687",
    )

    username = os.getenv(
        "NEO4J_USERNAME",
        "neo4j",
    )

    password = os.getenv(
         "NEO4J_PASSWORD",
          "aegisdev",

    )

    client = Neo4jClient(
        uri=uri,
        username=username,
        password=password,
    )

    try:

        # -----------------------------------------------------
        # 3. Verify Neo4j
        # -----------------------------------------------------

        if not client.test_connection():
            raise RuntimeError(
                "Neo4j connection test failed."
            )

        print("Neo4j connection successful.")

        # -----------------------------------------------------
        # 4. Convert discovered Assets to GraphBuilder format
        # -----------------------------------------------------

        graph_assets = []

        for asset in assets:

            graph_assets.append(
                {
                    "asset_id": asset.asset_id,
                    "name": asset.name,
                    "type": asset.asset_type,
                    "criticality": asset.metadata.get(
                        "criticality",
                        "UNKNOWN",
                    ),
                    "metadata": asset.metadata,
                }
            )

        # -----------------------------------------------------
        # 5. Build relationships
        # -----------------------------------------------------

        graph_relationships = []

        for relationship in relationships:

            graph_relationships.append(
                {
                    "source": relationship["source"],
                    "target": relationship["target"],
                    "type": relationship["relationship"],
                }
            )

        # -----------------------------------------------------
        # 6. Write Docker infrastructure into Neo4j
        # -----------------------------------------------------

        builder = GraphBuilder(client)

        builder.build_graph(
            assets=graph_assets,
            relationships=graph_relationships,
            vulnerabilities=[],
        )

        print(
            "Docker infrastructure successfully "
            "imported into Neo4j."
        )

    finally:

        client.close()


if __name__ == "__main__":
    main()
