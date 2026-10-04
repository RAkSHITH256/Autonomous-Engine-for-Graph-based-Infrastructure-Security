import os
import sys
from pathlib import Path

from backend.graph.graph_builder import GraphBuilder
from backend.graph.neo4j_client import Neo4jClient
from backend.provenance.provenance_importer import ProvenanceImporter


DEFAULT_PROVENANCE_PATH = (
    "security/reports/build-provenance.json"
)


def main() -> int:
    provenance_path = Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else DEFAULT_PROVENANCE_PATH
    )

    if not provenance_path.exists():
        print(
            f"ERROR: Provenance file not found: "
            f"{provenance_path}"
        )
        return 1

    neo4j_uri = os.getenv(
        "NEO4J_URI",
        "bolt://localhost:7687",
    )

    neo4j_username = os.getenv(
        "NEO4J_USERNAME",
        "neo4j",
    )

    neo4j_password = os.getenv(
        "NEO4J_PASSWORD",
        "aegisdev",
    )

    print("AEGIS Provenance Importer")
    print("=" * 40)

    print(f"Provenance: {provenance_path}")
    print(f"Neo4j URI:  {neo4j_uri}")
    print(f"Neo4j user: {neo4j_username}")

    client = Neo4jClient(
        uri=neo4j_uri,
        username=neo4j_username,
        password=neo4j_password,
    )

    try:
        if not client.test_connection():
            print(
                "ERROR: Could not connect to Neo4j."
            )
            return 1

        print("Neo4j connection: OK")

        graph_builder = GraphBuilder(
            client
        )

        importer = ProvenanceImporter(
            graph_builder=graph_builder
        )

        provenance = importer.import_file(
            provenance_path
        )

        print()
        print("Provenance imported successfully")
        print("-" * 40)
        print(
            f"Repository : {provenance.repository}"
        )
        print(
            f"Commit     : {provenance.commit_sha}"
        )
        print(
            f"Branch     : {provenance.branch}"
        )
        print(
            f"Workflow   : {provenance.workflow}"
        )
        print(
            f"Run ID     : {provenance.run_id}"
        )
        print(
            f"Image      : {provenance.image}"
        )
        print(
            f"Image ID   : {provenance.image_id}"
        )

        print()
        print(
            "Repository -> Container Image "
            "provenance added to graph."
        )

        return 0

    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
