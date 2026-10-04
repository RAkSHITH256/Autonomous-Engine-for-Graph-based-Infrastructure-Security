from pathlib import Path

from backend.graph.graph_builder import GraphBuilder
from backend.models.build_provenance import BuildProvenance
from backend.provenance.provenance_parser import ProvenanceParser


class ProvenanceImporter:
    """
    Imports CI/CD build provenance into the AEGIS security graph.
    """

    def __init__(
        self,
        graph_builder: GraphBuilder,
        parser: ProvenanceParser | None = None,
    ):
        self.graph_builder = graph_builder
        self.parser = parser or ProvenanceParser()

    def import_file(
        self,
        path: str | Path,
    ) -> BuildProvenance:
        """
        Parse and import a build provenance JSON file.
        """

        provenance = self.parser.parse_file(path)

        self.graph_builder.add_build_provenance(
            provenance
        )

        return provenance
