from backend.models.finding import Finding


class SBOMFindingAdapter:
    """
    Converts SBOM dependency records into AEGIS Finding objects.
    """

    def to_finding(
        self,
        dependency: dict,
        asset_id: str,
    ) -> Finding:

        if not asset_id:
            raise ValueError("asset_id is required")

        package = dependency.get(
            "name",
            "UNKNOWN",
        )

        version = dependency.get(
            "version",
            "UNKNOWN",
        )

        finding_id = (
            f"SBOM-{asset_id}-{package}-{version}"
        )

        return Finding(
            finding_id=finding_id,
            category="DEPENDENCY",
            severity="INFO",
            title=f"Dependency detected: {package}",
            description=(
                f"SBOM dependency {package} "
                f"version {version} was detected."
            ),
            asset_id=asset_id,
            evidence_ids=[],
            status="OPEN",
            metadata={
                # Source
                "source": "SBOM",

                # IMPORTANT:
                # The rest of AEGIS expects the dependency
                # name under the key "package".
                "package": package,

                "version": version,

                "type": dependency.get(
                    "type",
                    "library",
                ),

                "purl": dependency.get(
                    "purl"
                ),

                "scope": dependency.get(
                    "scope"
                ),

                # Compatibility alias
                "dependency_name": package,
            },
        )

    def to_findings(
        self,
        dependencies: list[dict],
        asset_id: str,
    ) -> list[Finding]:

        if not asset_id:
            raise ValueError("asset_id is required")

        return [
            self.to_finding(
                dependency=dependency,
                asset_id=asset_id,
            )
            for dependency in dependencies
        ]