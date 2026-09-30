from backend.models.finding import Finding


class SBOMFindingAdapter:
    """
    Converts SBOM dependency records into AEGIS Finding objects.

    The adapter does not perform vulnerability scanning itself.
    It normalizes dependency information into the common
    Finding model used by the AEGIS correlation pipeline.
    """

    def to_finding(
        self,
        dependency: dict,
        asset_id: str,
    ) -> Finding:
        """
        Convert one SBOM dependency into one Finding.
        """

        if not asset_id:
            raise ValueError("asset_id is required")

        name = dependency.get("name", "UNKNOWN")
        version = dependency.get("version", "UNKNOWN")

        finding_id = (
            f"SBOM-{asset_id}-{name}-{version}"
        )

        return Finding(
            finding_id=finding_id,

            # Finding category
            category="DEPENDENCY",

            # SBOM presence itself is informational.
            # Actual vulnerability severity can be enriched later
            # by vulnerability scanners such as Trivy.
            severity="INFO",

            title=f"Dependency detected: {name}",

            description=(
                f"SBOM dependency {name} "
                f"version {version} was detected."
            ),

            asset_id=asset_id,

            evidence_ids=[],

            status="OPEN",

            metadata={
                # Source of the finding
                "source": "SBOM",

                # Dependency information
                "dependency_name": name,
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
            },
        )

    def to_findings(
        self,
        dependencies: list[dict],
        asset_id: str,
    ) -> list[Finding]:
        """
        Convert multiple SBOM dependencies into Findings.
        """

        if not asset_id:
            raise ValueError("asset_id is required")

        findings = []

        for dependency in dependencies:

            finding = self.to_finding(
                dependency=dependency,
                asset_id=asset_id,
            )

            findings.append(finding)

        return findings