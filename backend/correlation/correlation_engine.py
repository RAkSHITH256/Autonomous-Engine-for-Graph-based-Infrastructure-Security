from backend.models.finding import Finding
from backend.models.asset import Asset


class CorrelationEngine:
    """
    Correlates normalized AEGIS findings with infrastructure assets.

    Supports:

        1. Direct asset ID correlation
        2. Docker image reference correlation
        3. Docker image ID correlation
    """

    # =========================================================
    # NORMALIZE IMAGE ID
    # =========================================================

    @staticmethod
    def _normalize_image_id(
        image_id: str | None,
    ) -> str:
        """
        Normalize Docker image IDs.

        Examples:

            sha256:abcdef123
            abcdef123

        become:

            abcdef123
        """

        if not image_id:
            return ""

        normalized = str(image_id).strip()

        if normalized.startswith("sha256:"):
            normalized = normalized[
                len("sha256:") :
            ]

        return normalized

    # =========================================================
    # CORRELATE SINGLE FINDING
    # =========================================================

    def correlate_finding(
        self,
        finding: Finding,
        assets: list[Asset],
    ) -> Asset | None:
        """
        Match a finding to an infrastructure asset.

        Correlation order:

            1. Direct asset ID
            2. Image reference
            3. Docker image ID
        """

        # ---------------------------------------------------------
        # 1. Direct asset ID correlation
        # ---------------------------------------------------------

        for asset in assets:

            if asset.asset_id == finding.asset_id:
                return asset

        # ---------------------------------------------------------
        # 2. Image reference correlation
        # ---------------------------------------------------------

        finding_image = finding.asset_id

        if finding_image:

            for asset in assets:

                asset_image = asset.metadata.get(
                    "image"
                )

                image_reference = asset.metadata.get(
                    "image_reference"
                )

                if (
                    asset_image == finding_image
                    or image_reference == finding_image
                ):
                    return asset

        # ---------------------------------------------------------
        # 3. Docker image ID correlation
        # ---------------------------------------------------------

        finding_image_id = (
            finding.metadata.get(
                "image_id"
            )
        )

        normalized_finding_image_id = (
            self._normalize_image_id(
                finding_image_id
            )
        )

        if normalized_finding_image_id:

            for asset in assets:

                asset_image_id = asset.metadata.get(
                    "image_id"
                )

                normalized_asset_image_id = (
                    self._normalize_image_id(
                        asset_image_id
                    )
                )

                if not normalized_asset_image_id:
                    continue

                if (
                    normalized_finding_image_id.startswith(
                        normalized_asset_image_id
                    )
                    or normalized_asset_image_id.startswith(
                        normalized_finding_image_id
                    )
                ):
                    return asset

        # ---------------------------------------------------------
        # No correlation
        # ---------------------------------------------------------

        return None

    # =========================================================
    # CORRELATE MULTIPLE FINDINGS
    # =========================================================

    def correlate_findings(
        self,
        findings: list[Finding],
        assets: list[Asset],
    ) -> dict[str, Asset]:

        correlations = {}

        for finding in findings:

            asset = self.correlate_finding(
                finding,
                assets,
            )

            if asset is not None:

                correlations[
                    finding.finding_id
                ] = asset

        return correlations

    # =========================================================
    # STORE CORRELATIONS
    # =========================================================

    def store_correlations(
        self,
        correlations: dict[str, Asset],
        findings: list[Finding],
        client,
    ) -> None:
        """
        Persist finding/vulnerability relationships in Neo4j.
        """

        finding_map = {
            finding.finding_id: finding
            for finding in findings
        }

        for finding_id, asset in correlations.items():

            finding = finding_map[
                finding_id
            ]

            query = """
            MERGE (asset:Asset {
                asset_id: $asset_id
            })

            SET
                asset.name = $asset_name,
                asset.type = $asset_type,
                asset.image = $asset_image

            MERGE (finding:Finding {
                finding_id: $finding_id
            })

            SET
                finding.category = $category,
                finding.severity = $severity,
                finding.title = $title

            MERGE (asset)-[:HAS_FINDING]->(finding)

            MERGE (vulnerability:Vulnerability {
                vulnerability_id: $vulnerability_id
            })

            SET
                vulnerability.identifier =
                    $vulnerability_identifier,

                vulnerability.severity =
                    $severity,

                vulnerability.package =
                    $package,

                vulnerability.installed_version =
                    $installed_version,

                vulnerability.fixed_version =
                    $fixed_version

            MERGE (finding)-[:IDENTIFIES]->(vulnerability)

            MERGE (asset)-[:HAS_VULNERABILITY]->(vulnerability)
            """

            with client.driver.session() as session:

                session.run(
                    query,

                    # -------------------------------------------------
                    # Asset
                    # -------------------------------------------------

                    asset_id=asset.asset_id,

                    asset_name=asset.name,

                    asset_type=asset.asset_type,

                    asset_image=asset.metadata.get(
                        "image",
                        asset.metadata.get(
                            "image_reference"
                        ),
                    ),

                    # -------------------------------------------------
                    # Finding
                    # -------------------------------------------------

                    finding_id=finding.finding_id,

                    category=finding.category,

                    severity=finding.severity,

                    title=finding.title,

                    # -------------------------------------------------
                    # Vulnerability
                    # -------------------------------------------------

                    vulnerability_id=(
                        finding.metadata.get(
                            "vulnerability_id",
                            finding.finding_id,
                        )
                    ),

                    vulnerability_identifier=(
                        finding.metadata.get(
                            "vulnerability_id",
                            "UNKNOWN",
                        )
                    ),

                    package=finding.metadata.get(
                        "package",
                        "UNKNOWN",
                    ),

                    installed_version=(
                        finding.metadata.get(
                            "installed_version",
                            "UNKNOWN",
                        )
                    ),

                    fixed_version=(
                        finding.metadata.get(
                            "fixed_version",
                            "",
                        )
                    ),
                )