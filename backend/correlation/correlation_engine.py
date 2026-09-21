from backend.models.finding import Finding
from backend.models.asset import Asset


class CorrelationEngine:

    def correlate_finding(
        self,
        finding: Finding,
        assets: list[Asset],
    ) -> Asset | None:

        # ---------------------------------------------------------
        # 1. Direct asset ID correlation
        # ---------------------------------------------------------
        for asset in assets:
            if asset.asset_id == finding.asset_id:
                return asset

        # ---------------------------------------------------------
        # 2. Image-based correlation
        #
        # Trivy stores the affected image in finding.asset_id.
        # Infrastructure assets store their image in metadata["image"].
        # ---------------------------------------------------------
        finding_image = finding.asset_id

        if finding_image:
            for asset in assets:

                asset_image = asset.metadata.get("image")

                if asset_image == finding_image:
                    return asset

        # ---------------------------------------------------------
        # No correlation found
        # ---------------------------------------------------------
        return None

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
                correlations[finding.finding_id] = asset

        return correlations

    def store_correlations(
        self,
        correlations: dict[str, Asset],
        findings: list[Finding],
        client,
    ) -> None:

        # Create a quick lookup:
        # finding_id -> Finding object
        finding_map = {
            finding.finding_id: finding
            for finding in findings
        }

        for finding_id, asset in correlations.items():

            finding = finding_map[finding_id]

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
                vulnerability.identifier = $vulnerability_identifier,
                vulnerability.severity = $severity,
                vulnerability.package = $package,
                vulnerability.installed_version = $installed_version,
                vulnerability.fixed_version = $fixed_version

            MERGE (finding)-[:IDENTIFIES]->(vulnerability)

            MERGE (asset)-[:HAS_VULNERABILITY]->(vulnerability)
            """

            with client.driver.session() as session:

                session.run(
                    query,

                    # -------------------------
                    # Asset
                    # -------------------------
                    asset_id=asset.asset_id,
                    asset_name=asset.name,
                    asset_type=asset.asset_type,
                    asset_image=asset.metadata.get("image"),

                    # -------------------------
                    # Finding
                    # -------------------------
                    finding_id=finding.finding_id,
                    category=finding.category,
                    severity=finding.severity,
                    title=finding.title,

                    # -------------------------
                    # Vulnerability
                    # -------------------------
                    vulnerability_id=finding.metadata.get(
                        "vulnerability_id",
                        finding.finding_id,
                    ),

                    vulnerability_identifier=finding.metadata.get(
                        "vulnerability_id",
                        "UNKNOWN",
                    ),

                    package=finding.metadata.get(
                        "package",
                        "UNKNOWN",
                    ),

                    installed_version=finding.metadata.get(
                        "installed_version",
                        "UNKNOWN",
                    ),

                    fixed_version=finding.metadata.get(
                        "fixed_version",
                        "",
                    ),
                )