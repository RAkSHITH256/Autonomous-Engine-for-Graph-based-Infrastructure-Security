from backend.models.finding import Finding


class TrivyParser:

    def parse(self, evidence):
        findings = []

        results = evidence.raw_data.get("Results", [])

        image = evidence.metadata.get("image", "UNKNOWN")

        for result in results:
            vulnerabilities = result.get("Vulnerabilities") or []

            for vulnerability in vulnerabilities:
                vulnerability_id = vulnerability.get(
                    "VulnerabilityID", "UNKNOWN"
                )

                severity = vulnerability.get(
                    "Severity", "UNKNOWN"
                )

                package = vulnerability.get(
                    "PkgName", "UNKNOWN"
                )

                installed_version = vulnerability.get(
                    "InstalledVersion", ""
                )

                fixed_version = vulnerability.get(
                    "FixedVersion", ""
                )

                target = result.get(
                    "Target",
                    image
                )

                target_type = result.get(
                    "Type",
                    "UNKNOWN"
                )

                finding = Finding(
                    finding_id=f"trivy-{vulnerability_id}-{package}",
                    category="container_vulnerability",
                    severity=severity,
                    title=f"{vulnerability_id} in {package}",
                    description=(
                        vulnerability.get("Description")
                        or f"{vulnerability_id} detected in {package}"
                    ),
                    asset_id=image,
                    evidence_ids=[evidence.evidence_id],
                    metadata={
    "source": "TRIVY",
    "vulnerability_id": vulnerability_id,
    "package": package,
    "installed_version": installed_version,
    "fixed_version": fixed_version,
    "target": target,
    "target_type": target_type,
    "image_id": evidence.metadata.get("image_id"),
},
                )

                findings.append(finding)

        return findings