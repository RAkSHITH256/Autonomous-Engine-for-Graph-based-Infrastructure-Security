from backend.models.finding import Finding


class TrivyParser:

    def parse(self, evidence):
        findings = []

        results = evidence.raw_data.get("Results", [])

        for result in results:
            vulnerabilities = result.get("Vulnerabilities", [])

            for vulnerability in vulnerabilities:
                vulnerability_id = vulnerability.get(
                    "VulnerabilityID",
                    "UNKNOWN"
                )

                severity = vulnerability.get(
                    "Severity",
                    "UNKNOWN"
                )

                package = vulnerability.get(
                    "PkgName",
                    "UNKNOWN"
                )

                installed_version = vulnerability.get(
                    "InstalledVersion",
                    "UNKNOWN"
                )

                fixed_version = vulnerability.get(
                    "FixedVersion",
                    "UNKNOWN"
                )

                finding = Finding(
                    finding_id=f"trivy-{vulnerability_id}-{package}",
                    category="container_vulnerability",
                    severity=severity,
                    title=f"{vulnerability_id} in {package}",
                    description=(
                        f"Trivy detected {vulnerability_id} in "
                        f"{package} version {installed_version}. "
                        f"Fixed version: {fixed_version or 'not available'}."
                    ),
                    asset_id=evidence.metadata["image"],
                    evidence_ids=[evidence.evidence_id],
                    metadata={
                        "vulnerability_id": vulnerability_id,
                        "package": package,
                        "installed_version": installed_version,
                        "fixed_version": fixed_version,
                    },
                )

                findings.append(finding)

        return findings