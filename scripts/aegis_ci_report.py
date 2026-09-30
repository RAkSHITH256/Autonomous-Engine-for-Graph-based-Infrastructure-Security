#!/usr/bin/env python3
"""
AEGIS CI report engine.

Consumes the real outputs produced by:
  - Trivy filesystem scan
  - Semgrep JSON scan
  - CycloneDX SBOM

Produces:
  - aegis-report.json
  - aegis-report.md

This is the CI integration/reporting layer. It does not perform real
infrastructure changes. Remediation entries are recommendations only.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any


SEVERITY_WEIGHT = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
    "UNKNOWN": 0,
}


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON: {path}: {exc}") from exc


def trivy_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for result in data.get("Results", []) or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append(
                {
                    "source": "trivy",
                    "id": vuln.get("VulnerabilityID", "UNKNOWN"),
                    "severity": str(vuln.get("Severity", "UNKNOWN")).upper(),
                    "title": vuln.get("Title") or vuln.get("PkgName") or "Dependency vulnerability",
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "target": target,
                    "url": vuln.get("PrimaryURL", ""),
                }
            )

    return findings


def semgrep_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for item in data.get("results", []) or []:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        severity = str(
            metadata.get("severity")
            or extra.get("severity")
            or "MEDIUM"
        ).upper()

        findings.append(
            {
                "source": "semgrep",
                "id": item.get("check_id", "UNKNOWN"),
                "severity": severity,
                "title": extra.get("message") or item.get("check_id", "Semgrep finding"),
                "package": "",
                "installed_version": "",
                "fixed_version": "",
                "target": item.get("path", ""),
                "line": (item.get("start") or {}).get("line"),
                "url": "",
            }
        )

    return findings


def sbom_summary(data: dict[str, Any]) -> dict[str, Any]:
    components = data.get("components") or []
    return {
        "component_count": len(components),
        "components": [
            {
                "name": c.get("name", ""),
                "version": c.get("version", ""),
                "type": c.get("type", ""),
                "purl": c.get("purl", ""),
            }
            for c in components
        ],
    }


def risk_score(findings: list[dict[str, Any]]) -> int:
    """
    CI exposure score derived only from scanner findings.

    This intentionally is NOT presented as the graph attack-path score.
    The graph-aware risk engine remains a separate AEGIS subsystem.
    """
    raw = sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    return min(100, raw)


def risk_level(score: int) -> str:
    if score >= 30:
        return "CRITICAL"
    if score >= 15:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def recommendation(finding: dict[str, Any]) -> str:
    source = finding["source"]
    fixed = finding.get("fixed_version")

    if source == "trivy":
        package = finding.get("package") or "affected dependency"
        if fixed:
            return f"Upgrade {package} to {fixed} or later, then rerun AEGIS."
        return f"Review {package}; no fixed version was reported by Trivy."

    return (
        f"Review {finding['target']} and address Semgrep rule "
        f"{finding['id']}, then rerun AEGIS."
    )


def build_report(
    trivy: dict[str, Any],
    semgrep: dict[str, Any],
    sbom: dict[str, Any],
) -> dict[str, Any]:
    findings = trivy_findings(trivy) + semgrep_findings(semgrep)
    severity_counts = Counter(f["severity"] for f in findings)
    score = risk_score(findings)

    enriched = []
    for finding in findings:
        enriched.append(
            {
                **finding,
                "recommendation": recommendation(finding),
            }
        )

    return {
        "schema_version": "1.0",
        "status": "success",
        "repository": os.getenv("GITHUB_REPOSITORY", "local"),
        "commit": os.getenv("GITHUB_SHA", "local"),
        "branch": os.getenv("GITHUB_REF_NAME", "local"),
        "summary": {
            "finding_count": len(findings),
            "critical": severity_counts.get("CRITICAL", 0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "ci_exposure_score": score,
            "ci_risk_level": risk_level(score),
            "sbom_component_count": len(sbom.get("components") or []),
        },
        "sources": {
            "trivy": {
                "findings": len(trivy_findings(trivy)),
            },
            "semgrep": {
                "findings": len(semgrep_findings(semgrep)),
                "errors": len(semgrep.get("errors") or []),
            },
            "sbom": sbom_summary(sbom),
        },
        "findings": enriched,
        "remediation": {
            "mode": "recommendation_only",
            "real_changes_performed": False,
            "items": [
                {
                    "id": f["id"],
                    "action": f["recommendation"],
                }
                for f in enriched
            ],
        },
    }


def markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        "# AEGIS Security Report",
        "",
        f"**Repository:** `{report['repository']}`",
        f"**Commit:** `{report['commit']}`",
        f"**Branch:** `{report['branch']}`",
        "",
        "## Summary",
        "",
        f"- Findings: **{s['finding_count']}**",
        f"- Critical: **{s['critical']}**",
        f"- High: **{s['high']}**",
        f"- Medium: **{s['medium']}**",
        f"- Low: **{s['low']}**",
        f"- CI exposure score: **{s['ci_exposure_score']}/100**",
        f"- CI risk level: **{s['ci_risk_level']}**",
        f"- SBOM components: **{s['sbom_component_count']}**",
        "",
        "> The CI exposure score summarizes scanner findings. It is not the graph attack-path risk score.",
        "",
        "## Findings and remediation",
        "",
    ]

    if not report["findings"]:
        lines.append("No Trivy or Semgrep findings were reported.")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            "| Source | ID | Severity | Target | Package | Fixed version | Recommendation |",
            "|---|---|---|---|---|---|---|",
        ]
    )

    for f in report["findings"]:
        target = str(f.get("target", "")).replace("|", "\\|")
        recommendation_text = f["recommendation"].replace("|", "\\|")
        lines.append(
            f"| {f['source']} | `{f['id']}` | {f['severity']} | "
            f"{target} | {f.get('package', '')} | {f.get('fixed_version', '')} | "
            f"{recommendation_text} |"
        )

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy", required=True, type=Path)
    parser.add_argument("--semgrep", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)

    report = build_report(
        load_json(args.trivy),
        load_json(args.semgrep),
        load_json(args.sbom),
    )

    (args.output / "aegis-report.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    (args.output / "aegis-report.md").write_text(
        markdown(report),
        encoding="utf-8",
    )

    print(markdown(report))


if __name__ == "__main__":
    main()
