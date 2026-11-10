"""Trivy: known vulnerabilities in dependencies (filesystem mode)."""

from __future__ import annotations

from htw.core.finding import DEPENDENCY, Finding, Location, Package, Severity
from htw.core.redact import clean_text
from htw.detect.model import PACKAGE_MANAGER, StackProfile
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import (
    as_dict,
    as_float,
    as_list,
    cwe_ids,
    ecosystem_for,
    http_links,
    parse_json,
    unique,
)


class Trivy(ToolAdapter):
    name = "trivy"
    binary = "trivy"
    homepage = "https://github.com/aquasecurity/trivy"
    install_hint = (
        "`brew install trivy`, or download a release from "
        "https://github.com/aquasecurity/trivy/releases"
    )
    network = "downloads its vulnerability database; package data stays local"

    def coverage(self, profile: StackProfile) -> set[str]:
        return {"vulns"} if profile.has(PACKAGE_MANAGER) else set()

    def scan(self, ctx: ScanContext) -> list[Finding]:
        argv = ["trivy", "fs", "--scanners", "vuln", "--format", "json", "--quiet"]
        for pattern in ctx.asset.exclude:
            cleaned = pattern.strip().strip("/").removesuffix("/**")
            if cleaned and (ctx.root / cleaned).is_dir():
                argv += ["--skip-dirs", cleaned]
        argv.append(".")
        result = ctx.runner.run(argv, cwd=ctx.root, extra_env={"TRIVY_SKIP_VERSION_CHECK": "true"})
        if result.returncode != 0 or not result.stdout.strip():
            raise self._fail(result)
        report = as_dict(parse_json(self.name, result.stdout))

        findings = []
        for raw_result in as_list(report.get("Results")):
            target = as_dict(raw_result)
            path = ctx.relative(str(target.get("Target") or ""))
            for raw in as_list(target.get("Vulnerabilities")):
                entry = as_dict(raw)
                advisory = str(entry.get("VulnerabilityID") or "")
                name = str(entry.get("PkgName") or "")
                if not advisory or not name:
                    continue
                version = str(entry.get("InstalledVersion") or "")
                scores = [
                    as_float(as_dict(vendor).get("V3Score"))
                    for vendor in as_dict(entry.get("CVSS")).values()
                ]
                vendor_ids = [str(v) for v in as_list(entry.get("VendorIDs"))]
                fixed = [v.strip() for v in str(entry.get("FixedVersion") or "").split(",")]
                findings.append(
                    Finding(
                        asset_id=ctx.asset.id,
                        agent="deps_sbom",
                        tool=self.name,
                        category=DEPENDENCY,
                        rule_id=advisory,
                        title=f"{name} {version}: {advisory}",
                        message=clean_text(entry.get("Title") or entry.get("Description"))
                        or f"{name} {version} is affected by {advisory}.",
                        severity=Severity.parse(entry.get("Severity")),
                        location=Location(path=path),
                        package=Package(
                            ecosystem=ecosystem_for(target.get("Type")),
                            name=name,
                            version=version,
                            fixed_versions=unique(fixed),
                            purl=str(as_dict(entry.get("PkgIdentifier")).get("PURL") or "") or None,
                        ),
                        identifiers=unique([advisory, *vendor_ids, *cwe_ids(entry.get("CweIDs"))]),
                        references=http_links(
                            [entry.get("PrimaryURL"), *as_list(entry.get("References"))]
                        ),
                        cvss_score=max((s for s in scores if s is not None), default=None),
                    )
                )
        return findings
