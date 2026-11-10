"""Grype: known vulnerabilities in dependencies, matched locally against its database."""

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
from htw.scanners.syft import anchore_excludes


class Grype(ToolAdapter):
    name = "grype"
    binary = "grype"
    homepage = "https://github.com/anchore/grype"
    install_hint = (
        "`brew install grype`, or download a release from https://github.com/anchore/grype/releases"
    )
    network = "downloads its vulnerability database; package data stays local"
    version_args = ("version",)

    def coverage(self, profile: StackProfile) -> set[str]:
        return {"vulns"} if profile.has(PACKAGE_MANAGER) else set()

    def scan(self, ctx: ScanContext) -> list[Finding]:
        sbom = ctx.artifacts.get("sbom-syft")
        if sbom is not None:
            source = [f"sbom:{sbom}"]
        else:
            source = ["dir:.", *anchore_excludes(ctx.root, ctx.asset.exclude)]
        result = ctx.runner.run(
            ["grype", *source, "-o", "json", "-q"],
            cwd=ctx.root,
            extra_env={"GRYPE_CHECK_FOR_APP_UPDATE": "false"},
        )
        if result.returncode != 0 or not result.stdout.strip():
            raise self._fail(result)
        report = as_dict(parse_json(self.name, result.stdout))

        findings = []
        for raw in as_list(report.get("matches")):
            match = as_dict(raw)
            vulnerability = as_dict(match.get("vulnerability"))
            artifact = as_dict(match.get("artifact"))
            advisory = str(vulnerability.get("id") or "")
            name = str(artifact.get("name") or "")
            if not advisory or not name:
                continue
            related = [as_dict(r) for r in as_list(match.get("relatedVulnerabilities"))]
            scores = [
                as_float(as_dict(as_dict(c).get("metrics")).get("baseScore"))
                for source_entry in (vulnerability, *related)
                for c in as_list(source_entry.get("cvss"))
            ]
            score = max((s for s in scores if s is not None), default=None)
            locations = [as_dict(loc) for loc in as_list(artifact.get("locations"))]
            # Paths are reported relative to the scanned directory, with a leading slash.
            path = str(locations[0].get("path") or "").lstrip("/") if locations else ""
            fix = as_dict(vulnerability.get("fix"))
            weaknesses = cwe_ids(
                [as_dict(c).get("cwe") for c in as_list(vulnerability.get("cwes"))]
            )
            version = str(artifact.get("version") or "")
            findings.append(
                Finding(
                    asset_id=ctx.asset.id,
                    agent="deps_sbom",
                    tool=self.name,
                    category=DEPENDENCY,
                    rule_id=advisory,
                    title=f"{name} {version}: {advisory}",
                    message=clean_text(vulnerability.get("description"))
                    or f"{name} {version} is affected by {advisory}.",
                    severity=Severity.parse(vulnerability.get("severity")),
                    location=Location(path=ctx.relative(path)),
                    package=Package(
                        ecosystem=ecosystem_for(artifact.get("type")),
                        name=name,
                        version=version,
                        fixed_versions=unique([str(v) for v in as_list(fix.get("versions"))]),
                        purl=str(artifact.get("purl") or "") or None,
                    ),
                    identifiers=unique(
                        [advisory, *[str(r.get("id") or "") for r in related], *weaknesses]
                    ),
                    references=http_links(
                        [vulnerability.get("dataSource"), *as_list(vulnerability.get("urls"))]
                    ),
                    cvss_score=score,
                )
            )
        return findings
