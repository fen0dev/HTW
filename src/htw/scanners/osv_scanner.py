"""OSV-Scanner: known vulnerabilities in dependencies, matched against osv.dev."""

from __future__ import annotations

from typing import Any

from htw.core.finding import DEPENDENCY, Finding, Location, Package, Severity
from htw.core.fingerprint import normalize_package_name
from htw.core.redact import clean_text
from htw.detect.model import PACKAGE_MANAGER, StackProfile
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import (
    as_dict,
    as_float,
    as_list,
    cwe_ids,
    http_links,
    parse_json,
    unique,
)

EXIT_VULNERABILITIES = 1
EXIT_NO_PACKAGES = 128


def primary_id(ids: list[str]) -> str:
    """Pick one advisory id for a group of aliases, deterministically."""
    for prefix in ("GHSA-", "CVE-"):
        matching = sorted(i for i in ids if i.startswith(prefix))
        if matching:
            return matching[0]
    return sorted(ids)[0]


def fixed_versions(vulnerabilities: list[dict[str, Any]], ecosystem: str, name: str) -> list[str]:
    wanted = normalize_package_name(ecosystem, name).lower()
    versions = []
    for vulnerability in vulnerabilities:
        for affected in as_list(vulnerability.get("affected")):
            package = as_dict(as_dict(affected).get("package"))
            candidate = normalize_package_name(
                str(package.get("ecosystem") or ""), str(package.get("name") or "")
            ).lower()
            if candidate != wanted:
                continue
            for version_range in as_list(as_dict(affected).get("ranges")):
                if as_dict(version_range).get("type") == "GIT":
                    continue
                for event in as_list(as_dict(version_range).get("events")):
                    fixed = as_dict(event).get("fixed")
                    if isinstance(fixed, str) and fixed:
                        versions.append(fixed)
    return versions


class OsvScanner(ToolAdapter):
    name = "osv-scanner"
    binary = "osv-scanner"
    homepage = "https://github.com/google/osv-scanner"
    install_hint = (
        "`brew install osv-scanner`, or download a release from "
        "https://github.com/google/osv-scanner/releases"
    )
    network = (
        "sends package names and versions to osv.dev (and deps.dev to resolve transitive "
        "dependencies); no source code is sent"
    )

    def coverage(self, profile: StackProfile) -> set[str]:
        return {"vulns"} if profile.has(PACKAGE_MANAGER) else set()

    @staticmethod
    def command(version: str | None) -> list[str]:
        """`scan source` is the v2 syntax; v1 takes the flags directly."""
        major = (version or "2").split(".")[0]
        subcommand = ["scan", "source"] if not major.isdigit() or int(major) >= 2 else []
        return ["osv-scanner", *subcommand, "--format", "json", "-r", "."]

    def scan(self, ctx: ScanContext) -> list[Finding]:
        version = self.version(ctx.runner, ctx.root)
        result = ctx.runner.run(self.command(version), cwd=ctx.root)
        if result.returncode == EXIT_NO_PACKAGES:
            return []
        if result.returncode not in (0, EXIT_VULNERABILITIES) or not result.stdout.strip():
            raise self._fail(result)
        report = as_dict(parse_json(self.name, result.stdout))

        findings = []
        for raw_result in as_list(report.get("results")):
            source = as_dict(as_dict(raw_result).get("source"))
            path = ctx.relative(str(source.get("path") or ""))
            for raw_package in as_list(as_dict(raw_result).get("packages")):
                entry = as_dict(raw_package)
                package = as_dict(entry.get("package"))
                name = str(package.get("name") or "")
                ecosystem = str(package.get("ecosystem") or "unknown")
                version_found = str(package.get("version") or "")
                by_id = {
                    str(v.get("id")): v
                    for v in map(as_dict, as_list(entry.get("vulnerabilities")))
                    if v.get("id")
                }
                if not name:
                    continue
                for raw_group in as_list(entry.get("groups")):
                    group = as_dict(raw_group)
                    ids = [str(i) for i in as_list(group.get("ids")) if i]
                    if not ids:
                        continue
                    advisory = primary_id(ids)
                    members = [by_id[i] for i in ids if i in by_id]
                    details = by_id.get(advisory) or (members[0] if members else {})
                    score = as_float(group.get("max_severity"))
                    database = [as_dict(m.get("database_specific")) for m in members]
                    if score is not None and score > 0:
                        severity = Severity.from_cvss(score)
                    else:
                        severity = Severity.parse(
                            next((d["severity"] for d in database if d.get("severity")), None)
                        )
                    aliases = sorted(str(a) for a in as_list(group.get("aliases")))
                    weaknesses = cwe_ids([d.get("cwe_ids") for d in database])
                    references = [
                        as_dict(r).get("url")
                        for member in members
                        for r in as_list(member.get("references"))
                    ]
                    findings.append(
                        Finding(
                            asset_id=ctx.asset.id,
                            agent="deps_sbom",
                            tool=self.name,
                            category=DEPENDENCY,
                            rule_id=advisory,
                            title=f"{name} {version_found}: {advisory}",
                            message=clean_text(details.get("summary") or details.get("details"))
                            or f"{name} {version_found} is affected by {advisory}.",
                            severity=severity,
                            location=Location(path=path),
                            package=Package(
                                ecosystem=ecosystem,
                                name=name,
                                version=version_found,
                                fixed_versions=unique(fixed_versions(members, ecosystem, name)),
                                purl=str(package.get("purl") or "").split("?")[0] or None,
                            ),
                            identifiers=unique([advisory, *aliases, *weaknesses], limit=12),
                            references=http_links(references),
                            cvss_score=score if score else None,
                        )
                    )
        return findings
