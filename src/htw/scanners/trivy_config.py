"""Trivy in config mode: misconfigurations in files, not running systems.

`trivy fs` (vulnerabilities) stays with the dependencies agent. This adapter runs
`trivy config` and keeps only the file types the calling agent is responsible for.
It does not pull images and it does not talk to a cloud API.
"""

from __future__ import annotations

from htw.core.finding import CONTAINER, IAC, Finding, Location, Severity
from htw.core.redact import clean_text
from htw.detect.model import StackProfile
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_int, as_list, cwe_ids, http_links, parse_json, repo_path
from htw.scanners.targets import keys_for_trivy, trivy_types

_CATEGORY = {"container": CONTAINER, "iac": IAC}


class TrivyConfig(ToolAdapter):
    name = "trivy-config"
    binary = "trivy"
    homepage = "https://github.com/aquasecurity/trivy"
    install_hint = (
        "`brew install trivy`, or download a release from "
        "https://github.com/aquasecurity/trivy/releases"
    )
    network = "HTW passes --skip-db-update; a missing local cache may still be downloaded once"

    def __init__(self, area: str) -> None:
        if area not in _CATEGORY:
            raise ValueError(area)
        self.area = area

    def coverage(self, profile: StackProfile) -> set[str]:
        return keys_for_trivy(profile, self.area)

    def scan(self, ctx: ScanContext) -> list[Finding]:
        accepted = trivy_types(ctx.profile, self.area)
        argv = [
            "trivy", "config", "--scanners", "misconfig", "--format", "json", "--quiet",
            "--skip-version-check", "--skip-db-update",
        ]  # fmt: skip
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
            kind = str(target.get("Type") or "").lower()
            if kind not in accepted:
                continue
            path = repo_path(ctx.root, target.get("Target"))
            for raw in as_list(target.get("Misconfigurations")):
                entry = as_dict(raw)
                rule = str(entry.get("ID") or entry.get("AVDID") or "")
                if not rule:
                    continue
                cause = as_dict(entry.get("CauseMetadata"))
                start = as_int(cause.get("StartLine"))
                findings.append(
                    Finding(
                        asset_id=ctx.asset.id,
                        agent=self.area,
                        tool=self.name,
                        category=_CATEGORY[self.area],
                        rule_id=rule,
                        title=clean_text(entry.get("Title")) or rule,
                        message=clean_text(entry.get("Message") or entry.get("Description")),
                        severity=Severity.parse(entry.get("Severity")),
                        location=Location(
                            path=path,
                            start_line=start,
                            end_line=as_int(cause.get("EndLine")) or start,
                        ),
                        identifiers=cwe_ids(entry.get("CweIDs") or cause.get("Code")),
                        references=http_links(
                            [entry.get("PrimaryURL"), *as_list(entry.get("References"))]
                        ),
                    )
                )
        return findings
