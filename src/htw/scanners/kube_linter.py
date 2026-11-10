"""kube-linter: Kubernetes manifest checks. Local files only."""

from __future__ import annotations

from htw.core.finding import IAC, Finding, Location, Severity
from htw.core.redact import clean_text
from htw.detect.model import StackProfile
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_list, parse_json, repo_path
from htw.scanners.targets import keys_for_kube_linter


class KubeLinter(ToolAdapter):
    name = "kube-linter"
    binary = "kube-linter"
    homepage = "https://github.com/stackrox/kube-linter"
    install_hint = (
        "`brew install kube-linter`, or download a release from "
        "https://github.com/stackrox/kube-linter/releases"
    )
    network = "none"
    version_args = ("version",)

    def coverage(self, profile: StackProfile) -> set[str]:
        return keys_for_kube_linter(profile)

    def scan(self, ctx: ScanContext) -> list[Finding]:
        argv = ["kube-linter", "lint", ".", "--format", "json"]
        result = ctx.runner.run(argv, cwd=ctx.root)
        if not result.stdout.strip():
            if result.returncode == 0:
                return []
            raise self._fail(result)
        report = as_dict(parse_json(self.name, result.stdout))
        findings = []
        for raw in as_list(report.get("Reports")):
            entry = as_dict(raw)
            diagnostic = as_dict(entry.get("Diagnostic"))
            metadata = as_dict(as_dict(as_dict(entry.get("Object")).get("Metadata")))
            path = repo_path(ctx.root, metadata.get("FilePath"))
            rule = str(entry.get("Check") or "")
            if not rule or path is None:
                continue
            findings.append(
                Finding(
                    asset_id=ctx.asset.id,
                    agent="iac",
                    tool=self.name,
                    category=IAC,
                    rule_id=rule,
                    title=rule,
                    message=clean_text(diagnostic.get("Message")),
                    severity=Severity.MEDIUM,
                    location=Location(path=path),
                )
            )
        return findings
