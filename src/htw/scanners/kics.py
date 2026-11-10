"""KICS: IaC queries bundled with the binary. Nothing is sent to a cloud API."""

from __future__ import annotations

from htw.core.finding import IAC, Finding, Location, Severity
from htw.core.redact import clean_text
from htw.detect.model import StackProfile
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_int, as_list, parse_json, read_json_file, repo_path
from htw.scanners.targets import keys_for_kics

# Platforms this agent owns. Dockerfile and CI results belong to the other agents.
_PLATFORMS = {
    "terraform": "iac:terraform",
    "cloudformation": "iac:cloudformation",
    "kubernetes": "iac:kubernetes",
    "k8s": "iac:kubernetes",
    "ansible": "iac:ansible",
    "helm": "iac:kubernetes",
}


class Kics(ToolAdapter):
    name = "kics"
    binary = "kics"
    homepage = "https://github.com/Checkmarx/kics"
    install_hint = (
        "`brew install kics`, or download a release from https://github.com/Checkmarx/kics/releases"
    )
    network = "none; queries bundled with the binary are used"
    version_args = ("version",)

    def coverage(self, profile: StackProfile) -> set[str]:
        return keys_for_kics(profile)

    def scan(self, ctx: ScanContext) -> list[Finding]:
        output = ctx.artifacts_dir / "kics"
        output.mkdir(parents=True, exist_ok=True)
        argv = [
            "kics", "scan", "--path", ".",
            "--report-formats", "json", "--output-path", str(output),
            "--disable-secrets", "--silent",
        ]  # fmt: skip
        result = self.invoke(ctx, argv, writable=(output,))
        report_path = next(output.glob("*.json"), None)
        if report_path is None:
            raise self._fail(result, "wrote no JSON report")
        report = as_dict(read_json_file(self.name, report_path))
        # Touch parse_json so a non-object report still fails the same way.
        if not report and result.stdout.strip():
            report = as_dict(parse_json(self.name, result.stdout))
        wanted = keys_for_kics(ctx.profile)
        findings = []
        for query in as_list(report.get("queries")):
            entry = as_dict(query)
            key = _PLATFORMS.get(str(entry.get("platform") or "").lower().replace(" ", ""))
            if key not in wanted:
                continue
            rule = str(entry.get("query_id") or entry.get("query_name") or "")
            title = clean_text(entry.get("query_name")) or rule
            for raw_file in as_list(entry.get("files")):
                location = as_dict(raw_file)
                path = repo_path(ctx.root, location.get("file_name"))
                if path is None or not rule:
                    continue
                line = as_int(location.get("line"))
                findings.append(
                    Finding(
                        asset_id=ctx.asset.id,
                        agent="iac",
                        tool=self.name,
                        category=IAC,
                        rule_id=rule,
                        title=title,
                        message=clean_text(location.get("issue_type") or entry.get("description")),
                        severity=Severity.parse(entry.get("severity")),
                        location=Location(path=path, start_line=line, end_line=line),
                    )
                )
        return findings
