"""Checkov: misconfigurations in IaC, Dockerfiles and CI configuration.

External module download is disabled, and nothing is uploaded. Checkov reads the
files in the asset and does not contact a cloud account.
"""

from __future__ import annotations

from htw.core.finding import CONTAINER, IAC, PIPELINE, Finding, Location, Severity
from htw.core.redact import clean_text
from htw.detect.model import CI_CD, StackProfile
from htw.detect.model import CONTAINER as CONTAINER_CATEGORY
from htw.detect.model import IAC as IAC_CATEGORY
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_int, as_list, http_links, parse_json, repo_path
from htw.scanners.targets import checkov_frameworks, keys_for_checkov

_CATEGORY = {IAC_CATEGORY: IAC, CONTAINER_CATEGORY: CONTAINER, CI_CD: PIPELINE}
_AGENT = {IAC_CATEGORY: "iac", CONTAINER_CATEGORY: "container", CI_CD: "pipeline"}


class Checkov(ToolAdapter):
    name = "checkov"
    binary = "checkov"
    homepage = "https://github.com/bridgecrewio/checkov"
    install_hint = "`pipx install checkov`"
    network = (
        "none with these flags: external modules are not downloaded and results are not uploaded"
    )

    def __init__(self, area: str) -> None:
        if area not in _CATEGORY:
            raise ValueError(area)
        self.area = area

    def coverage(self, profile: StackProfile) -> set[str]:
        return keys_for_checkov(profile, self.area)

    def scan(self, ctx: ScanContext) -> list[Finding]:
        frameworks = checkov_frameworks(ctx.profile, self.area)
        if not frameworks:
            return []
        argv = [
            "checkov", "-d", ".",
            "--framework", ",".join(frameworks),
            "--output", "json", "--compact", "--quiet",
            "--download-external-modules", "false",
            "--skip-results-upload",
        ]  # fmt: skip
        result = self.invoke(ctx, argv)
        if not result.stdout.strip():
            raise self._fail(result)
        payload = parse_json(self.name, result.stdout)
        blocks = payload if isinstance(payload, list) else [payload]
        findings = []
        for block in blocks:
            results = as_dict(as_dict(block).get("results"))
            for raw in as_list(results.get("failed_checks")):
                entry = as_dict(raw)
                rule = str(entry.get("check_id") or "")
                path = repo_path(ctx.root, entry.get("file_path") or entry.get("file_abs_path"))
                if not rule or path is None:
                    continue
                span = as_list(entry.get("file_line_range"))
                start = as_int(span[0]) if span else None
                end = as_int(span[1]) if len(span) > 1 else start
                findings.append(
                    Finding(
                        asset_id=ctx.asset.id,
                        agent=_AGENT[self.area],
                        tool=self.name,
                        category=_CATEGORY[self.area],
                        rule_id=rule,
                        title=clean_text(entry.get("check_name")) or rule,
                        message=clean_text(entry.get("check_name")),
                        severity=Severity.parse(entry.get("severity"), Severity.MEDIUM),
                        location=Location(path=path, start_line=start, end_line=end),
                        references=http_links([entry.get("guideline")]),
                    )
                )
        return findings
