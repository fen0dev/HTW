"""Bandit: static analysis for Python."""

from __future__ import annotations

from htw.core.finding import SAST, Finding, Location, Severity
from htw.core.redact import clean_text
from htw.detect.model import StackProfile
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_int, as_list, cwe_ids, http_links, parse_json


class Bandit(ToolAdapter):
    name = "bandit"
    binary = "bandit"
    homepage = "https://github.com/PyCQA/bandit"
    install_hint = "`pipx install bandit`"
    network = "none"

    def coverage(self, profile: StackProfile) -> set[str]:
        return {"sast:Python"} if "Python" in profile.languages else set()

    def scan(self, ctx: ScanContext) -> list[Finding]:
        result = self.invoke(ctx, ["bandit", "-r", ".", "-f", "json", "-q"])
        if result.returncode not in (0, 1) or not result.stdout.strip():
            raise self._fail(result)
        report = as_dict(parse_json(self.name, result.stdout))

        findings = []
        for raw in as_list(report.get("results")):
            entry = as_dict(raw)
            path = ctx.relative(str(entry.get("filename") or ""))
            if path is None:
                continue
            start = as_int(entry.get("line_number"))
            lines = [n for n in map(as_int, as_list(entry.get("line_range"))) if n]
            findings.append(
                Finding(
                    asset_id=ctx.asset.id,
                    agent="sast",
                    tool=self.name,
                    category=SAST,
                    rule_id=str(entry.get("test_id") or "unknown"),
                    title=str(entry.get("test_name") or entry.get("test_id") or "bandit finding"),
                    message=clean_text(entry.get("issue_text")),
                    severity=Severity.parse(entry.get("issue_severity")),
                    location=Location(
                        path=path, start_line=start, end_line=max(lines, default=start)
                    ),
                    identifiers=cwe_ids(entry.get("issue_cwe")),
                    references=http_links([entry.get("more_info")]),
                    confidence=str(entry.get("issue_confidence") or "").lower() or None,
                )
            )
        return findings
