"""OpenSSF Scorecard, opt-in.

The default scan does not run it: several checks talk to GitHub. When the scope file
names it, HTW uses local mode and does not pass a token of its own.
"""

from __future__ import annotations

from htw.core.finding import PIPELINE, Finding, Severity
from htw.core.redact import clean_text
from htw.detect.model import CI_CD, StackProfile
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_float, as_list, parse_json


class Scorecard(ToolAdapter):
    name = "scorecard"
    binary = "scorecard"
    homepage = "https://github.com/ossf/scorecard"
    install_hint = (
        "`brew install scorecard`, or download a release from "
        "https://github.com/ossf/scorecard/releases"
    )
    network = (
        "opt-in; local mode can still contact GitHub for checks that need it. HTW adds no token"
    )
    optional = True
    version_args = ("version",)

    def coverage(self, profile: StackProfile) -> set[str]:
        if profile.has(CI_CD, "GitHub Actions") or profile.is_git_repository:
            return {"supply-chain:scorecard"}
        return set()

    def scan(self, ctx: ScanContext) -> list[Finding]:
        argv = ["scorecard", "--local", ".", "--format", "json", "--show-details"]
        result = ctx.runner.run(argv, cwd=ctx.root)
        if not result.stdout.strip():
            raise self._fail(result)
        report = as_dict(parse_json(self.name, result.stdout))
        findings = []
        for raw in as_list(report.get("checks")):
            entry = as_dict(raw)
            score = as_float(entry.get("score"))
            name = str(entry.get("name") or "")
            if not name or score is None or score >= 7:
                continue
            severity = (
                Severity.HIGH if score <= 2 else Severity.MEDIUM if score <= 5 else Severity.LOW
            )
            findings.append(
                Finding(
                    asset_id=ctx.asset.id,
                    agent="pipeline",
                    tool=self.name,
                    category=PIPELINE,
                    rule_id=name,
                    title=f"Scorecard {name} scored {score:g}/10",
                    message=clean_text(entry.get("reason")),
                    severity=severity,
                )
            )
        return findings
