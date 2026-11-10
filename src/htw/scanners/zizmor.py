"""zizmor: static audit of GitHub Actions workflows.

`--offline` keeps the run on the files in the checkout. zizmor is not pointed at a
GitHub repository URL.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from htw.core.finding import PIPELINE, Finding, Location, Severity
from htw.core.redact import clean_text
from htw.detect.model import StackProfile
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_int, as_list, http_links, parse_json, repo_path
from htw.scanners.targets import keys_for_zizmor

_SEVERITIES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "unknown": Severity.MEDIUM,
}


def _location(root: Path, finding: dict[str, Any]) -> Location:
    path: str | None = None
    line: int | None = None

    def visit(node: object) -> None:
        nonlocal path, line
        if isinstance(node, dict):
            for key, value in node.items():
                if path is None and key in {"path", "file"} and isinstance(value, str):
                    path = repo_path(root, value)
                if line is None and key in {"line", "row", "start_line"}:
                    line = as_int(value)
                if isinstance(value, str) and value.startswith("line ") and line is None:
                    line = as_int(value.removeprefix("line "))
                visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)
        elif (
            isinstance(node, str)
            and path is None
            and (node.endswith((".yml", ".yaml")) or "/workflows/" in node)
        ):
            path = repo_path(root, node)

    visit(finding.get("locations"))
    return Location(path=path, start_line=line, end_line=line)


class Zizmor(ToolAdapter):
    name = "zizmor"
    binary = "zizmor"
    homepage = "https://github.com/zizmorcore/zizmor"
    install_hint = (
        "`brew install zizmor`, or download a release from "
        "https://github.com/zizmorcore/zizmor/releases"
    )
    network = "none; HTW passes --offline"

    def coverage(self, profile: StackProfile) -> set[str]:
        return keys_for_zizmor(profile)

    def scan(self, ctx: ScanContext) -> list[Finding]:
        argv = ["zizmor", "--offline", "--format", "json", "--no-progress", "."]
        result = self.invoke(ctx, argv)
        if not result.stdout.strip():
            if result.returncode == 0:
                return []
            raise self._fail(result)
        payload = parse_json(self.name, result.stdout)
        raw_findings = (
            payload if isinstance(payload, list) else as_list(as_dict(payload).get("findings"))
        )
        findings = []
        for raw in raw_findings:
            entry = as_dict(raw)
            if entry.get("ignored") is True:
                continue
            rule = str(entry.get("ident") or entry.get("rule") or "")
            if not rule:
                continue
            determinations = as_dict(entry.get("determinations"))
            severity = _SEVERITIES.get(
                str(determinations.get("severity") or entry.get("severity") or "").lower(),
                Severity.MEDIUM,
            )
            confidence = str(determinations.get("confidence") or "").lower() or None
            findings.append(
                Finding(
                    asset_id=ctx.asset.id,
                    agent="pipeline",
                    tool=self.name,
                    category=PIPELINE,
                    rule_id=rule,
                    title=rule,
                    message=clean_text(entry.get("desc") or entry.get("description")),
                    severity=severity,
                    location=_location(ctx.root, entry),
                    references=http_links([entry.get("url")]),
                    confidence=confidence,
                )
            )
        return findings
