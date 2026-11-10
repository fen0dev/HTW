"""Nuclei, opt-in. Same approval gate as ZAP: one staging URL and no other host."""

from __future__ import annotations

from typing import Any

from htw.core.finding import DAST, Finding, Severity
from htw.core.levels import ControlLevel
from htw.core.redact import clean_text
from htw.detect.model import StackProfile
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, http_links, parse_json
from htw.scanners.runtime_url import approved_staging_url


def _references(value: object) -> list[Any]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


class Nuclei(ToolAdapter):
    name = "nuclei"
    binary = "nuclei"
    homepage = "https://github.com/projectdiscovery/nuclei"
    install_hint = (
        "`brew install nuclei`, or download a release from "
        "https://github.com/projectdiscovery/nuclei/releases"
    )
    network = "contacts only the staging URL named in the current DAST approval"
    level = ControlLevel.L2
    optional = True
    version_args = ("-version",)

    def coverage(self, profile: StackProfile) -> set[str]:
        del profile
        return {"dast:baseline"}

    def scan(self, ctx: ScanContext) -> list[Finding]:
        url = approved_staging_url(ctx)
        argv = ["nuclei", "-u", url, "-jsonl", "-silent", "-disable-update-check"]
        result = self.invoke(ctx, argv)
        if result.returncode not in (0, 1) and not result.stdout.strip():
            raise self._fail(result)
        findings = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            entry = as_dict(parse_json(self.name, line))
            info = as_dict(entry.get("info"))
            rule = str(entry.get("template-id") or entry.get("templateID") or "")
            if not rule:
                continue
            matched = str(entry.get("matched-at") or entry.get("host") or "")
            if matched and not matched.startswith(url):
                # A template that followed a link off the approved origin is dropped.
                continue
            findings.append(
                Finding(
                    asset_id=ctx.asset.id,
                    agent="dast",
                    tool=self.name,
                    category=DAST,
                    rule_id=rule,
                    title=clean_text(info.get("name")) or rule,
                    message=clean_text(info.get("description")),
                    severity=Severity.parse(info.get("severity")),
                    references=http_links(_references(info.get("reference"))),
                )
            )
        return findings
