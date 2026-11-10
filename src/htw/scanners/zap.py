"""OWASP ZAP baseline: one approved staging URL, no other host.

Baseline mode is the passive scan. It still opens a connection, so it stays behind
the DAST approval and refuses any target that is not the approved URL.
"""

from __future__ import annotations

from htw.core.finding import DAST, Finding, Severity
from htw.core.levels import ControlLevel
from htw.core.redact import clean_text
from htw.detect.model import StackProfile
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_list, http_links, parse_json
from htw.scanners.runtime_url import approved_staging_url

_RISK = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}


class Zap(ToolAdapter):
    name = "zap"
    binary = "zap-baseline.py"
    homepage = "https://www.zaproxy.org/"
    install_hint = "install the OWASP ZAP packaged baseline script `zap-baseline.py`"
    network = "contacts only the staging URL named in the current DAST approval"
    level = ControlLevel.L2

    def coverage(self, profile: StackProfile) -> set[str]:
        del profile
        return {"dast:baseline"}

    def scan(self, ctx: ScanContext) -> list[Finding]:
        url = approved_staging_url(ctx)
        report = ctx.artifacts_dir / "zap-baseline.json"
        argv = ["zap-baseline.py", "-t", url, "-J", str(report), "-I"]
        result = ctx.runner.run(argv, cwd=ctx.root)
        if not report.is_file():
            if result.returncode not in (0, 1, 2) or not result.stdout.strip():
                raise self._fail(result)
            payload = parse_json(self.name, result.stdout)
        else:
            payload = parse_json(self.name, report.read_text(encoding="utf-8", errors="replace"))
        findings = []
        sites = as_list(as_dict(payload).get("site"))
        for site in sites:
            for raw in as_list(as_dict(site).get("alerts")):
                entry = as_dict(raw)
                rule = str(entry.get("pluginid") or entry.get("alertRef") or "")
                name = clean_text(entry.get("name") or entry.get("alert"))
                if not rule and not name:
                    continue
                findings.append(
                    Finding(
                        asset_id=ctx.asset.id,
                        agent="dast",
                        tool=self.name,
                        category=DAST,
                        rule_id=rule or name,
                        title=name or rule,
                        message=clean_text(entry.get("desc") or entry.get("description")),
                        severity=_RISK.get(str(entry.get("riskcode")), Severity.MEDIUM),
                        references=http_links([entry.get("reference")]),
                    )
                )
        return findings
