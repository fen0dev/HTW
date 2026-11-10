"""Gitleaks: secrets in the working tree and in git history."""

from __future__ import annotations

import tempfile
from pathlib import Path

from htw.core.finding import SECRET, Finding, Location, Severity
from htw.core.redact import REDACTED, clean_text
from htw.detect.model import StackProfile
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_int, as_list, read_json_file

# What gitleaks writes in place of a secret when run with --redact.
GITLEAKS_REDACTED = "REDACTED"


class Gitleaks(ToolAdapter):
    name = "gitleaks"
    binary = "gitleaks"
    homepage = "https://github.com/gitleaks/gitleaks"
    install_hint = (
        "`brew install gitleaks`, or download a release from "
        "https://github.com/gitleaks/gitleaks/releases"
    )
    network = "none"
    version_args = ("version",)

    def coverage(self, profile: StackProfile) -> set[str]:
        return {"secrets"}

    @staticmethod
    def command(version: str | None, root: Path, history: bool, report: Path) -> list[str]:
        """Build the command line. `git`/`dir` replaced `detect` in gitleaks 8.19."""
        parts = [int(p) for p in (version or "").split(".")[:2] if p.isdigit()]
        modern = len(parts) < 2 or tuple(parts) >= (8, 19)
        if modern:
            argv = ["gitleaks", "git" if history else "dir", str(root)]
        else:
            argv = ["gitleaks", "detect", "--source", str(root)]
            if not history:
                argv.append("--no-git")
        return [
            *argv,
            "--report-format", "json",
            "--report-path", str(report),
            "--redact",
            "--no-banner",
            "--exit-code", "0",
        ]  # fmt: skip

    def scan(self, ctx: ScanContext) -> list[Finding]:
        history = bool(ctx.settings.options.get("history", True)) and (ctx.root / ".git").exists()
        version = self.version(ctx.runner, ctx.root)
        with tempfile.TemporaryDirectory(prefix="htw-gitleaks-") as scratch:
            report = Path(scratch) / "report.json"
            result = self.invoke(
                ctx, self.command(version, ctx.root, history, report), writable=(Path(scratch),)
            )
            if result.returncode != 0 or not report.exists():
                raise self._fail(result)
            entries = as_list(read_json_file(self.name, report))

        findings = []
        for raw in entries:
            entry = as_dict(raw)
            path = ctx.relative(str(entry.get("File") or ""))
            rule = str(entry.get("RuleID") or "unknown")
            if path is None:
                continue
            # --redact already masks the value. Mask again in case an old version did not.
            match = str(entry.get("Match") or "")
            secret = str(entry.get("Secret") or "")
            if secret and secret != GITLEAKS_REDACTED:
                match = match.replace(secret, REDACTED)
            commit = str(entry.get("Commit") or "") or None
            findings.append(
                Finding(
                    asset_id=ctx.asset.id,
                    agent="secrets",
                    tool=self.name,
                    category=SECRET,
                    rule_id=rule,
                    title=f"Secret detected ({rule})",
                    message=clean_text(entry.get("Description"))
                    or "A credential-like value is committed to the repository.",
                    severity=Severity.HIGH,
                    location=Location(
                        path=path,
                        start_line=as_int(entry.get("StartLine")),
                        end_line=as_int(entry.get("EndLine")),
                        commit=commit,
                    ),
                    identifiers=("CWE-798",),
                    context=f"{rule}\n{match}" if match else None,
                )
            )
        return findings
