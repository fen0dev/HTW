"""Semgrep: multi-language static analysis."""

from __future__ import annotations

from typing import Any

from htw.core.finding import SAST, Finding, LineFix, Location, Severity
from htw.core.redact import clean_text, redact_text
from htw.detect.model import StackProfile
from htw.errors import ConfigError, ToolError
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_int, as_list, cwe_ids, http_links, parse_json

DEFAULT_RULES = ("p/default",)

# Languages with Semgrep rules in the public registry.
SUPPORTED_LANGUAGES = frozenset(
    {
        "Python", "JavaScript", "TypeScript", "Go", "Java", "Kotlin", "Scala", "Ruby", "PHP",
        "C#", "C", "C++", "Rust", "Swift", "Elixir", "Shell", "Solidity", "Dart", "Lua",
    }
)  # fmt: skip

_MAX_FIX_CHARS = 4_000
_MAX_FIX_LINES = 40


def line_fix_from_semgrep(extra: dict[str, Any]) -> LineFix | None:
    """The autofix, kept only when it is a small replacement of the matched text.

    A fix that redaction would change is dropped: the proposal must not carry a secret,
    and a redacted fix would not apply.
    """
    original = extra.get("lines")
    replacement = extra.get("fix")
    if not isinstance(original, str) or not isinstance(replacement, str):
        return None
    if not original.strip() or original == replacement:
        return None
    if len(original) > _MAX_FIX_CHARS or len(replacement) > _MAX_FIX_CHARS:
        return None
    if original.count("\n") > _MAX_FIX_LINES or replacement.count("\n") > _MAX_FIX_LINES:
        return None
    if redact_text(original) != original or redact_text(replacement) != replacement:
        return None
    return LineFix(original, replacement)


_SEVERITIES = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "LOW": Severity.LOW,
}


class Semgrep(ToolAdapter):
    name = "semgrep"
    binary = "semgrep"
    homepage = "https://github.com/semgrep/semgrep"
    install_hint = "`pipx install semgrep` or `brew install semgrep`"
    network = (
        "downloads rulesets from semgrep.dev unless `semgrep_rules` points to local files; "
        "metrics and version checks are disabled; no code is uploaded"
    )

    def coverage(self, profile: StackProfile) -> set[str]:
        return {f"sast:{language}" for language in profile.languages & SUPPORTED_LANGUAGES}

    @staticmethod
    def rule_arguments(ctx: ScanContext) -> list[str]:
        arguments = []
        for rule in ctx.settings.options.get("semgrep_rules") or DEFAULT_RULES:
            if rule.startswith(("p/", "r/")):
                arguments += ["--config", rule]
                continue
            path = (ctx.config_dir / rule).resolve()
            if not path.exists():
                raise ConfigError(
                    f"scanners.sast.semgrep_rules: {rule!r} is neither a registry ruleset "
                    f"(p/... or r/...) nor an existing path ({path})"
                )
            arguments += ["--config", str(path)]
        return arguments

    def scan(self, ctx: ScanContext) -> list[Finding]:
        argv = [
            "semgrep", "scan",
            *self.rule_arguments(ctx),
            "--json", "--quiet", "--metrics=off", "--disable-version-check",
        ]  # fmt: skip
        for pattern in ctx.asset.exclude:
            argv += ["--exclude", pattern]
        argv.append(".")
        result = self.invoke(ctx, argv, extra_env={"SEMGREP_SEND_METRICS": "off"})
        if not result.stdout.strip():
            raise self._fail(result)
        report = as_dict(parse_json(self.name, result.stdout))
        if not isinstance(report.get("results"), list):
            raise self._fail(result, "returned no results section")
        if result.returncode not in (0, 1) and not report["results"]:
            errors = as_list(report.get("errors"))
            detail = clean_text(as_dict(errors[0]).get("message")) if errors else result.stderr_tail
            raise ToolError(f"semgrep failed (exit {result.returncode}): {detail or 'no detail'}")

        findings = []
        for raw in report["results"]:
            entry = as_dict(raw)
            extra = as_dict(entry.get("extra"))
            metadata = as_dict(extra.get("metadata"))
            path = ctx.relative(str(entry.get("path") or ""))
            rule = str(entry.get("check_id") or "unknown")
            if path is None:
                continue
            start = as_int(as_dict(entry.get("start")).get("line"))
            findings.append(
                Finding(
                    asset_id=ctx.asset.id,
                    agent="sast",
                    tool=self.name,
                    category=SAST,
                    rule_id=rule,
                    title=rule.rsplit(".", 1)[-1],
                    message=clean_text(extra.get("message")),
                    severity=_SEVERITIES.get(str(extra.get("severity")).upper(), Severity.MEDIUM),
                    location=Location(
                        path=path,
                        start_line=start,
                        end_line=as_int(as_dict(entry.get("end")).get("line")) or start,
                    ),
                    identifiers=cwe_ids(metadata.get("cwe")),
                    references=http_links(
                        [metadata.get("source"), *as_list(metadata.get("references"))]
                    ),
                    confidence=str(metadata.get("confidence") or "").lower() or None,
                    line_fix=line_fix_from_semgrep(extra),
                )
            )
        return findings
