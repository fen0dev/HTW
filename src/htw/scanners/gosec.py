"""gosec: static analysis for Go."""

from __future__ import annotations

import os
from pathlib import Path

from htw.core.finding import SAST, Finding, Location, Severity
from htw.core.paths import is_excluded
from htw.core.redact import clean_text
from htw.core.runner import ToolRunner
from htw.detect.model import StackProfile
from htw.detect.signatures import PRUNED_DIRECTORIES
from htw.errors import ToolError
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_int, as_list, cwe_ids, parse_json

MAX_MODULES = 50


class Gosec(ToolAdapter):
    name = "gosec"
    binary = "gosec"
    homepage = "https://github.com/securego/gosec"
    install_hint = (
        "`go install github.com/securego/gosec/v2/cmd/gosec@latest` (needs the Go toolchain, "
        "which gosec also uses at scan time)"
    )
    network = "the Go toolchain may download modules the code depends on"

    def coverage(self, profile: StackProfile) -> set[str]:
        return {"sast:Go"} if "Go" in profile.languages else set()

    def available(self, runner: ToolRunner) -> bool:
        return runner.which("gosec") is not None and runner.which("go") is not None

    def missing_message(self) -> str:
        return (
            "gosec needs both `gosec` and the Go toolchain (`go`) on PATH. "
            f"Install: {self.install_hint}"
        )

    @staticmethod
    def module_dirs(root: Path, exclude: tuple[str, ...]) -> list[Path]:
        """Directories holding a go.mod. gosec has to run once per module."""
        modules = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            rel = Path(dirpath).relative_to(root).as_posix()
            dirnames[:] = sorted(
                name
                for name in dirnames
                if name not in PRUNED_DIRECTORIES
                and name != "vendor"
                and not is_excluded(f"{rel}/{name}" if rel != "." else name, exclude)
            )
            if "go.mod" in filenames:
                modules.append(Path(dirpath))
                if len(modules) >= MAX_MODULES:
                    break
        return modules

    def scan(self, ctx: ScanContext) -> list[Finding]:
        modules = self.module_dirs(ctx.root, ctx.asset.exclude)
        if not modules:
            raise ToolError(
                "gosec: Go files found but no go.mod; gosec needs a Go module to analyse"
            )
        findings: list[Finding] = []
        load_errors: list[str] = []
        files = 0
        for module in modules:
            result = ctx.runner.run(
                ["gosec", "-fmt", "json", "-quiet", "-no-fail", "./..."], cwd=module
            )
            if not result.stdout.strip():
                load_errors.append(result.stderr_tail or f"no output for {module.name}")
                continue
            report = as_dict(parse_json(self.name, result.stdout))
            files += as_int(as_dict(report.get("Stats")).get("files")) or 0
            load_errors += [str(key) for key in as_dict(report.get("Golang errors"))]
            for raw in as_list(report.get("Issues")):
                entry = as_dict(raw)
                path = ctx.relative(str(entry.get("file") or ""))
                if path is None:
                    continue
                first, _, last = str(entry.get("line") or "").partition("-")
                start = as_int(first)
                findings.append(
                    Finding(
                        asset_id=ctx.asset.id,
                        agent="sast",
                        tool=self.name,
                        category=SAST,
                        rule_id=str(entry.get("rule_id") or "unknown"),
                        title=str(entry.get("rule_id") or "gosec finding"),
                        message=clean_text(entry.get("details")),
                        severity=Severity.parse(entry.get("severity")),
                        location=Location(
                            path=path, start_line=start, end_line=as_int(last) or start
                        ),
                        identifiers=cwe_ids(entry.get("cwe")),
                        confidence=str(entry.get("confidence") or "").lower() or None,
                    )
                )
        if not files and load_errors:
            raise ToolError(
                "gosec could not load any Go package: "
                + clean_text("; ".join(load_errors[:3]), 300)
            )
        return findings
