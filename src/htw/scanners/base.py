"""The tool adapter interface.

A `ToolAdapter` wraps one external scanner binary: it knows how to invoke the tool and
how to turn its native output into normalized findings. Adapters get a `ScanContext`
and nothing else.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from htw.core.config import AgentSettings, Asset
from htw.core.finding import Finding
from htw.core.levels import ControlLevel
from htw.core.paths import to_relative
from htw.core.runner import CommandResult, ToolRunner
from htw.detect.model import StackProfile
from htw.errors import ToolError

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?(?:[-+.\w]*)?")

STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_MISSING = "missing"


@dataclass
class ScanContext:
    """Everything an adapter may use. Adapters get no other access."""

    asset: Asset
    root: Path
    profile: StackProfile
    runner: ToolRunner
    settings: AgentSettings
    config_dir: Path
    artifacts_dir: Path
    # Files produced by earlier tools in the same run, e.g. the SBOM.
    artifacts: dict[str, Path] = field(default_factory=dict)

    def relative(self, path: str | None) -> str | None:
        return to_relative(path, self.root) if path else None


@dataclass
class ToolOutcome:
    agent: str
    tool: str
    status: str
    version: str | None = None
    message: str = ""
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    command: tuple[str, ...] = ()
    install_hint: str = ""


class ToolAdapter(ABC):
    """Wrapper around one external scanner binary."""

    name: ClassVar[str]
    binary: ClassVar[str]
    homepage: ClassVar[str]
    install_hint: ClassVar[str]
    # What the tool sends or fetches over the network, shown by `htw doctor`.
    network: ClassVar[str] = "none"
    level: ClassVar[ControlLevel] = ControlLevel.L0
    version_args: ClassVar[tuple[str, ...]] = ("--version",)
    # Opt-in tools are listed by `htw doctor` but are not selected unless the scope
    # file names them. They stay out of the coverage gaps, so a default scan does not
    # fail `--strict` for a check the operator did not ask for.
    optional: ClassVar[bool] = False

    @abstractmethod
    def coverage(self, profile: StackProfile) -> set[str]:
        """Coverage keys this tool can provide for the detected stack."""

    @abstractmethod
    def scan(self, ctx: ScanContext) -> list[Finding]:
        """Run the tool and return findings. Raise ToolError if the result is unusable."""

    def available(self, runner: ToolRunner) -> bool:
        return runner.which(self.binary) is not None

    @property
    def isolates_network(self) -> bool:
        """True when this tool's declared network use is none, so the sandbox drops the network."""
        text = self.network.strip().lower()
        return text == "none" or text.startswith("none;") or text.startswith("none ")

    def invoke(
        self,
        ctx: ScanContext,
        argv: Sequence[str],
        *,
        cwd: Path | None = None,
        extra_env: Mapping[str, str] | None = None,
        writable: Sequence[Path] = (),
        timeout_seconds: int | None = None,
    ) -> CommandResult:
        """Run the scanner on the asset. The asset stays read-only; the home directory is not mounted."""
        work = cwd or ctx.root
        reports = (ctx.artifacts_dir, *writable)
        return ctx.runner.run(
            argv,
            cwd=work,
            extra_env=extra_env,
            timeout_seconds=timeout_seconds,
            offline=self.isolates_network,
            writable=reports,
            read_root=ctx.root,
            sandbox=True,
        )

    def version(self, runner: ToolRunner, cwd: Path) -> str | None:
        try:
            # Version probes must not mount the current directory: `htw doctor` may be
            # started from the operator's home.
            result = runner.run(
                [self.binary, *self.version_args], cwd=cwd, timeout_seconds=60, sandbox=False
            )
        except ToolError:
            return None
        match = _VERSION_RE.search(result.stdout + "\n" + result.stderr)
        return match.group(0) if match else None

    def missing_message(self) -> str:
        return (
            f"{self.name} is not installed (no `{self.binary}` on PATH). "
            f"Install: {self.install_hint}"
        )

    def _fail(self, result: CommandResult, what: str = "failed") -> ToolError:
        detail = result.stderr_tail or result.stdout[-500:].strip() or "no output"
        return ToolError(f"{self.name} {what} (exit {result.returncode}): {detail}")
