"""Dockle, opt-in, and only against a local image archive.

HTW never asks Dockle to pull from a registry. A named `dockle` run with no
`*.tar` archive in the asset fails the tool instead of reaching out.
"""

from __future__ import annotations

import os
from pathlib import Path

from htw.core.finding import CONTAINER, Finding, Location, Severity
from htw.core.paths import is_excluded
from htw.core.redact import clean_text
from htw.detect.model import CONTAINER as CONTAINER_CATEGORY
from htw.detect.model import StackProfile
from htw.detect.signatures import PRUNED_DIRECTORIES
from htw.errors import ToolError
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_list, parse_json

MAX_ARCHIVES = 5


def _archives(root: Path, exclude: tuple[str, ...]) -> list[str]:
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [
            name
            for name in sorted(dirnames)
            if name not in PRUNED_DIRECTORIES
            and not is_excluded(f"{rel_dir}/{name}" if rel_dir else name, exclude)
        ]
        for name in filenames:
            if not name.endswith(".tar"):
                continue
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if is_excluded(rel, exclude):
                continue
            found.append(rel)
            if len(found) >= MAX_ARCHIVES:
                return found
    return found


class Dockle(ToolAdapter):
    name = "dockle"
    binary = "dockle"
    homepage = "https://github.com/goodwithtech/dockle"
    install_hint = (
        "`brew install goodwithtech/r/dockle`, or download a release from "
        "https://github.com/goodwithtech/dockle/releases"
    )
    network = "none; HTW only passes a local image archive and never a registry reference"
    optional = True

    def coverage(self, profile: StackProfile) -> set[str]:
        return {"image-archive"} if profile.has(CONTAINER_CATEGORY) else set()

    def scan(self, ctx: ScanContext) -> list[Finding]:
        archives = _archives(ctx.root, ctx.asset.exclude)
        if not archives:
            raise ToolError(
                "dockle scans a local image archive (*.tar) only. "
                "HTW does not pull images and does not scan a registry."
            )
        findings = []
        for archive in archives:
            argv = ["dockle", "--input", archive, "--format", "json", "--exit-code", "0"]
            result = self.invoke(ctx, argv)
            if not result.stdout.strip():
                raise self._fail(result)
            report = as_dict(parse_json(self.name, result.stdout))
            for raw in as_list(report.get("details")):
                entry = as_dict(raw)
                rule = str(entry.get("code") or "")
                if not rule:
                    continue
                findings.append(
                    Finding(
                        asset_id=ctx.asset.id,
                        agent="container",
                        tool=self.name,
                        category=CONTAINER,
                        rule_id=rule,
                        title=rule,
                        message=clean_text(entry.get("title") or entry.get("details")),
                        severity=Severity.parse(entry.get("level")),
                        location=Location(path=archive),
                    )
                )
        return findings
