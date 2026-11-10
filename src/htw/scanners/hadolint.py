"""Hadolint: static lint of Dockerfiles. No image is built or pulled."""

from __future__ import annotations

import os
import re
from pathlib import Path

from htw.core.finding import CONTAINER, Finding, Location, Severity
from htw.core.paths import is_excluded
from htw.core.redact import clean_text
from htw.detect.model import CONTAINER as CONTAINER_CATEGORY
from htw.detect.model import StackProfile
from htw.detect.signatures import PRUNED_DIRECTORIES
from htw.scanners.base import ScanContext, ToolAdapter
from htw.scanners.common import as_dict, as_int, as_list, parse_json, repo_path

_DOCKERFILE_RE = re.compile(r"(^|/)(dockerfile|containerfile)(\.[\w.-]+)?$", re.IGNORECASE)
_LEVELS = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "style": Severity.INFO,
}
MAX_DOCKERFILES = 200


def dockerfile_paths(root: Path, exclude: tuple[str, ...]) -> list[str]:
    """Dockerfile paths relative to `root`. Symlinks are not followed."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        kept = []
        for name in sorted(dirnames):
            if name in PRUNED_DIRECTORIES:
                continue
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if not is_excluded(rel, exclude):
                kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if is_excluded(rel, exclude) or not _DOCKERFILE_RE.search(rel):
                continue
            found.append(rel)
            if len(found) >= MAX_DOCKERFILES:
                return found
    return found


class Hadolint(ToolAdapter):
    name = "hadolint"
    binary = "hadolint"
    homepage = "https://github.com/hadolint/hadolint"
    install_hint = (
        "`brew install hadolint`, or download a release from "
        "https://github.com/hadolint/hadolint/releases"
    )
    network = "none"

    def coverage(self, profile: StackProfile) -> set[str]:
        return {"dockerfile-lint"} if profile.has(CONTAINER_CATEGORY, "Dockerfile") else set()

    def scan(self, ctx: ScanContext) -> list[Finding]:
        files = dockerfile_paths(ctx.root, ctx.asset.exclude)
        if not files:
            return []
        argv = ["hadolint", "--format", "json", "--no-color", *files]
        result = self.invoke(ctx, argv)
        # Hadolint exits 1 when it finds issues. Empty stdout is a real failure.
        if not result.stdout.strip():
            if result.returncode == 0:
                return []
            raise self._fail(result)
        findings = []
        for raw in as_list(parse_json(self.name, result.stdout)):
            entry = as_dict(raw)
            path = repo_path(ctx.root, entry.get("file"))
            rule = str(entry.get("code") or "")
            if path is None or not rule:
                continue
            line = as_int(entry.get("line"))
            findings.append(
                Finding(
                    asset_id=ctx.asset.id,
                    agent="container",
                    tool=self.name,
                    category=CONTAINER,
                    rule_id=rule,
                    title=rule,
                    message=clean_text(entry.get("message")),
                    severity=_LEVELS.get(str(entry.get("level") or "").lower(), Severity.MEDIUM),
                    location=Location(path=path, start_line=line, end_line=line),
                    references=("https://github.com/hadolint/hadolint",),
                )
            )
        return findings
