"""Path helpers shared by detection and finding normalization."""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from pathlib import Path, PurePosixPath


def is_excluded(rel_path: str, patterns: Iterable[str]) -> bool:
    """Match a POSIX relative path against the asset's `exclude` patterns.

    A pattern excludes a path when it matches it as a glob, names one of its parent
    directories (`vendor`, `vendor/`, `vendor/**`), or, having no slash, matches its
    file name (`*.min.js`).
    """
    rel_path = rel_path.strip("/")
    name = PurePosixPath(rel_path).name
    for raw in patterns:
        pattern = raw.strip().strip("/")
        if pattern.endswith("/**"):
            pattern = pattern[: -len("/**")]
        if not pattern:
            continue
        if rel_path == pattern or rel_path.startswith(pattern + "/"):
            return True
        if fnmatch.fnmatchcase(rel_path, pattern):
            return True
        if "/" not in pattern and fnmatch.fnmatchcase(name, pattern):
            return True
    return False


def to_relative(path: str, root: Path) -> str | None:
    """Return `path` as a POSIX path relative to `root`, or None if it escapes the root.

    Scanners report a mix of absolute and relative paths. Anything that does not
    resolve inside the asset root is rejected rather than reported.
    """
    if not path:
        return None
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        normalized = Path(*candidate.parts)
        relative = normalized.relative_to(root)
    except ValueError:
        try:
            relative = candidate.resolve().relative_to(root.resolve())
        except (ValueError, OSError):
            return None
    if ".." in relative.parts:
        return None
    text = relative.as_posix()
    return None if text in ("", ".") else text


def safe_read_lines(
    root: Path, rel_path: str, start: int, end: int, limit: int = 2_000_000
) -> list[str]:
    """Read lines [start, end] (1-based) of a file inside `root`; empty on any problem.

    Symlinks are refused and the resolved path must stay inside the root, so a
    crafted repository cannot make HTW read files outside the allowlisted asset.
    """
    if start < 1 or end < start:
        return []
    target = root / rel_path
    try:
        if target.is_symlink() or not target.is_file():
            return []
        if not target.resolve().is_relative_to(root.resolve()):
            return []
        if target.stat().st_size > limit:
            return []
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    return lines[start - 1 : min(end, start + 50)]
