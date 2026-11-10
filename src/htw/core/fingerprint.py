"""Stable finding fingerprints.

A fingerprint identifies "the same problem" across scans, so that a recurring scan can
report only what changed. It is derived from the rule, the asset and a normalized
location. Line numbers are deliberately left out: code moving up or down a file must
not turn an old finding into a new one.

- Code and secret findings: tool, rule, file path and a hash of the flagged lines with
  whitespace normalized, plus an occurrence index when the same rule flags identical
  code more than once in a file.
- Dependency findings: advisory id, ecosystem, package name and manifest path. The
  installed version is left out, so an upgrade to a version that is still vulnerable
  remains the same finding.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

from htw.core.finding import DEPENDENCY, SECRET, Finding
from htw.core.paths import safe_read_lines

FINGERPRINT_VERSION = 1
FINGERPRINT_PREFIX = f"htw{FINGERPRINT_VERSION}:"

_WHITESPACE_RE = re.compile(r"\s+")
_PYPI_SEPARATORS_RE = re.compile(r"[-_.]+")


def normalize_context(lines: list[str] | str) -> str:
    """Collapse whitespace so that reformatting does not change a fingerprint."""
    if isinstance(lines, str):
        lines = lines.splitlines()
    cleaned = (_WHITESPACE_RE.sub(" ", line).strip() for line in lines)
    return "\n".join(line for line in cleaned if line)


def normalize_package_name(ecosystem: str, name: str) -> str:
    if ecosystem.lower() == "pypi":
        return _PYPI_SEPARATORS_RE.sub("-", name).lower()
    return name


def _digest(parts: list[object]) -> str:
    payload = json.dumps(parts, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _base_key(finding: Finding, root: Path | None) -> list[object]:
    if finding.category == DEPENDENCY and finding.package is not None:
        package = finding.package
        return [
            FINGERPRINT_VERSION,
            finding.asset_id,
            DEPENDENCY,
            finding.rule_id.upper(),
            package.ecosystem.lower(),
            normalize_package_name(package.ecosystem, package.name),
            finding.location.path or "",
        ]

    location = finding.location
    context = finding.context
    # Never hash a line that holds a secret: even a digest of it would be derived data
    # about the credential. Secret findings use the scanner's redacted match instead.
    readable = finding.category != SECRET and root is not None
    if context is None and readable and location.path and location.start_line:
        assert root is not None
        end = location.end_line or location.start_line
        context = "\n".join(safe_read_lines(root, location.path, location.start_line, end))
    normalized = normalize_context(context or "")
    if normalized:
        anchor = "ctx:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]
    else:
        # Nothing to hash (binary file, file gone): fall back to the line number.
        anchor = f"line:{location.start_line or 0}"
    return [
        FINGERPRINT_VERSION,
        finding.asset_id,
        finding.category,
        finding.tool,
        finding.rule_id,
        location.path or "",
        anchor,
    ]


def assign_fingerprints(findings: list[Finding], root: Path | None = None) -> None:
    """Set `fingerprint` on every finding. Deterministic for a given set of findings."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    keys: dict[str, list[object]] = {}
    for finding in findings:
        key = _base_key(finding, root)
        digest = _digest(key)
        keys[digest] = key
        groups[digest].append(finding)
    for digest, members in groups.items():
        members.sort(
            key=lambda f: (
                f.location.start_line or 0,
                f.package.version if f.package else "",
                f.location.commit or "",
            )
        )
        for index, finding in enumerate(members):
            finding.fingerprint = FINGERPRINT_PREFIX + _digest([*keys[digest], index])[:32]
