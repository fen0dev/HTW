"""The normalized finding record that every scanner output is reduced to."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

DEPENDENCY = "dependency"
SECRET = "secret"  # noqa: S105 - a finding category, not a credential
SAST = "sast"
CONTAINER = "container"
IAC = "iac"
PIPELINE = "pipeline"
DAST = "dast"
CATEGORIES = (DEPENDENCY, SECRET, SAST, CONTAINER, IAC, PIPELINE, DAST)


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RANKS[self]

    @classmethod
    def parse(cls, value: object, default: Severity | None = None) -> Severity:
        text = str(value or "").strip().lower()
        if text in _ALIASES:
            return _ALIASES[text]
        return default or cls.MEDIUM

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.INFO


_RANKS = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
_ALIASES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "low": Severity.LOW,
    "negligible": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "note": Severity.INFO,
    "none": Severity.INFO,
}


@dataclass
class Location:
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    commit: str | None = None

    def display(self) -> str:
        if not self.path:
            return "(no file)"
        text = self.path
        if self.start_line:
            text += f":{self.start_line}"
        if self.commit:
            text += f" @ {self.commit[:12]}"
        return text


@dataclass
class Package:
    ecosystem: str
    name: str
    version: str
    fixed_versions: tuple[str, ...] = ()
    purl: str | None = None


@dataclass
class LineFix:
    """Scanner-supplied replacement of the matched source. HTW never applies it."""

    original: str
    replacement: str


@dataclass
class Finding:
    asset_id: str
    agent: str
    tool: str
    category: str
    rule_id: str
    title: str
    message: str
    severity: Severity
    location: Location = field(default_factory=Location)
    package: Package | None = None
    identifiers: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    cvss_score: float | None = None
    confidence: str | None = None
    # Text the fingerprint is derived from when it cannot be read from the file, for
    # example a secret match that the scanner already redacted. Never persisted.
    context: str | None = None
    # Present only when the scanner named both the matched text and its replacement.
    line_fix: LineFix | None = None
    fingerprint: str = ""
    priority: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("context")
        data["severity"] = self.severity.value
        if self.package is None:
            data.pop("package")
        if self.line_fix is None:
            data.pop("line_fix")
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        data = dict(data)
        package = data.pop("package", None)
        location = data.pop("location", None) or {}
        line_fix = data.pop("line_fix", None)
        data.pop("context", None)
        if package:
            package["fixed_versions"] = tuple(package.get("fixed_versions") or ())
        return cls(
            **{
                **data,
                "severity": Severity(data["severity"]),
                "identifiers": tuple(data.get("identifiers") or ()),
                "references": tuple(data.get("references") or ()),
                "location": Location(**location),
                "package": Package(**package) if package else None,
                "line_fix": LineFix(**line_fix) if line_fix else None,
            }
        )


_CONTROL_CHARACTERS = dict.fromkeys((*range(32), 127), " ")


def _plain(value: str | None) -> str | None:
    return value.translate(_CONTROL_CHARACTERS) if value else value


def sanitize_finding(finding: Finding) -> Finding:
    """Strip control characters from every scanner-supplied string.

    Package names, file names and messages come from the scanned content. Removing
    escape sequences keeps them from rewriting a terminal or a log viewer.
    """
    finding.rule_id = _plain(finding.rule_id) or "unknown"
    finding.title = _plain(finding.title) or finding.rule_id
    finding.message = _plain(finding.message) or ""
    finding.location.path = _plain(finding.location.path)
    finding.location.commit = _plain(finding.location.commit)
    finding.confidence = _plain(finding.confidence)
    finding.identifiers = tuple(_plain(i) or "" for i in finding.identifiers)
    finding.references = tuple(_plain(r) or "" for r in finding.references)
    if finding.package is not None:
        package = finding.package
        package.ecosystem = _plain(package.ecosystem) or "unknown"
        package.name = _plain(package.name) or "unknown"
        package.version = _plain(package.version) or ""
        package.fixed_versions = tuple(_plain(v) or "" for v in package.fixed_versions)
        package.purl = _plain(package.purl)
    if finding.line_fix is not None:
        finding.line_fix.original = _plain(finding.line_fix.original) or ""
        finding.line_fix.replacement = _plain(finding.line_fix.replacement) or ""
    return finding
