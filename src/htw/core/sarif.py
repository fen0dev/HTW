"""SARIF 2.1.0 output.

Scanner wrappers parse each tool's native JSON, because that is where package names,
installed versions and fixed versions are still structured. This module turns the
normalized findings into one SARIF log with one run per underlying tool, HTW's stable
fingerprint in `partialFingerprints`, and the comparison with the previous scan in
`baselineState`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from htw import __version__
from htw.core.finding import Finding, Severity
from htw.core.suppressions import Suppression

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
FINGERPRINT_KEY = "htw/v1"
PROJECT_URI = "https://github.com/fen0dev/HTW"

_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 2.5,
    Severity.INFO: 0.0,
}
_BASELINE = {
    "new": "new",
    "reappeared": "new",
    "unchanged": "unchanged",
    "unverified": "unchanged",
    "resolved": "absent",
}


@dataclass(frozen=True)
class SarifEntry:
    finding: Finding
    state: str
    first_seen: str | None = None
    suppression: Suppression | None = None


@dataclass(frozen=True)
class SarifTool:
    name: str
    version: str | None = None
    uri: str | None = None


def _rule(finding: Finding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": finding.rule_id,
        "shortDescription": {"text": finding.title or finding.rule_id},
        "properties": {
            "tags": ["security", finding.category, *finding.identifiers],
            "security-severity": f"{finding.cvss_score or _SECURITY_SEVERITY[finding.severity]:.1f}",
        },
    }
    if finding.references:
        rule["helpUri"] = finding.references[0]
    return rule


def _result(entry: SarifEntry, rule_index: int) -> dict[str, Any]:
    finding = entry.finding
    properties: dict[str, Any] = {
        "htw/state": entry.state,
        "htw/priority": finding.priority,
        "htw/severity": finding.severity.value,
        "htw/category": finding.category,
        "htw/agent": finding.agent,
    }
    if entry.first_seen:
        properties["htw/firstSeen"] = entry.first_seen
    if finding.identifiers:
        properties["htw/identifiers"] = list(finding.identifiers)
    if finding.package is not None:
        properties["htw/package"] = {
            "ecosystem": finding.package.ecosystem,
            "name": finding.package.name,
            "version": finding.package.version,
            "fixedVersions": list(finding.package.fixed_versions),
        }
    if finding.location.commit:
        properties["htw/commit"] = finding.location.commit

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _LEVELS[finding.severity],
        "message": {"text": finding.message or finding.title or finding.rule_id},
        "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint},
        "baselineState": _BASELINE.get(entry.state, "unchanged"),
        "properties": properties,
    }
    if finding.location.path:
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": quote(finding.location.path), "uriBaseId": "%SRCROOT%"}
        }
        if finding.location.start_line:
            region = {"startLine": finding.location.start_line}
            if (
                finding.location.end_line
                and finding.location.end_line >= finding.location.start_line
            ):
                region["endLine"] = finding.location.end_line
            physical["region"] = region
        result["locations"] = [{"physicalLocation": physical}]
    if entry.suppression is not None:
        result["suppressions"] = [
            {
                "kind": "external",
                "justification": f"{entry.suppression.kind}: {entry.suppression.reason} "
                f"({entry.suppression.author}, expires {entry.suppression.expires.isoformat()})",
            }
        ]
    return result


def build_sarif(
    asset_id: str,
    run_id: str,
    entries: list[SarifEntry],
    tools: Mapping[str, SarifTool],
) -> dict[str, Any]:
    """Build a SARIF log with one run per tool that ran or has findings on record."""
    by_tool: dict[str, list[SarifEntry]] = {name: [] for name in tools}
    for entry in entries:
        by_tool.setdefault(entry.finding.tool, []).append(entry)

    runs = []
    for name in sorted(by_tool):
        tool = tools.get(name) or SarifTool(name)
        rules: list[dict[str, Any]] = []
        rule_index: dict[str, int] = {}
        results = []
        for entry in sorted(by_tool[name], key=lambda e: e.finding.fingerprint):
            rule_id = entry.finding.rule_id
            if rule_id not in rule_index:
                rule_index[rule_id] = len(rules)
                rules.append(_rule(entry.finding))
            results.append(_result(entry, rule_index[rule_id]))
        driver: dict[str, Any] = {"name": tool.name, "rules": rules}
        if tool.version:
            driver["version"] = tool.version
        if tool.uri:
            driver["informationUri"] = tool.uri
        runs.append(
            {
                "tool": {"driver": driver},
                "conversion": {
                    "tool": {
                        "driver": {
                            "name": "htw",
                            "version": __version__,
                            "informationUri": PROJECT_URI,
                        }
                    }
                },
                "automationDetails": {"id": f"htw/{asset_id}/{name}/{run_id}"},
                "columnKind": "utf16CodeUnits",
                "results": results,
                "properties": {"htw/asset": asset_id, "htw/run": run_id},
            }
        )
    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": runs}
