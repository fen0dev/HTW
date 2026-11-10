"""Triage: deduplicate, rank and filter obvious false positives.

The rules are deterministic and run with no network. A model is consulted only when
the caller passes one, and its answer can hide a finding or lower confidence. It
cannot raise a severity and it is not given secret values or source lines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from htw.core.finding import DEPENDENCY, SECRET, Finding
from htw.core.fingerprint import normalize_package_name
from htw.core.llm import HttpLlm
from htw.core.scoring import PRIORITIES
from htw.errors import ConfigError

_VENDOR_DIRS = frozenset(
    {"node_modules", "vendor", "third_party", "third-party", "site-packages", ".venv", "venv"}
)
_DOC_PATH_RE = re.compile(
    r"(^|/)(README|CHANGELOG|CONTRIBUTING)(\.[^/]+)?$|(^|/)(docs|examples|example)/",
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(
    r"(?i)placeholder|changeme|example|redacted|your[-_ ]?(token|key|secret|password)"
    r"|not-a-real|insert[-_ ]key"
)
_CONFIDENCE = {"high": 2, "medium": 1, "low": 0}


@dataclass(frozen=True)
class TriageNote:
    fingerprint: str
    title: str
    action: str
    reason: str


def triage_findings(
    findings: list[Finding],
    *,
    environment: str,
    llm: HttpLlm | None = None,
) -> tuple[list[Finding], list[TriageNote]]:
    """Return the findings to keep, and a note for each one set aside."""
    del environment  # reserved for a later exposure adjustment; ranking uses confidence
    notes: list[TriageNote] = []
    kept: list[Finding] = []
    for finding in findings:
        reason = _false_positive_reason(finding)
        if reason:
            notes.append(TriageNote(finding.fingerprint, finding.title, "false_positive", reason))
        else:
            kept.append(finding)
    kept, duplicates = _deduplicate(kept)
    notes.extend(duplicates)
    for finding in kept:
        _lower_low_confidence(finding)
    if llm is not None:
        try:
            kept, model_notes = _apply_model(kept, llm)
        except ConfigError as exc:
            notes.append(TriageNote("-", "LLM triage", "error", str(exc)))
        else:
            notes.extend(model_notes)
    return kept, notes


def _false_positive_reason(finding: Finding) -> str | None:
    parts = set((finding.location.path or "").split("/"))
    if finding.category not in {DEPENDENCY, SECRET} and parts & _VENDOR_DIRS:
        return "third-party or vendored path; review the dependency, not a copy of its source"
    if finding.category == SECRET and _DOC_PATH_RE.search(finding.location.path or ""):
        blob = f"{finding.context or ''}\n{finding.message}"
        if _PLACEHOLDER_RE.search(blob):
            return "placeholder credential in documentation"
    return None


def _deduplicate(findings: list[Finding]) -> tuple[list[Finding], list[TriageNote]]:
    dropped: set[int] = set()
    notes: list[TriageNote] = []
    for members in _groups(findings).values():
        if len({item.tool for item in members}) < 2:
            continue
        best = max(members, key=_preference)
        for item in members:
            if item is best or id(item) in dropped:
                continue
            dropped.add(id(item))
            notes.append(
                TriageNote(
                    item.fingerprint,
                    item.title,
                    "duplicate",
                    f"same issue as {best.fingerprint} from {best.tool}",
                )
            )
    return [item for item in findings if id(item) not in dropped], notes


def _groups(findings: list[Finding]) -> dict[tuple[object, ...], list[Finding]]:
    groups: dict[tuple[object, ...], list[Finding]] = {}
    for finding in findings:
        key = _dedup_key(finding)
        if key is None:
            continue
        groups.setdefault(key, []).append(finding)
    return groups


def _dedup_key(finding: Finding) -> tuple[object, ...] | None:
    if finding.category == DEPENDENCY and finding.package is not None:
        cves = tuple(
            sorted(item.upper() for item in finding.identifiers if item.upper().startswith("CVE-"))
        )
        if not cves:
            return None
        package = finding.package
        return (
            DEPENDENCY,
            package.ecosystem.lower(),
            normalize_package_name(package.ecosystem, package.name),
            finding.location.path or "",
            cves,
        )
    cwes = tuple(
        sorted(item.upper() for item in finding.identifiers if item.upper().startswith("CWE-"))
    )
    if not cwes or not finding.location.path or not finding.location.start_line:
        return None
    return (finding.category, finding.location.path, finding.location.start_line, cwes)


def _preference(finding: Finding) -> tuple[int, int, str]:
    return (finding.severity.rank, _CONFIDENCE.get(finding.confidence or "", 1), finding.tool)


def _lower_low_confidence(finding: Finding) -> None:
    if (
        finding.confidence != "low"
        or finding.category == SECRET
        or finding.priority not in PRIORITIES
    ):
        return
    finding.priority = PRIORITIES[min(PRIORITIES.index(finding.priority) + 1, len(PRIORITIES) - 1)]


def _apply_model(findings: list[Finding], llm: HttpLlm) -> tuple[list[Finding], list[TriageNote]]:
    by_id = {finding.fingerprint: finding for finding in findings}
    items = [
        {
            "fingerprint": finding.fingerprint,
            "rule": finding.rule_id,
            "path": finding.location.path or "",
            "line": str(finding.location.start_line or ""),
            "category": finding.category,
            "severity": finding.severity.value,
            "message": finding.message[:400],
        }
        for finding in findings
    ]
    try:
        judgments = llm.judge(items)
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigError(f"LLM triage failed ({type(exc).__name__})") from exc
    drop: set[str] = set()
    notes: list[TriageNote] = []
    for judgment in judgments:
        fingerprint = str(judgment.get("fingerprint") or "")
        finding = by_id.get(fingerprint)
        if finding is None or fingerprint in drop:
            continue
        if judgment.get("confidence") == "low":
            finding.confidence = "low"
            _lower_low_confidence(finding)
        reason = str(judgment.get("reason") or "").strip()
        if judgment.get("false_positive") is True and reason:
            drop.add(fingerprint)
            notes.append(
                TriageNote(fingerprint, finding.title, "false_positive", f"model: {reason[:300]}")
            )
    return [finding for finding in findings if finding.fingerprint not in drop], notes
