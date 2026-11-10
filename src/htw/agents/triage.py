"""Triage: deduplicate, rank and filter obvious false positives.

The rules are deterministic and run with no network. A model is consulted only when
the caller passes one, and only for findings those rules did not settle. Its answer
can hide a finding or lower confidence. It cannot raise a severity and it is not
given secret values or source lines. A fingerprint it has already classified is
reused from the state directory and is not sent again.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
_MESSAGE_LIMIT = 160
_MEMORY_VERSION = 1
_FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9:._-]{1,128}$")


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
    state_dir: Path | None = None,
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
            kept, model_notes = _apply_model(kept, llm, state_dir)
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


def _settled(finding: Finding) -> bool:
    """High confidence already survived the local false-positive rules."""
    return (finding.confidence or "").lower() == "high"


def _apply_model(
    findings: list[Finding], llm: HttpLlm, state_dir: Path | None
) -> tuple[list[Finding], list[TriageNote]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.fingerprint, []).append(finding)
    stored = _load_memory(state_dir)
    pending: list[Finding] = []
    seen: set[str] = set()
    drop: set[str] = set()
    notes: list[TriageNote] = []
    for finding in findings:
        fingerprint = finding.fingerprint
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        cached = stored.get(fingerprint)
        if cached is not None:
            _replay(grouped[fingerprint], cached, drop, notes)
            continue
        if _settled(finding):
            continue
        pending.append(finding)
    if not pending:
        return [finding for finding in findings if finding.fingerprint not in drop], notes
    items = [_item(finding) for finding in pending]
    sent = {finding.fingerprint for finding in pending}
    try:
        judgments = llm.judge(items)
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigError(f"LLM triage failed ({type(exc).__name__})") from exc
    fresh: dict[str, dict[str, Any]] = {}
    for judgment in judgments:
        fingerprint = str(judgment.get("fingerprint") or "")
        members = grouped.get(fingerprint)
        if fingerprint not in sent or not members or fingerprint in fresh:
            continue
        saved = _saved_judgment(judgment)
        fresh[fingerprint] = saved
        _replay(members, saved, drop, notes)
    if fresh:
        stored.update(fresh)
        _save_memory(state_dir, stored)
    return [finding for finding in findings if finding.fingerprint not in drop], notes


def _item(finding: Finding) -> dict[str, str]:
    return {
        "fingerprint": finding.fingerprint,
        "rule": finding.rule_id,
        "path": finding.location.path or "",
        "line": str(finding.location.start_line or ""),
        "category": finding.category,
        "severity": finding.severity.value,
        "message": finding.message[:_MESSAGE_LIMIT],
    }


def _saved_judgment(judgment: dict[str, Any]) -> dict[str, Any]:
    reason = str(judgment.get("reason") or "").strip()[:300]
    false_positive = judgment.get("false_positive") is True and bool(reason)
    confidence = "low" if judgment.get("confidence") == "low" else ""
    return {"false_positive": false_positive, "confidence": confidence, "reason": reason}


def _replay(
    members: list[Finding], saved: dict[str, Any], drop: set[str], notes: list[TriageNote]
) -> None:
    fingerprint = members[0].fingerprint
    for finding in members:
        if saved.get("confidence") == "low" and finding.confidence != "low":
            finding.confidence = "low"
            _lower_low_confidence(finding)
    reason = str(saved.get("reason") or "")
    if saved.get("false_positive") is True and reason:
        drop.add(fingerprint)
        notes.append(
            TriageNote(fingerprint, members[0].title, "false_positive", f"model: {reason[:300]}")
        )


def _memory_path(state_dir: Path | None) -> Path | None:
    if state_dir is None:
        return None
    try:
        root = state_dir.resolve()
        directory = root / "cache"
        path = directory / "llm-triage.json"
        if directory.is_symlink() or path.is_symlink():
            return None
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        resolved = directory.resolve() / path.name
    except OSError:
        return None
    if resolved != root and root not in resolved.parents:
        return None
    return path


def _load_memory(state_dir: Path | None) -> dict[str, dict[str, Any]]:
    path = _memory_path(state_dir)
    if path is None or path.is_symlink() or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return {}
    if not isinstance(data, dict) or data.get("version") != _MEMORY_VERSION:
        return {}
    raw = data.get("judgments")
    if not isinstance(raw, dict):
        return {}
    kept: dict[str, dict[str, Any]] = {}
    for fingerprint, entry in raw.items():
        if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.fullmatch(fingerprint):
            continue
        if not isinstance(entry, dict):
            continue
        kept[fingerprint] = _saved_judgment(entry)
    return kept


def _save_memory(state_dir: Path | None, judgments: dict[str, dict[str, Any]]) -> None:
    path = _memory_path(state_dir)
    if path is None or path.is_symlink():
        return
    payload = {
        "version": _MEMORY_VERSION,
        "judgments": {key: judgments[key] for key in sorted(judgments)},
    }
    temporary = path.with_suffix(".tmp")
    try:
        temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except OSError:
        return
