"""A local digest of the latest finished scan for each declared asset.

The digest is read from `summary.json` and `findings.sarif`, which a scan already
wrote. It is written under the state directory. Nothing is uploaded, and no server
is started.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from htw.agents.reporting import gap_markdown
from htw.core.config import Asset, Config
from htw.core.markdown import code, md
from htw.core.scoring import PRIORITIES
from htw.errors import EXIT_REFUSED, HtwError

_MAX_SUMMARY_BYTES = 2 * 1024 * 1024
_MAX_SARIF_BYTES = 32 * 1024 * 1024
_MAX_GAPS = 40
_OPEN_STATES = frozenset({"new", "reappeared", "unchanged", "unverified"})


class DigestError(HtwError):
    """No finished local report could be read. Nothing was uploaded."""

    exit_code = EXIT_REFUSED


@dataclass
class _AssetDigest:
    asset_id: str
    problem: str = ""
    run_id: str = ""
    status: str = ""
    started_at: str = ""
    report: Path | None = None
    new: int = 0
    reappeared: int = 0
    resolved: int = 0
    unchanged: int = 0
    unverified: int = 0
    suppressed: int = 0
    open_by_priority: Counter[str] = field(default_factory=Counter)
    priorities_read: bool = False
    gaps: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    missing: int = 0


def write_digest(
    config: Config,
    asset_ids: Sequence[str] | None = None,
    *,
    now: datetime | None = None,
) -> tuple[Path, str]:
    """Read finished reports and write `<state_dir>/digest.md`. Returns path and text."""
    assets = _select(config, asset_ids)
    reports = config.reports_dir
    if config.state_dir.is_symlink() or not _contained(reports, config.state_dir):
        raise DigestError("the reports directory is outside the state directory")
    rows = [_read_asset(reports, asset.id) for asset in assets]
    if not any(row.problem == "" for row in rows):
        details = "; ".join(f"{row.asset_id}: {row.problem}" for row in rows)
        raise DigestError(
            f"No finished scan to read ({details}). "
            "The digest is built only from reports already written on this machine."
        )
    text = _render(rows, now or datetime.now(UTC))
    path = config.state_dir / "digest.md"
    if path.is_symlink():
        raise DigestError("digest path is a symlink; it was not written")
    temporary = path.with_suffix(".tmp")
    try:
        temporary.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except OSError as exc:
        raise DigestError(f"the digest could not be written: {exc}") from None
    return path, text


def _select(config: Config, asset_ids: Sequence[str] | None) -> tuple[Asset, ...]:
    if not asset_ids:
        return config.assets
    chosen = []
    seen: set[str] = set()
    for asset_id in asset_ids:
        asset = config.asset(asset_id)
        if asset.id not in seen:
            chosen.append(asset)
            seen.add(asset.id)
    return tuple(chosen)


def _read_asset(reports: Path, asset_id: str) -> _AssetDigest:
    row = _AssetDigest(asset_id)
    asset_dir = reports / asset_id
    if not asset_dir.exists():
        row.problem = "no finished scan"
        return row
    if not _contained(asset_dir, reports) or asset_dir.is_symlink() or not asset_dir.is_dir():
        row.problem = "no finished scan"
        return row
    latest = _latest(asset_dir, reports)
    if latest is None:
        row.problem = "no finished scan"
        return row
    summary = _load_json(latest / "summary.json", reports, _MAX_SUMMARY_BYTES)
    parsed = _summary(summary) if summary is not None else None
    if parsed is None:
        row.problem = "latest report could not be read"
        return row
    row.run_id = parsed["run_id"] or latest.name
    row.status = parsed["status"]
    row.started_at = parsed["started_at"]
    row.new = parsed["new"]
    row.reappeared = parsed["reappeared"]
    row.resolved = parsed["resolved"]
    row.unchanged = parsed["unchanged"]
    row.unverified = parsed["unverified"]
    row.suppressed = parsed["suppressed"]
    row.gaps = parsed["gaps"]
    row.failed = parsed["failed"]
    row.missing = parsed["missing"]
    report = latest / "report.md"
    if report.is_file() and not report.is_symlink() and _contained(report, reports):
        row.report = report
    sarif = _load_json(latest / "findings.sarif", reports, _MAX_SARIF_BYTES)
    counts = _open_priorities(sarif) if sarif is not None else None
    expected = row.new + row.reappeared + row.unchanged + row.unverified
    if counts is not None and sum(counts.values()) == expected:
        row.open_by_priority = counts
        row.priorities_read = True
    return row


def _latest(asset_dir: Path, reports: Path) -> Path | None:
    names: list[str] = []
    try:
        children = list(asset_dir.iterdir())
    except OSError:
        return None
    for child in children:
        summary = child / "summary.json"
        if (
            child.is_symlink()
            or not child.is_dir()
            or summary.is_symlink()
            or not summary.is_file()
            or not _contained(summary, reports)
        ):
            continue
        names.append(child.name)
    if not names:
        return None
    return asset_dir / max(names)


def _load_json(path: Path, root: Path, limit: int) -> dict[str, Any] | None:
    if path.is_symlink() or not path.is_file() or not _contained(path, root):
        return None
    try:
        payload = path.read_bytes()
    except OSError:
        return None
    if len(payload) > limit:
        return None
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _summary(data: dict[str, Any]) -> dict[str, Any] | None:
    delta = data.get("delta")
    if not isinstance(delta, dict):
        return None
    new = _count(delta.get("new"))
    reappeared = _count(delta.get("reappeared"))
    resolved = _count(delta.get("resolved"))
    unchanged = _count(delta.get("unchanged"))
    unverified = _count(delta.get("unverified"))
    suppressed = _count(delta.get("suppressed"))
    if None in (new, reappeared, resolved, unchanged, unverified, suppressed):
        return None
    assert new is not None and reappeared is not None and resolved is not None
    assert unchanged is not None and unverified is not None and suppressed is not None
    status = data.get("status")
    run_id = data.get("run")
    started = data.get("started_at")
    gaps = data.get("gaps")
    scanners = data.get("scanners")
    if not isinstance(status, str) or (gaps is not None and not isinstance(gaps, list)):
        return None
    if scanners is not None and not isinstance(scanners, list):
        return None
    failed: list[str] = []
    missing = 0
    for scanner in scanners or []:
        if not isinstance(scanner, dict):
            continue
        state = scanner.get("status")
        tool = scanner.get("tool")
        if state == "error" and isinstance(tool, str) and tool:
            failed.append(tool)
        elif state == "missing":
            missing += 1
    gap_text = [item for item in gaps or [] if isinstance(item, str)]
    return {
        "status": status,
        "run_id": run_id if isinstance(run_id, str) else "",
        "started_at": started if isinstance(started, str) else "",
        "gaps": gap_text,
        "failed": failed,
        "missing": missing,
        "new": new,
        "reappeared": reappeared,
        "resolved": resolved,
        "unchanged": unchanged,
        "unverified": unverified,
        "suppressed": suppressed,
    }


def _count(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, list):
        return len(value)
    return None


def _open_priorities(data: dict[str, Any]) -> Counter[str] | None:
    runs = data.get("runs")
    if not isinstance(runs, list):
        return None
    counts: Counter[str] = Counter()
    for run in runs:
        if not isinstance(run, dict):
            return None
        results = run.get("results", [])
        if not isinstance(results, list):
            return None
        for result in results:
            if not isinstance(result, dict):
                return None
            if _suppressed(result):
                continue
            properties = result.get("properties")
            if not isinstance(properties, dict):
                continue
            state = properties.get("htw/state")
            priority = properties.get("htw/priority")
            if state not in _OPEN_STATES:
                continue
            if not isinstance(priority, str) or priority not in PRIORITIES:
                return None
            counts[priority] += 1
    return counts


def _suppressed(result: dict[str, Any]) -> bool:
    suppressions = result.get("suppressions")
    return isinstance(suppressions, list) and len(suppressions) > 0


def _contained(path: Path, root: Path) -> bool:
    try:
        resolved = path.resolve()
        base = root.resolve()
    except OSError:
        return False
    return resolved == base or base in resolved.parents


def _render(rows: list[_AssetDigest], now: datetime) -> str:
    readable = [row for row in rows if row.problem == ""]
    open_counts: Counter[str] = Counter()
    priorities_complete = all(row.priorities_read for row in readable)
    if priorities_complete:
        for row in readable:
            open_counts.update(row.open_by_priority)
    open_total = sum(open_counts.values())
    stamp = now.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# HTW digest",
        "",
        "> **Confidential.** Built from the scan reports already stored on this machine. "
        "Nothing was uploaded. Do not paste it into public issues, pull requests or chats.",
        "",
        f"Read at {stamp}. One latest finished scan per declared asset.",
        "",
        f"- Declared assets: {len(rows)}. Finished scans read: {len(readable)}.",
    ]
    if priorities_complete:
        lines.append(f"- Open findings: {open_total} ({_priority_list(open_counts)}).")
    else:
        lines.append("- Open findings by priority were not summed, because a report did not match.")
    lines.append(
        "- In those scans: "
        f"{sum(row.new for row in readable)} new, "
        f"{sum(row.reappeared for row in readable)} reappeared, "
        f"{sum(row.resolved for row in readable)} resolved."
    )
    lines += [
        "- Time to resolution and a false-positive rate are not in these reports, "
        "so this digest does not show them.",
        "",
        "## By asset",
        "",
        "| Asset | Run | Status | New | Reappeared | Resolved | Still open | Open by priority |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(_table_row(row))
    for row in rows:
        lines += ["", f"## {md(row.asset_id)}", ""]
        lines.extend(_asset_lines(row))
    lines.append("")
    return "\n".join(lines)


def _table_row(row: _AssetDigest) -> str:
    if row.problem:
        return f"| {md(row.asset_id)} | | {md(row.problem)} | | | | | |"
    priority = _priority_list(row.open_by_priority) if row.priorities_read else "not read"
    run = code(row.run_id)
    return (
        f"| {md(row.asset_id)} | {run} | {md(row.status)} | {row.new} | {row.reappeared} "
        f"| {row.resolved} | {row.unchanged} | {md(priority)} |"
    )


def _asset_lines(row: _AssetDigest) -> list[str]:
    if row.problem:
        return [f"{md(row.problem)}."]
    lines = []
    if row.report is not None:
        lines.append(f"- Report: {code(row.report)}")
    if row.started_at:
        lines.append(f"- Started: {code(row.started_at)}")
    if row.unverified:
        lines.append(f"- Open, not re-checked: {row.unverified}.")
    if row.suppressed:
        lines.append(f"- Suppressed: {row.suppressed}.")
    if row.failed or row.missing:
        failed = ", ".join(md(tool) for tool in row.failed)
        parts = []
        if row.failed:
            noun = "scanner" if len(row.failed) == 1 else "scanners"
            parts.append(f"{len(row.failed)} {noun} failed ({failed})")
        if row.missing:
            parts.append(f"{row.missing} not installed")
        lines.append("- " + "; ".join(parts) + ".")
    if row.gaps:
        lines.append("- Not covered:")
        for gap in row.gaps[:_MAX_GAPS]:
            lines.append(f"  - {gap_markdown(gap)}")
        if len(row.gaps) > _MAX_GAPS:
            lines.append(f"  - {len(row.gaps) - _MAX_GAPS} more in the report.")
    if not row.priorities_read:
        lines.append(
            "- Open findings were not grouped by priority, because `findings.sarif` "
            "did not match `summary.json`."
        )
    return lines


def _priority_list(counts: Counter[str]) -> str:
    parts = [f"{counts[priority]} {priority}" for priority in PRIORITIES if counts[priority]]
    return ", ".join(parts) if parts else "none"
