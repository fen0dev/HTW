"""Reporting: turn a run into files people and tools can read.

Each run writes, under `<state_dir>/reports/<asset>/<run>/`:

- `report.md`       what changed since the last scan, what is open, what was not covered
- `findings.sarif`  all findings on record, normalized (SARIF 2.1.0)
- `summary.json`    machine-readable counts, coverage and the detected stack
- `sbom.cdx.json`   CycloneDX SBOM, when Syft is installed
- `proposals/`      fix proposals, when `fixes.propose` is enabled

Reports describe where a weakness is and how to remedy it. They never contain secret
values or source snippets, and they are not written anywhere public.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from htw import __version__
from htw.agents import AGENTS
from htw.agents.run import REFUSED, AssetRun
from htw.core.finding import Finding
from htw.core.markdown import code, link, md
from htw.core.sarif import SarifEntry, SarifTool, build_sarif
from htw.core.scoring import PRIORITIES
from htw.detect.model import CATEGORIES, CATEGORY_TITLES
from htw.integrations.pull_requests import ProposalWriter
from htw.scanners.base import STATUS_ERROR, STATUS_MISSING, STATUS_OK

MAX_DETAILED = 50
MAX_TABLE_ROWS = 200


def _tool_homepages() -> dict[str, str]:
    return {adapter.name: adapter.homepage for agent in AGENTS for adapter in agent.adapters}


def _priority_counts(findings: list[Finding]) -> str:
    counts = Counter(finding.priority for finding in findings)
    parts = [f"{counts[p]} {p}" for p in PRIORITIES if counts[p]]
    return ", ".join(parts)


def _remedy(finding: Finding) -> str:
    package = finding.package
    if package is None:
        return ""
    if package.fixed_versions:
        return f"Fixed in {md(', '.join(package.fixed_versions[:4]))}"
    return "No fixed version reported"


def _table(findings: list[Finding], first_seen: dict[str, str] | None = None) -> list[str]:
    lines = [
        "| Priority | Severity | Finding | Location | Tool | Id |",
        "|---|---|---|---|---|---|",
    ]
    for finding in findings[:MAX_TABLE_ROWS]:
        title = md(finding.title)
        remedy = _remedy(finding)
        if remedy:
            title += f"<br>{remedy}"
        elif first_seen and finding.fingerprint in first_seen:
            title += f"<br>First seen {first_seen[finding.fingerprint][:10]}"
        lines.append(
            f"| {finding.priority} | {finding.severity.value} | {title} "
            f"| {code(finding.location.display())} | {md(finding.tool)} "
            f"| {code(finding.fingerprint)} |"
        )
    if len(findings) > MAX_TABLE_ROWS:
        lines.append("")
        lines.append(
            f"{len(findings) - MAX_TABLE_ROWS} more not shown; see `findings.sarif` for the full list."
        )
    return lines


def _details(findings: list[Finding]) -> list[str]:
    lines: list[str] = []
    for finding in findings[:MAX_DETAILED]:
        lines += ["", f"#### {md(finding.title)}", ""]
        lines.append(f"- Id: {code(finding.fingerprint)}")
        lines.append(
            f"- Priority {finding.priority}, severity {finding.severity.value}"
            + (f", CVSS {finding.cvss_score:.1f}" if finding.cvss_score else "")
            + (f", confidence {md(finding.confidence)}" if finding.confidence else "")
        )
        lines.append(f"- Where: {code(finding.location.display())}")
        lines.append(f"- Rule: {code(finding.rule_id)} ({md(finding.tool)})")
        if finding.message:
            lines.append(f"- What: {md(finding.message)}")
        if finding.package is not None:
            lines.append(
                f"- Package: {md(finding.package.name)} {md(finding.package.version)} "
                f"({md(finding.package.ecosystem)}). {_remedy(finding)}."
            )
        if finding.identifiers:
            lines.append(f"- Identifiers: {md(', '.join(finding.identifiers))}")
        links = [rendered for rendered in map(link, finding.references) if rendered]
        if links:
            lines.append(f"- References: {' '.join(links)}")
    if len(findings) > MAX_DETAILED:
        lines += ["", f"{len(findings) - MAX_DETAILED} more in `findings.sarif`."]
    return lines


def render_markdown(run: AssetRun) -> str:
    asset, delta, profile = run.asset, run.delta, run.profile
    assert profile is not None and run.started_at is not None
    new = run.visible(delta.new)
    reappeared = run.visible(delta.reappeared)
    unchanged = run.visible(delta.unchanged)
    unverified = run.visible(delta.unverified)
    resolved = run.visible(delta.resolved)
    auth = asset.authorization

    lines = [
        f"# HTW scan report: {md(asset.id)}",
        "",
        "> **Confidential.** This report lists weaknesses that may not be fixed yet. Share it "
        "only with the people who own this asset, and do not paste it into public issues, "
        "pull requests or chats.",
        "",
        f"- Run: `{run.run_id}`, started {run.started_at.strftime('%Y-%m-%d %H:%M')} UTC, "
        f"HTW {__version__}",
        f"- Status: **{run.status}**"
        + (" (some scanners failed, see Coverage)" if run.has_errors else "")
        + (" with coverage gaps (see Coverage)" if run.gaps and not run.has_errors else ""),
        f"- Mode: {'report and propose fixes for review' if run.fixes_enabled else 'report only'}; "
        "static checks only (L0), nothing was changed",
        f"- Asset: {md(asset.type)}, owner {md(asset.owner)}, criticality {asset.criticality}",
        f"- Authorization: {md(auth.authorized_by)}, valid until {auth.expires_on.isoformat()}"
        + (f", reference {md(auth.reference)}" if auth.reference else ""),
        f"- Ownership check: {md(run.decision.ownership_evidence)}",
    ]
    for warning in run.decision.warnings:
        lines.append(f"- Warning: {md(warning)}")
    for note in run.notes:
        lines.append(f"- Note: {md(note)}")

    lines += ["", "## What changed since the last scan", ""]
    if not (new or reappeared or resolved):
        lines.append("Nothing changed. No new, reappeared or resolved findings.")
        lines.append("")
    lines += [
        "| | Count | By priority |",
        "|---|---|---|",
        f"| New | {len(new)} | {_priority_counts(new)} |",
        f"| Reappeared | {len(reappeared)} | {_priority_counts(reappeared)} |",
        f"| Resolved | {len(resolved)} | |",
        f"| Still open | {len(unchanged)} | {_priority_counts(unchanged)} |",
    ]
    if unverified:
        lines.append(
            f"| Open, not re-checked | {len(unverified)} | {_priority_counts(unverified)} |"
        )
    if run.suppressed:
        lines.append(f"| Suppressed | {len(run.suppressed)} | |")

    if new:
        lines += ["", "## New findings", "", *_table(new), *_details(new)]
    if reappeared:
        lines += [
            "",
            "## Reappeared findings",
            "",
            "These were resolved in an earlier scan and are back.",
            "",
            *_table(reappeared),
            *_details(reappeared),
        ]
    if resolved:
        lines += ["", "## Resolved findings", "", *_table(resolved)]
    if unchanged:
        lines += ["", "## Still open", "", *_table(unchanged, delta.first_seen)]
    if unverified:
        lines += [
            "",
            "## Open, not re-checked in this run",
            "",
            "The scanner that reported these did not complete in this run, so they are "
            "neither confirmed nor resolved.",
            "",
            *_table(unverified, delta.first_seen),
        ]

    lines += ["", "## Coverage", "", "### Detected stack", ""]
    if not profile.components:
        lines.append("Nothing recognizable was detected.")
    for category in CATEGORIES:
        components = profile.of(category)
        if components:
            rendered = ", ".join(
                f"{md(c.name)} ({c.count})"
                + ("" if c.confidence == "high" else f" [{c.confidence}]")
                for c in components
            )
            lines.append(f"- {CATEGORY_TITLES[category]}: {rendered}")
    for note in profile.notes:
        lines.append(f"- Note: {md(note)}")

    lines += [
        "",
        "### Scanners",
        "",
        "| Agent | Tool | Version | Result | Findings | Detail |",
        "|---|---|---|---|---|---|",
    ]
    for plan in run.plans:
        if not plan.applicable:
            lines.append(f"| {md(plan.title)} | | | not applicable | | {md(plan.reason)} |")
    for outcome in run.outcomes:
        title = next((p.title for p in run.plans if p.agent == outcome.agent), outcome.agent)
        result = {
            STATUS_OK: "ran",
            STATUS_ERROR: "**failed**",
            STATUS_MISSING: "**not installed**",
        }[outcome.status]
        count = str(len(outcome.findings)) if outcome.status == STATUS_OK else ""
        lines.append(
            f"| {md(title)} | {md(outcome.tool)} | {md(outcome.version or '')} | {result} "
            f"| {count} | {md(outcome.message)} |"
        )

    gaps = run.gaps
    if gaps:
        lines += ["", "### Not covered", ""]
        for gap in gaps:
            lines.append(f"- {md(gap)}: no installed scanner covers this. See the Scanners table.")

    if run.triage:
        lines += ["", "## Triage", ""]
        for decision in run.triage:
            lines.append(
                f"- {decision.action.replace('_', ' ')}: {md(decision.title)} "
                f"({code(decision.fingerprint)}): {md(decision.reason)}"
            )

    if run.suppressed or run.expired_suppressions:
        lines += ["", "## Suppressions", ""]
        for fingerprint, suppression in sorted(run.suppressed.items()):
            lines.append(
                f"- {code(fingerprint)}: {suppression.kind.replace('_', ' ')}, "
                f"{md(suppression.reason)} ({md(suppression.author)}, "
                f"expires {suppression.expires.isoformat()})"
            )
        for suppression in run.expired_suppressions:
            lines.append(
                f"- {code(suppression.fingerprint)}: **expired** on "
                f"{suppression.expires.isoformat()} and no longer applies. Renew or remove it."
            )

    if run.fixes_enabled:
        lines += ["", "## Fix proposals", ""]
        if not run.proposals:
            lines.append("No fix could be proposed mechanically for the open findings.")
        for proposal in run.proposals:
            patch = "with patch" if proposal.has_patch else "no patch"
            lines.append(
                f"- {proposal.priority}: {proposal.title} ({patch}): `proposals/{proposal.id}.md`"
            )
        lines += [
            "",
            "Proposals are suggestions for a person to review. HTW did not apply any of them.",
        ]
        if run.pull_requests:
            lines += ["", "Draft pull requests opened for review (not merged):", ""]
            for reference in run.pull_requests:
                lines.append(f"- {code(reference.branch)}: {reference.url}")

    lines += [
        "",
        "## Handling",
        "",
        "- A leaked credential must be revoked and rotated first, then removed from the "
        "code and its history. Removing it from the latest commit is not enough.",
        "- If a finding is wrong or an accepted risk, add a suppression with a reason, an "
        "author and an expiry date to the suppressions file, and send it through code review.",
        "- If a weakness turns out to be in a third-party component, report it privately to "
        "its maintainers. Do not open a public issue with details.",
        "",
    ]
    return "\n".join(lines)


def build_summary(run: AssetRun) -> dict[str, Any]:
    profile = run.profile
    return {
        "htw_version": __version__,
        "asset": run.asset.id,
        "run": run.run_id,
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "mode": "propose-fixes" if run.fixes_enabled else "report-only",
        "delta": {
            "new": [f.fingerprint for f in run.visible(run.delta.new)],
            "reappeared": [f.fingerprint for f in run.visible(run.delta.reappeared)],
            "resolved": [f.fingerprint for f in run.visible(run.delta.resolved)],
            "unchanged": len(run.visible(run.delta.unchanged)),
            "unverified": len(run.visible(run.delta.unverified)),
            "suppressed": len(run.suppressed),
        },
        "scanners": [
            {
                "agent": o.agent,
                "tool": o.tool,
                "version": o.version,
                "status": o.status,
                "findings": len(o.findings),
                "detail": o.message,
            }
            for o in run.outcomes
        ],
        "plans": [plan.to_dict() for plan in run.plans],
        "gaps": run.gaps,
        "stack": profile.to_dict() if profile else None,
        "proposals": [
            {"id": p.id, "title": p.title, "priority": p.priority, "has_patch": p.has_patch}
            for p in run.proposals
        ],
        "pull_requests": [
            {"url": reference.url, "branch": reference.branch, "draft": reference.draft}
            for reference in run.pull_requests
        ],
        "triage": [
            {
                "fingerprint": decision.fingerprint,
                "action": decision.action,
                "reason": decision.reason,
            }
            for decision in run.triage
        ],
    }


def build_run_sarif(run: AssetRun) -> dict[str, Any]:
    homepages = _tool_homepages()
    tools = {
        o.tool: SarifTool(o.tool, o.version, homepages.get(o.tool))
        for o in run.outcomes
        if o.status == STATUS_OK
    }
    entries = []
    for state, findings in (
        ("new", run.delta.new),
        ("reappeared", run.delta.reappeared),
        ("unchanged", run.delta.unchanged),
        ("unverified", run.delta.unverified),
        ("resolved", run.delta.resolved),
    ):
        for finding in findings:
            entries.append(
                SarifEntry(
                    finding=finding,
                    state=state,
                    first_seen=run.delta.first_seen.get(finding.fingerprint),
                    suppression=run.suppressed.get(finding.fingerprint),
                )
            )
            if finding.tool not in tools:
                tools[finding.tool] = SarifTool(finding.tool, None, homepages.get(finding.tool))
    return build_sarif(run.asset.id, run.run_id, entries, tools)


def write_reports(run: AssetRun) -> Path:
    """Write all report files for a completed run and return the directory."""
    assert run.report_dir is not None
    directory = run.report_dir
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "report.md").write_text(render_markdown(run), encoding="utf-8")
    (directory / "findings.sarif").write_text(
        json.dumps(build_run_sarif(run), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (directory / "summary.json").write_text(
        json.dumps(build_summary(run), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if run.fixes_enabled:
        ProposalWriter(directory / "proposals").write(run.proposals)
    return directory


def console_summary(run: AssetRun) -> str:
    """A short plain-text summary for the terminal and CI logs."""
    if run.status == REFUSED:
        reasons = "\n".join(f"  - {reason}" for reason in run.decision.reasons)
        return f"[{run.asset.id}] REFUSED: not scanned.\n{reasons}"
    new = run.visible(run.delta.new)
    reappeared = run.visible(run.delta.reappeared)
    resolved = run.visible(run.delta.resolved)
    unchanged = run.visible(run.delta.unchanged)
    lines = [
        f"[{run.asset.id}] {run.status}: {len(new)} new, {len(reappeared)} reappeared, "
        f"{len(resolved)} resolved, {len(unchanged)} still open"
        + (f", {len(run.suppressed)} suppressed" if run.suppressed else "")
        + (f", {len(run.triage)} triaged aside" if run.triage else "")
    ]
    for finding in (new + reappeared)[:10]:
        lines.append(
            f"  {finding.priority} {finding.severity.value:<8} {finding.title} "
            f"({finding.location.display()})"
        )
    if len(new) + len(reappeared) > 10:
        lines.append(f"  ... and {len(new) + len(reappeared) - 10} more")
    for outcome in run.outcomes:
        if outcome.status == STATUS_MISSING:
            lines.append(f"  warning: {outcome.message}")
        elif outcome.status == STATUS_ERROR:
            lines.append(f"  error: {outcome.tool}: {outcome.message}")
    for gap in run.gaps:
        lines.append(f"  not covered: {gap}")
    for warning in run.decision.warnings:
        lines.append(f"  warning: {warning}")
    if run.report_dir is not None:
        lines.append(f"  report: {run.report_dir / 'report.md'}")
    return "\n".join(lines)
