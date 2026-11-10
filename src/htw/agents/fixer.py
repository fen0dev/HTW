"""Fix proposals.

HTW never changes the systems it scans. A fix is a *proposal*: a description of the
remedy and, where it can be derived mechanically, a patch. Proposals are written next
to the report, and can be handed to a `PullRequestPublisher` that opens a draft pull
request for a person to review. Nothing here applies a patch or merges anything.

Proposal text describes the remedy, never how to exploit the weakness.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from htw.core.finding import DEPENDENCY, Finding, LineFix
from htw.core.fingerprint import normalize_package_name
from htw.core.markdown import code, md
from htw.core.redact import redact_text
from htw.core.scoring import PRIORITIES
from htw.detect.model import DEPENDENCY_AUTOMATION, StackProfile

KIND_DEPENDENCY_BUMP = "dependency_bump"
KIND_CODE_CHANGE = "code_change"

_PLAIN_VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)$")
_REQUIREMENT_RE = re.compile(
    r"^(?P<prefix>\s*)(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<extras>\[[^\]]*\])?"
    r"(?P<operator>\s*==\s*)(?P<version>[^\s;#\\]+)(?P<rest>.*)$"
)
_REQUIREMENTS_FILE_RE = re.compile(
    r"(^|/)requirements([-_.][\w.-]*)?\.txt$|(^|/)requirements/[\w.-]+\.txt$"
)
MAX_PATCHABLE_BYTES = 1_000_000


@dataclass(frozen=True)
class FileChange:
    path: str
    diff: str


@dataclass
class FixProposal:
    """A proposed remedy for one or more findings. Always needs human review."""

    asset_id: str
    kind: str
    title: str
    summary: str
    fingerprints: tuple[str, ...]
    priority: str
    proposer: str
    changes: tuple[FileChange, ...] = ()
    notes: list[str] = field(default_factory=list)
    # True when opening a public pull request discloses nothing that is not already
    # public, as with an upgrade for a published advisory.
    public_safe: bool = False

    requires_human_review = True

    @property
    def id(self) -> str:
        digest = hashlib.sha256(
            "\n".join([self.kind, self.title, *sorted(self.fingerprints)]).encode("utf-8")
        ).hexdigest()
        return f"fix-{digest[:12]}"

    @property
    def has_patch(self) -> bool:
        return bool(self.changes)

    @property
    def patch(self) -> str:
        return "".join(change.diff for change in self.changes)


@dataclass
class FixContext:
    asset_id: str
    root: Path
    profile: StackProfile


class FixProposer(ABC):
    """Turns findings into proposals. Implementations must not modify `ctx.root`."""

    name: str

    @abstractmethod
    def propose(self, findings: list[Finding], ctx: FixContext) -> list[FixProposal]: ...


def parse_version(text: str) -> tuple[int, ...] | None:
    """Parse a plain dotted release version. Pre-releases and ranges return None."""
    match = _PLAIN_VERSION_RE.match(text.strip())
    return tuple(int(part) for part in match.group(1).split(".")) if match else None


def target_version(current: str, fixed_per_advisory: list[tuple[str, ...]]) -> str | None:
    """The lowest version that clears every advisory, or None if it cannot be derived.

    For each advisory the smallest fixed version above the current one is taken (an
    advisory may list one fix per maintained branch); the target is the highest of
    those. Anything that is not a plain release version makes the answer unknown.
    """
    installed = parse_version(current)
    if installed is None or not fixed_per_advisory:
        return None
    needed: list[tuple[tuple[int, ...], str]] = []
    for fixed_versions in fixed_per_advisory:
        candidates = []
        for version in fixed_versions:
            parsed = parse_version(version)
            if parsed is None:
                return None
            if parsed > installed:
                candidates.append((parsed, version))
        if not candidates:
            return None
        needed.append(min(candidates))
    return max(needed)[1]


class DependencyBumpProposer(FixProposer):
    """Proposes dependency upgrades from the fixed versions the advisories report.

    Dependency update bots do this job better and should be preferred where they are
    configured. This proposer covers the gap: it always states the target version, and
    writes a patch only for the one format where that is unambiguous (an exact `==`
    pin without hashes in a requirements file).
    """

    name = "dependency-bump"

    def propose(self, findings: list[Finding], ctx: FixContext) -> list[FixProposal]:
        groups: dict[tuple[str, str, str, str], list[Finding]] = defaultdict(list)
        for finding in findings:
            if finding.category != DEPENDENCY or finding.package is None:
                continue
            package = finding.package
            key = (
                finding.location.path or "",
                package.ecosystem,
                normalize_package_name(package.ecosystem, package.name),
                package.version,
            )
            groups[key].append(finding)

        bots = sorted(ctx.profile.names(DEPENDENCY_AUTOMATION))
        proposals = []
        for (manifest, ecosystem, name, version), members in sorted(groups.items()):
            advisories = sorted({member.rule_id for member in members})
            target = target_version(
                version, [m.package.fixed_versions for m in members if m.package is not None]
            )
            where = f" in {code(manifest)}" if manifest else ""
            label = f"{md(name)} {md(version)}"
            affected = (
                f"{label} ({md(ecosystem)}){where} is affected by {len(advisories)} published "
                f"advisor{'y' if len(advisories) == 1 else 'ies'}: "
                f"{', '.join(md(advisory) for advisory in advisories)}."
            )
            if target:
                title = f"Upgrade {md(name)} from {md(version)} to {target}"
                summary = (
                    f"{affected} Version {target} is the lowest release that includes the "
                    "fixes for all of them."
                )
            else:
                title = f"Upgrade {label}"
                summary = (
                    f"{affected} A single target version could not be derived automatically; "
                    "check the advisories for the fixed releases."
                )
            proposal = FixProposal(
                asset_id=ctx.asset_id,
                kind=KIND_DEPENDENCY_BUMP,
                title=title,
                summary=summary,
                fingerprints=tuple(sorted(member.fingerprint for member in members)),
                priority=min((m.priority for m in members), key=_priority_rank),
                proposer=self.name,
                public_safe=True,
            )
            if bots:
                proposal.notes.append(
                    f"{' and '.join(bots)} is configured for this repository and should raise "
                    "this upgrade itself; prefer its pull request if one exists."
                )
            change = self._patch(ctx.root, manifest, name, version, target) if target else None
            if change is not None:
                proposal.changes = (change,)
                proposal.notes.append(
                    "The patch only edits the pin. Review the upgrade's changelog and run the "
                    "test suite before merging."
                )
            else:
                proposal.notes.append(
                    "No patch was generated: apply the upgrade with your package manager so "
                    "that the lockfile is regenerated consistently."
                )
            proposals.append(proposal)
        return proposals

    @staticmethod
    def _patch(
        root: Path, manifest: str, name: str, version: str, target: str
    ) -> FileChange | None:
        if not manifest or not _REQUIREMENTS_FILE_RE.search(manifest):
            return None
        path = root / manifest
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                return None
            if path.stat().st_size > MAX_PATCHABLE_BYTES:
                return None
            original = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        if "--hash" in original or not original.endswith("\n"):
            # Hash-pinned files need new hashes, which only the package index can supply.
            return None
        lines = original.splitlines(keepends=True)
        updated = list(lines)
        hits = 0
        for index, line in enumerate(lines):
            match = _REQUIREMENT_RE.match(line.rstrip("\r\n"))
            if (
                match
                and normalize_package_name("PyPI", match.group("name")) == name
                and _same_release(match.group("version"), version)
            ):
                ending = line[len(line.rstrip("\r\n")) :]
                updated[index] = (
                    f"{match.group('prefix')}{match.group('name')}{match.group('extras') or ''}"
                    f"{match.group('operator')}{target}{match.group('rest')}{ending}"
                )
                hits += 1
        if hits != 1:
            return None
        diff = "".join(
            difflib.unified_diff(lines, updated, fromfile=f"a/{manifest}", tofile=f"b/{manifest}")
        )
        return FileChange(path=manifest, diff=diff)


def _same_release(left: str, right: str) -> bool:
    """Compare versions the way scanners report them: 2.10 and 2.10.0 are the same."""
    if left == right:
        return True
    a, b = parse_version(left), parse_version(right)
    if a is None or b is None:
        return False
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) == b + (0,) * (width - len(b))


def _priority_rank(priority: str) -> int:
    return PRIORITIES.index(priority) if priority in PRIORITIES else len(PRIORITIES)


class ScannerPatchProposer(FixProposer):
    """Turns a scanner-supplied line replacement into a patch, after checking it.

    The patch is produced only when the matched text still occurs exactly once in the
    reported line range. HTW does not invent a fix the scanner did not supply, and it
    does not write the patch into the scanned tree.
    """

    name = "scanner-patch"

    def propose(self, findings: list[Finding], ctx: FixContext) -> list[FixProposal]:
        proposals = []
        for finding in findings:
            if finding.line_fix is None or finding.category == DEPENDENCY:
                continue
            change = apply_line_fix(ctx.root, finding)
            if change is None:
                continue
            proposal = FixProposal(
                asset_id=ctx.asset_id,
                kind=KIND_CODE_CHANGE,
                title=f"Apply {md(finding.tool)} fix for {md(finding.rule_id)}",
                summary=(
                    f"{md(finding.tool)} reported a replacement for {code(finding.rule_id)} "
                    f"at {code(finding.location.display())}. The patch is the scanner's "
                    "replacement of that match and nothing else."
                ),
                fingerprints=(finding.fingerprint,),
                priority=finding.priority or "P2",
                proposer=self.name,
                changes=(change,),
                public_safe=False,
                notes=["Review the change and run the test suite. HTW has not applied it."],
            )
            proposals.append(proposal)
        return proposals


def apply_line_fix(root: Path, finding: Finding) -> FileChange | None:
    """Build a one-file diff, or None when the fix cannot be checked."""
    fix = finding.line_fix
    location = finding.location
    if fix is None or not location.path or not location.start_line:
        return None
    if not _fix_is_publishable(fix):
        return None
    path = root / location.path
    try:
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            return None
        if path.stat().st_size > MAX_PATCHABLE_BYTES:
            return None
        original_text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    lines = original_text.splitlines(keepends=True)
    start = location.start_line - 1
    end = location.end_line or location.start_line
    if start < 0 or end > len(lines) or end < location.start_line:
        return None
    span = "".join(lines[start:end])
    if span.count(fix.original) != 1:
        return None
    updated_span = span.replace(fix.original, fix.replacement, 1)
    updated = lines[:start] + _keep_lines(updated_span) + lines[end:]
    if updated == lines:
        return None
    diff = "".join(
        difflib.unified_diff(
            lines, updated, fromfile=f"a/{location.path}", tofile=f"b/{location.path}"
        )
    )
    if not diff or diff.count("\n") > 400:
        return None
    return FileChange(path=location.path, diff=diff)


def _fix_is_publishable(fix: LineFix) -> bool:
    if not fix.original.strip() or fix.original == fix.replacement:
        return False
    if len(fix.original) > 4_000 or len(fix.replacement) > 4_000:
        return False
    if fix.original.count("\n") > 40 or fix.replacement.count("\n") > 40:
        return False
    return (
        redact_text(fix.original) == fix.original
        and redact_text(fix.replacement) == fix.replacement
    )


def _keep_lines(text: str) -> list[str]:
    if not text:
        return []
    parts = text.splitlines(keepends=True)
    if text.endswith(("\n", "\r")):
        return parts
    return parts


PROPOSERS: tuple[FixProposer, ...] = (DependencyBumpProposer(), ScannerPatchProposer())


def propose_fixes(findings: list[Finding], ctx: FixContext) -> list[FixProposal]:
    proposals: list[FixProposal] = []
    for proposer in PROPOSERS:
        proposals.extend(proposer.propose(findings, ctx))
    proposals.sort(key=lambda p: (_priority_rank(p.priority), p.title))
    return proposals
