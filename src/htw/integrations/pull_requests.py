"""Delivering fix proposals for human review.

Two destinations are defined:

- `ProposalWriter` writes each proposal as a Markdown file (plus a `.patch` when there
  is one) into the run's report directory. It touches nothing else and is what
  `fixes.propose: true` uses.
- `PullRequestPublisher` is the interface for opening a pull request on a git forge.
  The guardrails live in the base class so that no implementation can skip them. This
  release ships no concrete forge implementation.

Neither applies a patch to the scanned checkout, and neither merges.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from htw.agents.fixer import FixProposal
from htw.core.config import Asset
from htw.core.scope import ScopeDecision
from htw.errors import ScopeViolation

BRANCH_PREFIX = "htw/"
REVIEW_NOTICE = (
    "Proposed by HTW from scan findings. This change has not been tested or reviewed. "
    "A person must review it before it is merged; HTW never merges."
)
# Letters and digits only: git rejects `..`, `.lock`, `@{` and more in ref names.
_BRANCH_SAFE_RE = re.compile(r"[^a-z0-9]+")


def render_proposal(proposal: FixProposal) -> str:
    """Markdown body used for proposal files and pull request descriptions."""
    lines = [
        f"# {proposal.title}",
        "",
        f"> {REVIEW_NOTICE}",
        "",
        proposal.summary,
        "",
        f"- Priority: {proposal.priority}",
        f"- Kind: {proposal.kind.replace('_', ' ')}",
        f"- Proposal id: `{proposal.id}`",
        f"- Findings addressed: {', '.join(f'`{fp}`' for fp in proposal.fingerprints)}",
    ]
    if proposal.notes:
        lines += ["", "## Notes", ""] + [f"- {note}" for note in proposal.notes]
    if proposal.has_patch:
        lines += ["", "## Proposed change", "", "```diff", proposal.patch.rstrip("\n"), "```"]
    return "\n".join(lines) + "\n"


class ProposalWriter:
    """Writes proposals to disk for review. The default destination."""

    def __init__(self, directory: Path):
        self.directory = directory

    def write(self, proposals: list[FixProposal]) -> list[Path]:
        if not proposals:
            return []
        self.directory.mkdir(parents=True, exist_ok=True)
        written = []
        for proposal in proposals:
            target = self.directory / f"{proposal.id}.md"
            target.write_text(render_proposal(proposal), encoding="utf-8")
            written.append(target)
            if proposal.has_patch:
                (self.directory / f"{proposal.id}.patch").write_text(
                    proposal.patch, encoding="utf-8"
                )
        return written


@dataclass(frozen=True)
class PullRequestRef:
    url: str
    branch: str
    draft: bool = True


class PullRequestPublisher(ABC):
    """Opens a draft pull request for a proposal, for a person to review.

    Subclasses implement `_open_draft_pull_request` for one forge. They must create a
    new branch, commit only the proposal's patch, and open the pull request as a
    draft. They must not merge, approve, push to an existing branch or enable
    auto-merge.
    """

    def __init__(self, *, enabled: bool, destination_is_private: bool = False):
        self._enabled = enabled
        self._destination_is_private = destination_is_private

    def publish(
        self, proposal: FixProposal, asset: Asset, decision: ScopeDecision
    ) -> PullRequestRef:
        """Check every guardrail, then open the draft pull request."""
        if not self._enabled:
            raise ScopeViolation(
                "fix proposals are disabled (report-only mode). "
                "Set `fixes.propose: true` in the scope file to allow them."
            )
        if not decision.allowed or decision.asset_id != asset.id or proposal.asset_id != asset.id:
            raise ScopeViolation(
                f"refusing to open a pull request: asset {asset.id!r} is not authorized in scope"
            )
        if not proposal.has_patch:
            raise ScopeViolation(f"proposal {proposal.id} has no patch; nothing to open")
        if not proposal.public_safe and not self._destination_is_private:
            raise ScopeViolation(
                f"proposal {proposal.id} could disclose an unfixed weakness. It may only be "
                "published to a destination declared private (for example a private fork)."
            )
        reference = self._open_draft_pull_request(
            asset=asset,
            branch=self.branch_name(proposal),
            title=proposal.title,
            body=render_proposal(proposal),
            patch=proposal.patch,
        )
        if not reference.draft:
            raise ScopeViolation(
                "publisher returned a pull request that is not a draft; "
                "HTW only opens drafts for human review"
            )
        return reference

    @staticmethod
    def branch_name(proposal: FixProposal) -> str:
        slug = _BRANCH_SAFE_RE.sub("-", proposal.title.lower()).strip("-")[:40].strip("-")
        return f"{BRANCH_PREFIX}{proposal.id}-{slug}" if slug else f"{BRANCH_PREFIX}{proposal.id}"

    @abstractmethod
    def _open_draft_pull_request(
        self, *, asset: Asset, branch: str, title: str, body: str, patch: str
    ) -> PullRequestRef:
        """Create `branch`, commit `patch` on it and open a draft pull request."""
