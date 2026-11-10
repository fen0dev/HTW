"""The record of one asset's scan, shared by the orchestrator and reporting."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from htw.agents.base import AgentPlan
from htw.agents.fixer import FixProposal
from htw.core.config import Asset
from htw.core.finding import Finding
from htw.core.scope import ScopeDecision
from htw.core.store import Delta
from htw.core.suppressions import Suppression
from htw.detect import StackProfile
from htw.scanners.base import STATUS_ERROR, ToolOutcome

REFUSED = "refused"
COMPLETE = "complete"
INCOMPLETE = "incomplete"
STOPPED = "stopped"


@dataclass
class AssetRun:
    """Everything that happened for one asset in one invocation."""

    asset: Asset
    decision: ScopeDecision
    status: str
    run_id: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None
    profile: StackProfile | None = None
    plans: list[AgentPlan] = field(default_factory=list)
    outcomes: list[ToolOutcome] = field(default_factory=list)
    delta: Delta = field(default_factory=Delta)
    suppressed: dict[str, Suppression] = field(default_factory=dict)
    expired_suppressions: list[Suppression] = field(default_factory=list)
    proposals: list[FixProposal] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    report_dir: Path | None = None
    fixes_enabled: bool = False

    def visible(self, findings: list[Finding]) -> list[Finding]:
        return [f for f in findings if f.fingerprint not in self.suppressed]

    @property
    def gaps(self) -> list[str]:
        """Coverage the stack calls for that no installed scanner provided."""
        return [text for plan in self.plans for text in sorted(set(plan.uncovered.values()))]

    @property
    def has_errors(self) -> bool:
        return any(outcome.status == STATUS_ERROR for outcome in self.outcomes)
