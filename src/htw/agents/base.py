"""The scanner agent interface.

An agent owns one kind of check (dependencies, secrets, static analysis). It wraps one
or more established open-source tools, each behind a `ToolAdapter`, and decides which
of them to run for a detected stack.

Adding a scanner means writing an adapter and listing it in an agent. The core does
not change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from htw.core.config import AgentSettings
from htw.core.levels import ControlLevel
from htw.core.runner import ToolRunner
from htw.detect.model import StackProfile
from htw.errors import ConfigError
from htw.scanners.base import ToolAdapter


@dataclass
class AgentPlan:
    """What an agent will do for one asset, and why."""

    agent: str
    title: str
    applicable: bool
    reason: str
    selected: list[ToolAdapter] = field(default_factory=list)
    missing: list[ToolAdapter] = field(default_factory=list)
    needed: dict[str, str] = field(default_factory=dict)
    uncovered: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "applicable": self.applicable,
            "reason": self.reason,
            "tools": [adapter.name for adapter in self.selected],
            "missing_tools": [adapter.name for adapter in self.missing],
            "uncovered": sorted(self.uncovered.values()),
        }


class ScannerAgent(ABC):
    name: ClassVar[str]
    title: ClassVar[str]
    level: ClassVar[ControlLevel] = ControlLevel.L0
    # When set, a check above L1 is allowed only with a matching, unexpired approval.
    approval_control: ClassVar[str] = ""
    adapters: ClassVar[tuple[ToolAdapter, ...]]

    @abstractmethod
    def needed_coverage(self, profile: StackProfile) -> dict[str, str]:
        """Coverage keys the detected stack calls for, mapped to a human description."""

    @abstractmethod
    def not_applicable_reason(self, profile: StackProfile) -> str:
        """Why this agent has nothing to do for the detected stack."""

    def adapter(self, name: str) -> ToolAdapter:
        for adapter in self.adapters:
            if adapter.name == name:
                return adapter
        known = ", ".join(a.name for a in self.adapters)
        raise ConfigError(f"scanners.{self.name}.tools: unknown tool {name!r} (known: {known})")

    def plan(self, profile: StackProfile, settings: AgentSettings, runner: ToolRunner) -> AgentPlan:
        """Choose the tools to run.

        With `tools: auto`, adapters are tried in preference order and one is selected
        only if it covers something no earlier tool covers. A missing binary is recorded
        and the next adapter gets its chance, so the agent degrades to whatever is
        installed. An explicit `tools` list runs exactly the listed tools.
        """
        if not settings.enabled:
            return AgentPlan(self.name, self.title, False, "disabled in the scope file")
        needed = self.needed_coverage(profile)
        if not needed:
            return AgentPlan(self.name, self.title, False, self.not_applicable_reason(profile))

        explicit = settings.tools is not None
        candidates = (
            [self.adapter(name) for name in settings.tools or ()]
            if explicit
            else list(self.adapters)
        )
        plan = AgentPlan(
            self.name, self.title, True, ", ".join(sorted(set(needed.values()))), needed=needed
        )
        covered: set[str] = set()
        for adapter in candidates:
            if adapter.optional and not explicit:
                continue
            provides = adapter.coverage(profile)
            # An opt-in tool named in the scope file runs even though its coverage is
            # not part of the default plan, and therefore not part of the gaps.
            relevant = provides if adapter.optional else provides & set(needed)
            if not relevant or (not explicit and relevant <= covered):
                continue
            if adapter.available(runner):
                plan.selected.append(adapter)
                covered |= relevant & set(needed)
            else:
                plan.missing.append(adapter)
        plan.uncovered = {key: text for key, text in needed.items() if key not in covered}
        # A missing tool only matters if nothing else covered what it would have.
        plan.missing = [
            adapter
            for adapter in plan.missing
            if explicit or adapter.coverage(profile) & set(plan.uncovered)
        ]
        return plan
