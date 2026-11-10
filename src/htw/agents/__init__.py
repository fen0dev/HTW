"""Scanner agents. Each one wraps established open-source tools behind one interface."""

from __future__ import annotations

from htw.agents.base import AgentPlan, ScannerAgent
from htw.agents.container import ContainerAgent
from htw.agents.dast import DastAgent
from htw.agents.deps_sbom import DepsSbomAgent
from htw.agents.iac import IacAgent
from htw.agents.pipeline import PipelineAgent
from htw.agents.sast import SastAgent
from htw.agents.secrets import SecretsAgent

# Order matters only for readability of reports; agents are independent.
AGENTS: tuple[ScannerAgent, ...] = (
    DepsSbomAgent(),
    SecretsAgent(),
    SastAgent(),
    ContainerAgent(),
    IacAgent(),
    PipelineAgent(),
    DastAgent(),
)

__all__ = [
    "AGENTS",
    "AgentPlan",
    "ScannerAgent",
]
