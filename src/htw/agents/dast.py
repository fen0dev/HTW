"""Dynamic testing. Refused unless a current human approval names the staging URL."""

from __future__ import annotations

from htw.agents.base import AgentPlan, ScannerAgent
from htw.core.config import AgentSettings
from htw.core.levels import ControlLevel
from htw.core.runner import ToolRunner
from htw.detect.model import StackProfile
from htw.scanners.nuclei import Nuclei
from htw.scanners.zap import Zap


class DastAgent(ScannerAgent):
    """ZAP baseline against one approved staging URL. Nuclei is opt-in.

    There is no scanning of an address that was not named, in an unexpired approval,
    as `runtime.staging_url`. Live systems that are not that URL are out of scope.
    """

    name = "dast"
    title = "Dynamic testing (DAST)"
    level = ControlLevel.L2
    approval_control = "dast"
    adapters = (Zap(), Nuclei())

    def needed_coverage(self, profile: StackProfile) -> dict[str, str]:
        del profile
        return {"dast:baseline": "dynamic testing of the declared staging URL"}

    def not_applicable_reason(self, profile: StackProfile) -> str:
        del profile
        return "no staging URL declared"

    def plan(self, profile: StackProfile, settings: AgentSettings, runner: ToolRunner) -> AgentPlan:
        if not settings.options.get("staging_url"):
            return AgentPlan(self.name, self.title, False, self.not_applicable_reason(profile))
        return super().plan(profile, settings, runner)
