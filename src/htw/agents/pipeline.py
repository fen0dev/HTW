"""CI/CD agent: workflow files in the repository, not a running pipeline."""

from __future__ import annotations

from htw.agents.base import ScannerAgent
from htw.detect.model import CI_CD, StackProfile
from htw.scanners.checkov import Checkov
from htw.scanners.cosign import Cosign
from htw.scanners.scorecard import Scorecard
from htw.scanners.targets import needed, uncovered_pipelines
from htw.scanners.zizmor import Zizmor


class PipelineAgent(ScannerAgent):
    """Risks in CI configuration and, when asked, signature and Scorecard checks.

    zizmor audits GitHub Actions offline. Checkov covers the other CI systems it
    knows. Scorecard and cosign are opt-in: the default scan does not call them.
    """

    name = "pipeline"
    title = "CI/CD and supply chain"
    adapters = (Zizmor(), Checkov(CI_CD), Scorecard(), Cosign())

    def needed_coverage(self, profile: StackProfile) -> dict[str, str]:
        return {**needed(profile, CI_CD), **uncovered_pipelines(profile)}

    def not_applicable_reason(self, profile: StackProfile) -> str:
        del profile
        return "no CI/CD configuration detected"
