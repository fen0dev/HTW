"""Static analysis (SAST) agent."""

from __future__ import annotations

from htw.agents.base import ScannerAgent
from htw.detect.model import StackProfile
from htw.scanners.bandit import Bandit
from htw.scanners.gosec import Gosec
from htw.scanners.semgrep import Semgrep

# Markup, data and query languages are not what code-level static analysis is for.
NOT_ANALYSED = frozenset({"SQL"})


class SastAgent(ScannerAgent):
    """Static analysis of source code.

    Semgrep covers most languages. Bandit (Python) and gosec (Go) are used for the
    languages Semgrep is not available to cover.
    """

    name = "sast"
    title = "Static analysis (SAST)"
    adapters = (Semgrep(), Bandit(), Gosec())

    def needed_coverage(self, profile: StackProfile) -> dict[str, str]:
        return {
            f"sast:{language}": f"static analysis of {language} code"
            for language in sorted(profile.languages - NOT_ANALYSED)
        }

    def not_applicable_reason(self, profile: StackProfile) -> str:
        return "no source code in a programming language detected"
