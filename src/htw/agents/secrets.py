"""Secrets agent."""

from __future__ import annotations

from htw.agents.base import ScannerAgent
from htw.detect.model import StackProfile
from htw.scanners.gitleaks import Gitleaks
from htw.scanners.trufflehog import TruffleHog


class SecretsAgent(ScannerAgent):
    """Finds credentials in files and, for git checkouts, in the commit history.

    Secret values are redacted at the source: only the location, the kind of
    credential and a fingerprint leave the scanner wrapper.
    """

    name = "secrets"
    title = "Secrets"
    adapters = (Gitleaks(), TruffleHog())

    def needed_coverage(self, profile: StackProfile) -> dict[str, str]:
        if profile.files_seen == 0:
            return {}
        scope = "files and git history" if profile.is_git_repository else "files"
        return {"secrets": f"credentials in {scope}"}

    def not_applicable_reason(self, profile: StackProfile) -> str:
        return "the asset contains no files"
