"""Container agent: Dockerfiles and Compose files, never a registry pull."""

from __future__ import annotations

from htw.agents.base import ScannerAgent
from htw.detect.model import CONTAINER, StackProfile
from htw.scanners.checkov import Checkov
from htw.scanners.dockle import Dockle
from htw.scanners.hadolint import Hadolint
from htw.scanners.targets import needed
from htw.scanners.trivy_config import TrivyConfig


class ContainerAgent(ScannerAgent):
    """Static checks of container build files.

    Hadolint lints Dockerfiles. Trivy config (then Checkov) looks for misconfigurations.
    Dockle is opt-in and accepts only a local image archive.
    """

    name = "container"
    title = "Containers"
    adapters = (Hadolint(), TrivyConfig("container"), Checkov(CONTAINER), Dockle())

    def needed_coverage(self, profile: StackProfile) -> dict[str, str]:
        return needed(profile, CONTAINER)

    def not_applicable_reason(self, profile: StackProfile) -> str:
        del profile
        return "no Dockerfile or Compose file detected"
