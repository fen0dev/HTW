"""Dependencies and SBOM agent."""

from __future__ import annotations

from htw.agents.base import ScannerAgent
from htw.detect.model import PACKAGE_MANAGER, StackProfile
from htw.scanners.grype import Grype
from htw.scanners.osv_scanner import OsvScanner
from htw.scanners.syft import Syft
from htw.scanners.trivy import Trivy


class DepsSbomAgent(ScannerAgent):
    """Builds an SBOM and matches the dependencies against vulnerability advisories.

    Syft runs first so that Grype can match the SBOM it produced. Grype is preferred
    for matching because it works from a local database; OSV-Scanner and Trivy are the
    fallbacks.
    """

    name = "deps_sbom"
    title = "Dependencies and SBOM"
    adapters = (Syft(), Grype(), OsvScanner(), Trivy())

    def needed_coverage(self, profile: StackProfile) -> dict[str, str]:
        if not profile.has(PACKAGE_MANAGER):
            return {}
        managers = ", ".join(sorted(profile.names(PACKAGE_MANAGER)))
        return {
            "sbom": f"software bill of materials ({managers})",
            "vulns": f"known vulnerabilities in dependencies ({managers})",
        }

    def not_applicable_reason(self, profile: StackProfile) -> str:
        return "no package manifest or lockfile detected"
