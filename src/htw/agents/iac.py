"""Infrastructure-as-code agent. Files in the repository only; no cloud API."""

from __future__ import annotations

from htw.agents.base import ScannerAgent
from htw.detect.model import CLOUD, IAC, StackProfile
from htw.scanners.checkov import Checkov
from htw.scanners.kics import Kics
from htw.scanners.kube_linter import KubeLinter
from htw.scanners.targets import needed
from htw.scanners.trivy_config import TrivyConfig


class IacAgent(ScannerAgent):
    """Misconfigurations in Terraform, Kubernetes, Helm, CloudFormation and the rest.

    Checkov is preferred. Trivy config, KICS and kube-linter cover the same files when
    Checkov is not installed. None of them is given cloud credentials.
    """

    name = "iac"
    title = "Infrastructure as code"
    adapters = (Checkov(IAC), TrivyConfig("iac"), Kics(), KubeLinter())

    def needed_coverage(self, profile: StackProfile) -> dict[str, str]:
        return needed(profile, IAC)

    def not_applicable_reason(self, profile: StackProfile) -> str:
        if profile.has(CLOUD):
            return "no infrastructure-as-code files to scan; cloud accounts are not contacted"
        return "no infrastructure-as-code files detected"
