"""Detected components mapped to the static checks that cover them.

The maps are the contract between stack detection and the container, IaC and pipeline
agents. A component with no entry is still reported: the agent asks for coverage and,
when no wrapped tool provides it, the gap shows up in the report.
"""

from __future__ import annotations

from dataclasses import dataclass

from htw.detect.model import CI_CD, CONTAINER, IAC, StackProfile


@dataclass(frozen=True)
class Target:
    key: str
    description: str
    names: frozenset[str]
    checkov: str | None = None
    trivy_types: frozenset[str] = frozenset()
    kics: bool = False
    kube_linter: bool = False
    zizmor: bool = False


CONTAINER_TARGETS: tuple[Target, ...] = (
    Target(
        "dockerfile-lint",
        "Dockerfile lint",
        names=frozenset({"Dockerfile"}),
    ),
    Target(
        "dockerfile-config",
        "Dockerfile misconfiguration",
        names=frozenset({"Dockerfile"}),
        checkov="dockerfile",
        trivy_types=frozenset({"dockerfile"}),
        kics=True,
    ),
    Target(
        "compose-config",
        "Docker Compose misconfiguration",
        names=frozenset({"Docker Compose"}),
        trivy_types=frozenset({"dockercompose", "compose", "docker-compose"}),
    ),
)

IAC_TARGETS: tuple[Target, ...] = (
    Target(
        "iac:terraform",
        "Terraform",
        names=frozenset({"Terraform", "Terragrunt", "CDK for Terraform"}),
        checkov="terraform",
        trivy_types=frozenset({"terraform", "terragrunt"}),
        kics=True,
    ),
    Target(
        "iac:cloudformation",
        "CloudFormation",
        names=frozenset({"CloudFormation", "AWS SAM"}),
        checkov="cloudformation",
        trivy_types=frozenset({"cloudformation"}),
        kics=True,
    ),
    Target(
        "iac:kubernetes",
        "Kubernetes and Helm",
        names=frozenset({"Kubernetes", "Helm", "Kustomize", "Crossplane"}),
        checkov="kubernetes",
        trivy_types=frozenset({"kubernetes", "helm", "kustomize"}),
        kics=True,
        kube_linter=True,
    ),
    Target(
        "iac:ansible",
        "Ansible",
        names=frozenset({"Ansible"}),
        checkov="ansible",
        trivy_types=frozenset({"ansible"}),
        kics=True,
    ),
    Target(
        "iac:serverless",
        "Serverless Framework",
        names=frozenset({"Serverless Framework"}),
        checkov="serverless",
    ),
    Target(
        "iac:arm",
        "ARM templates",
        names=frozenset({"ARM templates"}),
        checkov="arm",
    ),
    Target(
        "iac:bicep",
        "Bicep",
        names=frozenset({"Bicep"}),
        checkov="bicep",
    ),
)

PIPELINE_TARGETS: tuple[Target, ...] = (
    Target(
        "cicd:github-actions",
        "GitHub Actions workflows",
        names=frozenset({"GitHub Actions"}),
        checkov="github_actions",
        zizmor=True,
    ),
    Target(
        "cicd:gitlab",
        "GitLab CI",
        names=frozenset({"GitLab CI"}),
        checkov="gitlab_ci",
    ),
    Target(
        "cicd:azure-pipelines",
        "Azure Pipelines",
        names=frozenset({"Azure Pipelines"}),
        checkov="azure_pipelines",
    ),
    Target(
        "cicd:bitbucket",
        "Bitbucket Pipelines",
        names=frozenset({"Bitbucket Pipelines"}),
        checkov="bitbucket_pipelines",
    ),
    Target(
        "cicd:circleci",
        "CircleCI",
        names=frozenset({"CircleCI"}),
        checkov="circleci_pipelines",
    ),
)

_BY_CATEGORY = {
    CONTAINER: CONTAINER_TARGETS,
    IAC: IAC_TARGETS,
    CI_CD: PIPELINE_TARGETS,
}


def selected(profile: StackProfile, category: str) -> list[Target]:
    names = profile.names(category)
    return [target for target in _BY_CATEGORY[category] if target.names & names]


def needed(profile: StackProfile, category: str) -> dict[str, str]:
    """Coverage keys the detected components call for."""
    result: dict[str, str] = {}
    for target in selected(profile, category):
        result.setdefault(target.key, target.description)
    return result


def uncovered_pipelines(profile: StackProfile) -> dict[str, str]:
    """CI systems the detector recognized and none of the wrapped tools scan.

    The value is a stable prefix plus the detected name. Reporting uses the prefix
    so the gap is not described as a missing installation: installing Checkov does
    not cover these systems, and HTW does not invent a scanner for them.
    """
    covered = {name for target in PIPELINE_TARGETS for name in target.names}
    extra: dict[str, str] = {}
    for name in sorted(profile.names(CI_CD) - covered):
        slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in name).strip("-")
        extra[f"cicd:uncovered:{slug}"] = f"no wrapped scanner: {name}"
    return extra


def checkov_frameworks(profile: StackProfile, category: str) -> list[str]:
    frameworks = []
    for target in selected(profile, category):
        if target.checkov and target.checkov not in frameworks:
            frameworks.append(target.checkov)
    # Helm and Kustomize have their own Checkov frameworks; the shared key above uses
    # `kubernetes` as the fallback that is always valid for that coverage.
    names = profile.names(category)
    if category == IAC:
        if "Helm" in names:
            frameworks.append("helm")
        if "Kustomize" in names:
            frameworks.append("kustomize")
    return frameworks


def keys_for_checkov(profile: StackProfile, category: str) -> set[str]:
    return {target.key for target in selected(profile, category) if target.checkov}


def keys_for_trivy(profile: StackProfile, category: str) -> set[str]:
    return {target.key for target in selected(profile, category) if target.trivy_types}


def trivy_types(profile: StackProfile, category: str) -> set[str]:
    return {
        kind
        for target in selected(profile, category)
        if target.trivy_types
        for kind in target.trivy_types
    }


def keys_for_kics(profile: StackProfile) -> set[str]:
    return {target.key for target in selected(profile, IAC) if target.kics}


def keys_for_kube_linter(profile: StackProfile) -> set[str]:
    return {target.key for target in selected(profile, IAC) if target.kube_linter}


def keys_for_zizmor(profile: StackProfile) -> set[str]:
    return {target.key for target in selected(profile, CI_CD) if target.zizmor}
