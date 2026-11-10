"""CI systems with no wrapped scanner are named as gaps, not as a missing install."""

from __future__ import annotations

from pathlib import Path

from htw.agents.pipeline import PipelineAgent
from htw.agents.reporting import gap_markdown, gap_notice
from htw.core.config import AgentSettings
from htw.detect import detect_stack
from htw.detect.model import CI_CD, StackProfile
from htw.detect.signatures import FILENAME_SIGNATURES, PATH_SIGNATURES, SUFFIX_SIGNATURES
from htw.scanners.targets import PIPELINE_TARGETS, uncovered_pipelines

from .conftest import write_tree
from .test_agents import runner


def _detected_ci_names() -> set[str]:
    names: set[str] = set()
    for signatures in FILENAME_SIGNATURES.values():
        for signature in signatures:
            if signature.category == CI_CD:
                names.add(signature.name)
    for _suffix, signature in SUFFIX_SIGNATURES:
        if signature.category == CI_CD:
            names.add(signature.name)
    for _pattern, signature in PATH_SIGNATURES:
        if signature.category == CI_CD:
            names.add(signature.name)
    return names


def test_every_detected_ci_system_is_wrapped_or_declared_uncovered() -> None:
    profile = StackProfile()
    for name in _detected_ci_names():
        profile.record(CI_CD, name, "marker")

    gaps = uncovered_pipelines(profile)
    covered = {name for target in PIPELINE_TARGETS for name in target.names}
    declared = {value.split(": ", 1)[1] for value in gaps.values()}

    assert declared == _detected_ci_names() - covered
    assert covered.isdisjoint(declared)
    assert all(value.startswith("no wrapped scanner: ") for value in gaps.values())
    # The systems Checkov and zizmor actually wrap stay out of that list.
    assert {
        "GitHub Actions",
        "GitLab CI",
        "CircleCI",
        "Azure Pipelines",
        "Bitbucket Pipelines",
    } <= covered


def test_jenkins_stays_unscanned_when_checkov_and_zizmor_are_installed(tmp_path: Path) -> None:
    root = write_tree(
        tmp_path,
        {
            "Jenkinsfile": "pipeline { agent any }\n",
            ".gitlab-ci.yml": "test:\n  script: echo\n",
            ".github/workflows/ci.yml": "on: push\njobs: {}\n",
        },
    )
    result = PipelineAgent().plan(
        detect_stack(root),
        AgentSettings(),
        runner("zizmor", "checkov"),
    )

    assert [adapter.name for adapter in result.selected] == ["zizmor", "checkov"]
    assert result.uncovered == {"cicd:uncovered:jenkins": "no wrapped scanner: Jenkins"}
    notice = gap_notice(result.uncovered["cicd:uncovered:jenkins"])
    paragraph = gap_markdown(result.uncovered["cicd:uncovered:jenkins"])
    assert notice == "not scanned: Jenkins (no wrapped scanner)"
    assert "does not scan it" in paragraph
    assert "no installed scanner" not in paragraph


def test_a_tool_that_exists_is_still_described_as_not_installed(tmp_path: Path) -> None:
    root = write_tree(tmp_path, {".gitlab-ci.yml": "test:\n  script: echo\n"})
    result = PipelineAgent().plan(detect_stack(root), AgentSettings(), runner())

    assert result.uncovered == {"cicd:gitlab": "GitLab CI"}
    assert gap_notice("GitLab CI") == "not covered: GitLab CI"
    assert "no installed scanner" in gap_markdown("GitLab CI")
