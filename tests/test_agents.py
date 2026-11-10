"""Scanner selection: which tools run for a detected stack, and what happens when
some of them are not installed."""

from __future__ import annotations

from pathlib import Path

import pytest

from htw.agents import AGENTS
from htw.agents.container import ContainerAgent
from htw.agents.dast import DastAgent
from htw.agents.deps_sbom import DepsSbomAgent
from htw.agents.iac import IacAgent
from htw.agents.pipeline import PipelineAgent
from htw.agents.sast import SastAgent
from htw.agents.secrets import SecretsAgent
from htw.core.config import AgentSettings
from htw.detect import detect_stack
from htw.errors import ConfigError

from .conftest import STACKS, VULNERABLE_APP, FakeRunner, write_tree


def runner(*installed: str) -> FakeRunner:
    return FakeRunner(dict.fromkeys(installed, lambda argv, cwd: (0, "")))


def plan(agent, stack: Path, installed: tuple[str, ...], settings: AgentSettings | None = None):
    result = agent.plan(detect_stack(stack), settings or AgentSettings(), runner(*installed))  # type: ignore[arg-type]
    return (
        [a.name for a in result.selected],
        [a.name for a in result.missing],
        sorted(result.uncovered),
    )


ALL = (
    "syft",
    "grype",
    "osv-scanner",
    "trivy",
    "gitleaks",
    "trufflehog",
    "semgrep",
    "bandit",
    "gosec",
    "go",
)


def test_agents_and_their_tools() -> None:
    assert [(a.name, [t.name for t in a.adapters]) for a in AGENTS] == [
        ("deps_sbom", ["syft", "grype", "osv-scanner", "trivy"]),
        ("secrets", ["gitleaks", "trufflehog"]),
        ("sast", ["semgrep", "bandit", "gosec"]),
        ("container", ["hadolint", "trivy-config", "checkov", "dockle"]),
        ("iac", ["checkov", "trivy-config", "kics", "kube-linter"]),
        ("pipeline", ["zizmor", "checkov", "scorecard", "cosign"]),
        ("dast", ["zap", "nuclei"]),
    ]
    static = [agent for agent in AGENTS if agent.name != "dast"]
    assert all(agent.level.name == "L0" for agent in static)
    assert all(tool.level.name == "L0" for agent in static for tool in agent.adapters)
    dast = next(agent for agent in AGENTS if agent.name == "dast")
    assert dast.level.name == "L2"
    assert all(tool.level.name == "L2" for tool in dast.adapters)


def test_with_everything_installed_one_tool_per_job_is_selected() -> None:
    assert plan(DepsSbomAgent(), VULNERABLE_APP, ALL) == (["syft", "grype"], [], [])
    assert plan(SecretsAgent(), VULNERABLE_APP, ALL) == (["gitleaks"], [], [])
    assert plan(SastAgent(), VULNERABLE_APP, ALL) == (["semgrep"], [], [])


@pytest.mark.parametrize(
    ("installed", "expected"),
    [
        (("syft", "osv-scanner"), (["syft", "osv-scanner"], [], [])),
        (("trivy",), (["trivy"], ["syft"], ["sbom"])),
        (("syft",), (["syft"], ["grype", "osv-scanner", "trivy"], ["vulns"])),
        ((), ([], ["syft", "grype", "osv-scanner", "trivy"], ["sbom", "vulns"])),
    ],
)
def test_dependency_agent_falls_back_to_what_is_installed(installed, expected) -> None:
    assert plan(DepsSbomAgent(), VULNERABLE_APP, installed) == expected


@pytest.mark.parametrize(
    ("installed", "expected"),
    [
        (("trufflehog",), (["trufflehog"], [], [])),
        ((), ([], ["gitleaks", "trufflehog"], ["secrets"])),
    ],
)
def test_secrets_agent_falls_back(installed, expected) -> None:
    assert plan(SecretsAgent(), VULNERABLE_APP, installed) == expected


@pytest.mark.parametrize(
    ("installed", "expected"),
    [
        # vulnerable-app is Python + JavaScript + Go.
        (("bandit", "gosec", "go"), (["bandit", "gosec"], ["semgrep"], ["sast:JavaScript"])),
        (("bandit",), (["bandit"], ["semgrep", "gosec"], ["sast:Go", "sast:JavaScript"])),
        # gosec without the Go toolchain cannot run.
        (
            ("gosec",),
            ([], ["semgrep", "bandit", "gosec"], ["sast:Go", "sast:JavaScript", "sast:Python"]),
        ),
        (("semgrep", "bandit", "gosec", "go"), (["semgrep"], [], [])),
    ],
)
def test_sast_agent_covers_languages_with_what_is_installed(installed, expected) -> None:
    assert plan(SastAgent(), VULNERABLE_APP, installed) == expected


def test_languages_no_tool_supports_are_reported_as_gaps() -> None:
    selected, missing, uncovered = plan(SastAgent(), STACKS / "polyglot", ALL)

    assert selected == ["semgrep"]
    assert missing == []
    assert uncovered == ["sast:Perl", "sast:PowerShell"]
    # SQL is detected but is not something code-level static analysis is asked to cover.
    profile = detect_stack(STACKS / "polyglot")
    assert "SQL" in profile.languages
    assert "sast:SQL" not in SastAgent().needed_coverage(profile)


def test_agents_are_not_applicable_to_stacks_they_have_nothing_for(tmp_path: Path) -> None:
    docs = detect_stack(STACKS / "docs-only")
    empty = detect_stack(tmp_path)
    everything = runner(*ALL)

    deps = DepsSbomAgent().plan(docs, AgentSettings(), everything)  # type: ignore[arg-type]
    sast = SastAgent().plan(docs, AgentSettings(), everything)  # type: ignore[arg-type]
    secrets = SecretsAgent().plan(docs, AgentSettings(), everything)  # type: ignore[arg-type]
    nothing = SecretsAgent().plan(empty, AgentSettings(), everything)  # type: ignore[arg-type]

    assert (deps.applicable, deps.reason) == (False, "no package manifest or lockfile detected")
    assert (sast.applicable, sast.reason) == (
        False,
        "no source code in a programming language detected",
    )
    # Documentation can still hold credentials.
    assert secrets.applicable and [a.name for a in secrets.selected] == ["gitleaks"]
    assert (nothing.applicable, nothing.reason) == (False, "the asset contains no files")


def test_secret_scope_mentions_history_only_for_git_checkouts(tmp_path: Path) -> None:
    plain = write_tree(tmp_path / "plain", {"a.txt": "x\n"})
    checkout = write_tree(tmp_path / "checkout", {"a.txt": "x\n", ".git/config": ""})

    assert SecretsAgent().needed_coverage(detect_stack(plain)) == {
        "secrets": "credentials in files"
    }
    assert SecretsAgent().needed_coverage(detect_stack(checkout)) == {
        "secrets": "credentials in files and git history"
    }


def test_an_explicit_tool_list_runs_exactly_those_tools() -> None:
    settings = AgentSettings(tools=("semgrep", "bandit"))

    assert plan(SastAgent(), VULNERABLE_APP, ALL, settings) == (["semgrep", "bandit"], [], [])
    assert plan(SastAgent(), VULNERABLE_APP, ("bandit",), settings) == (
        ["bandit"], ["semgrep"], ["sast:Go", "sast:JavaScript"],
    )  # fmt: skip
    # A listed tool that does not apply to this stack is not run.
    assert plan(SastAgent(), STACKS / "node-monorepo", ALL, AgentSettings(tools=("bandit",))) == (
        [], [], ["sast:JavaScript", "sast:TypeScript"],
    )  # fmt: skip


def test_unknown_tools_and_disabled_agents() -> None:
    profile = detect_stack(VULNERABLE_APP)

    with pytest.raises(
        ConfigError, match=r"unknown tool 'nessus' \(known: semgrep, bandit, gosec\)"
    ):
        SastAgent().plan(profile, AgentSettings(tools=("nessus",)), runner(*ALL))  # type: ignore[arg-type]

    disabled = SastAgent().plan(profile, AgentSettings(enabled=False), runner(*ALL))  # type: ignore[arg-type]
    assert (disabled.applicable, disabled.reason) == (False, "disabled in the scope file")
    assert disabled.to_dict()["tools"] == []


@pytest.mark.parametrize(
    ("stack", "deps", "sast"),
    [
        ("python-service", ["syft", "grype"], ["semgrep"]),
        ("node-monorepo", ["syft", "grype"], ["semgrep"]),
        ("go-kubernetes", ["syft", "grype"], ["semgrep"]),
        ("java-terraform-aws", ["syft", "grype"], ["semgrep"]),
        ("polyglot", ["syft", "grype"], ["semgrep"]),
        ("docs-only", [], []),
        ("lookalikes", [], []),
    ],
)
def test_plan_for_every_fixture_stack(stack: str, deps: list[str], sast: list[str]) -> None:
    assert plan(DepsSbomAgent(), STACKS / stack, ALL)[0] == deps
    assert plan(SastAgent(), STACKS / stack, ALL)[0] == sast
    assert plan(SecretsAgent(), STACKS / stack, ALL)[0] == ["gitleaks"]


STATIC = (
    "hadolint",
    "trivy",
    "checkov",
    "kics",
    "kube-linter",
    "zizmor",
    "scorecard",
    "cosign",
    "dockle",
    "zap-baseline.py",
    "nuclei",
)


def test_container_iac_and_pipeline_follow_the_detected_files() -> None:
    installed = ALL + STATIC
    # python-service has a Dockerfile, Compose and GitHub Actions, and no IaC.
    assert plan(ContainerAgent(), STACKS / "python-service", installed)[0] == [
        "hadolint",
        "trivy-config",
    ]
    assert plan(IacAgent(), STACKS / "python-service", installed) == (
        [],
        [],
        [],
    )
    assert (
        not IacAgent()
        .plan(detect_stack(STACKS / "python-service"), AgentSettings(), runner(*installed))
        .applicable
    )
    assert plan(PipelineAgent(), STACKS / "python-service", installed)[0] == ["zizmor"]

    # Terraform and Kubernetes are one Checkov run; zizmor does not apply.
    assert plan(IacAgent(), STACKS / "java-terraform-aws", installed)[0] == ["checkov"]
    assert "zizmor" not in plan(PipelineAgent(), STACKS / "java-terraform-aws", installed)[0]


def test_static_agents_fall_back_when_the_preferred_tool_is_missing() -> None:
    assert plan(ContainerAgent(), STACKS / "python-service", ("checkov",))[0] == ["checkov"]
    assert plan(IacAgent(), STACKS / "go-kubernetes", ("kube-linter",))[0] == ["kube-linter"]
    selected, _missing, uncovered = plan(PipelineAgent(), STACKS / "python-service", ("checkov",))
    assert selected == ["checkov"]
    assert uncovered == []


def test_opt_in_tools_are_not_part_of_the_default_plan() -> None:
    installed = ALL + STATIC
    selected, missing, uncovered = plan(PipelineAgent(), STACKS / "python-service", installed)
    assert "scorecard" not in selected and "cosign" not in selected
    assert "scorecard" not in missing and "supply-chain:scorecard" not in uncovered

    explicit = plan(
        PipelineAgent(),
        STACKS / "python-service",
        installed,
        AgentSettings(tools=("zizmor", "scorecard")),
    )
    assert explicit[0] == ["zizmor", "scorecard"]


def test_dast_is_not_applicable_without_a_staging_url() -> None:
    result = DastAgent().plan(
        detect_stack(VULNERABLE_APP), AgentSettings(), runner("zap-baseline.py")
    )
    assert result.applicable is False
    assert result.reason == "no staging URL declared"


def test_dast_with_a_staging_url_selects_zap_and_not_nuclei() -> None:
    settings = AgentSettings(options={"staging_url": "https://staging.example.invalid"})
    selected, missing, uncovered = plan(
        DastAgent(), VULNERABLE_APP, ("zap-baseline.py", "nuclei"), settings
    )
    assert selected == ["zap"]
    assert missing == [] and uncovered == []
