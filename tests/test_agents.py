"""Scanner selection: which tools run for a detected stack, and what happens when
some of them are not installed."""

from __future__ import annotations

from pathlib import Path

import pytest

from htw.agents import AGENTS
from htw.agents.deps_sbom import DepsSbomAgent
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
    ]
    # Phase 1 is static analysis only.
    assert all(a.level.name == "L0" for a in AGENTS)
    assert all(t.level.name == "L0" for a in AGENTS for t in a.adapters)


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
