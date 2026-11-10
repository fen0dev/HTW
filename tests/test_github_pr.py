"""Draft pull requests are opened from a clone. The scanned tree is not modified."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from htw.core.config import load_config
from htw.core.levels import ControlLevel
from htw.core.runner import CommandResult
from htw.core.scope import ScopeDecision
from htw.errors import ScopeViolation, ToolError
from htw.integrations.github import open_github_draft
from htw.integrations.pull_requests import GitHubCliPublisher

from .conftest import scope_yaml
from .test_fixer import proposal


class RecordingRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], Path]] = []

    def which(self, binary: str) -> str | None:
        return f"/fake/{binary}"

    def run(self, argv, cwd, timeout_seconds=None, extra_env=None) -> CommandResult:
        argv = list(argv)
        self.calls.append((argv, Path(cwd)))
        if argv[:3] == ["gh", "pr", "view"]:
            payload = {
                "isDraft": True,
                "url": "https://github.com/acme/app/pull/7",
                "autoMergeRequest": None,
            }
            return CommandResult(tuple(argv), 0, json.dumps(payload), "", 0.01)
        return CommandResult(tuple(argv), 0, "", "", 0.01)


def test_opening_a_pull_request_is_a_draft_push_and_does_not_merge(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    source.mkdir()
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = https://github.com/acme/app.git\n', encoding="utf-8"
    )
    (source / "requirements.txt").write_text("jinja2==2.10\n", encoding="utf-8")
    before = (source / "requirements.txt").read_text()
    runner = RecordingRunner()

    reference = open_github_draft(
        source=source,
        branch="htw/fix-abc-upgrade",
        title="Upgrade jinja2",
        body="Review this.\n",
        patch="--- a/requirements.txt\n+++ b/requirements.txt\n",
        runner=runner,
    )

    assert reference.draft and reference.url.endswith("/pull/7")
    assert (source / "requirements.txt").read_text() == before
    flat = [arg for argv, _cwd in runner.calls for arg in argv]
    assert "merge" not in flat and "--auto" not in flat and "approve" not in flat
    create = next(argv for argv, _cwd in runner.calls if argv[:3] == ["gh", "pr", "create"])
    assert "--draft" in create
    assert all(cwd != source for _argv, cwd in runner.calls)


def test_a_non_draft_pull_request_is_closed(tmp_path: Path) -> None:
    source = tmp_path / "repo"
    source.mkdir()
    (source / ".git").mkdir()
    (source / ".git" / "config").write_text(
        '[remote "origin"]\n\turl = git@github.com:acme/app.git\n', encoding="utf-8"
    )
    runner = RecordingRunner()

    def run(argv, cwd, timeout_seconds=None, extra_env=None):
        argv = list(argv)
        runner.calls.append((argv, Path(cwd)))
        if argv[:3] == ["gh", "pr", "view"]:
            payload = {"isDraft": False, "url": "https://github.com/acme/app/pull/8"}
            return CommandResult(tuple(argv), 0, json.dumps(payload), "", 0.01)
        return CommandResult(tuple(argv), 0, "", "", 0.01)

    runner.run = run  # type: ignore[method-assign]
    with pytest.raises(ScopeViolation, match="not a draft"):
        open_github_draft(
            source=source,
            branch="htw/fix-abc",
            title="Upgrade",
            body="body",
            patch="patch",
            runner=runner,
        )
    close = next(argv for argv, _cwd in runner.calls if argv[:3] == ["gh", "pr", "close"])
    assert "merge" not in close


def test_publisher_refuses_without_git_credentials_being_invented(tmp_path: Path) -> None:
    (tmp_path / "htw.yaml").write_text(scope_yaml([{"id": "app", "path": "."}]), encoding="utf-8")
    asset = load_config(tmp_path / "htw.yaml").assets[0]

    class Empty:
        def which(self, binary: str) -> None:
            return None

        def run(self, *args, **kwargs):
            raise AssertionError("should not run")

    publisher = GitHubCliPublisher(enabled=True, runner=Empty())  # type: ignore[arg-type]
    with pytest.raises(ToolError, match="does not create credentials"):
        publisher.publish(proposal(), asset, ScopeDecision("app", ControlLevel.L0))
