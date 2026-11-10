"""Open a draft GitHub pull request for a proposal. Never merges.

The operator's existing `gh` login is used. HTW does not create a token, does not read
one out of the repository, and does not modify the scanned working tree: the patch is
committed in a temporary clone and pushed from there.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from htw.core.runner import CommandResult
from htw.core.scope import read_git_remotes
from htw.errors import ScopeViolation, ToolError
from htw.integrations.pull_requests import PullRequestRef


class CommandRunner(Protocol):
    def which(self, binary: str) -> str | None: ...

    def run(
        self,
        argv: list[str],
        cwd: Path,
        timeout_seconds: int | None = None,
        extra_env: dict[str, str] | None = None,
        *,
        sandbox: bool | None = None,
    ) -> CommandResult: ...


def _forbid_merge(argv: list[str]) -> None:
    if "merge" in argv or "--auto" in argv or "approve" in argv:
        raise ScopeViolation(
            f"refusing to run {argv[0]} {argv[1] if len(argv) > 1 else ''}: HTW never merges or approves"
        )


def open_github_draft(
    *,
    source: Path,
    branch: str,
    title: str,
    body: str,
    patch: str,
    runner: CommandRunner,
) -> PullRequestRef:
    """Clone `source`, commit `patch` on `branch`, and open a draft pull request."""
    if runner.which("git") is None or runner.which("gh") is None:
        raise ToolError(
            "opening a pull request needs `git` and `gh` on PATH, already logged in. "
            "HTW does not create credentials."
        )
    remotes = [remote for remote in read_git_remotes(source) if remote.startswith("github.com/")]
    if len(remotes) != 1 or remotes[0].count("/") != 2:
        raise ScopeViolation(
            "a GitHub pull request needs exactly one github.com/owner/repo remote on the asset"
        )
    repo = remotes[0].split("/", 1)[1]
    temporary = Path(tempfile.mkdtemp(prefix="htw-pr-"))
    try:
        clone = temporary / "clone"
        _run(
            runner,
            ["git", "clone", "--local", "--no-hardlinks", "--", str(source), str(clone)],
            temporary,
        )
        clone.mkdir(parents=True, exist_ok=True)
        patch_path = clone / ".htw-proposal.patch"
        body_path = clone / ".htw-proposal.md"
        patch_path.write_text(patch, encoding="utf-8")
        body_path.write_text(body, encoding="utf-8")
        _run(runner, ["git", "apply", "--whitespace=nowarn", patch_path.name], clone)
        patch_path.unlink(missing_ok=True)
        _run(runner, ["git", "checkout", "-b", branch], clone)
        _run(runner, ["git", "add", "--update"], clone)
        _run(
            runner,
            ["git", "-c", "user.name=HTW", "-c", "user.email=htw@localhost", "commit", "-m", title],
            clone,
        )
        _run(
            runner, ["git", "remote", "set-url", "origin", f"https://github.com/{repo}.git"], clone
        )
        # `gh auth git-credential` uses the login the operator already has. No token is set here.
        _run(
            runner,
            [
                "git",
                "-c",
                "credential.helper=!gh auth git-credential",
                "push",
                "--set-upstream",
                "origin",
                branch,
            ],
            clone,
        )
        _run(
            runner,
            [
                "gh",
                "pr",
                "create",
                "--draft",
                "--repo",
                repo,
                "--head",
                branch,
                "--title",
                title,
                "--body-file",
                body_path.name,
            ],
            clone,
        )
        view = _run(
            runner,
            ["gh", "pr", "view", branch, "--repo", repo, "--json", "isDraft,url,autoMergeRequest"],
            clone,
        )
        try:
            payload = json.loads(view.stdout)
        except ValueError as exc:
            raise ToolError("gh pr view did not return JSON") from exc
        if payload.get("autoMergeRequest"):
            raise ScopeViolation("auto-merge was enabled on the pull request; refusing")
        if not payload.get("isDraft"):
            _run(
                runner,
                [
                    "gh",
                    "pr",
                    "close",
                    branch,
                    "--repo",
                    repo,
                    "--comment",
                    "HTW only opens drafts.",
                ],
                clone,
            )
            raise ScopeViolation("publisher returned a pull request that is not a draft")
        url = str(payload.get("url") or "")
        if not url.startswith("https://github.com/"):
            raise ToolError("gh did not return a github.com pull request URL")
        return PullRequestRef(url, branch, draft=True)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def _run(runner: CommandRunner, argv: list[str], cwd: Path) -> CommandResult:
    _forbid_merge(argv)
    # git and gh use the operator's existing login. They are not scanner processes,
    # and wrapping them would hide that login or require mounting the home directory.
    result = runner.run(argv, cwd, sandbox=False)
    if result.returncode != 0:
        detail = result.stderr_tail or result.stdout[-400:].strip() or "no output"
        raise ToolError(f"{argv[0]} failed (exit {result.returncode}): {detail}")
    return result
