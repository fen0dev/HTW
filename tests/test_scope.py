from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from htw.core.config import load_config
from htw.core.levels import ControlLevel
from htw.core.scope import (
    KillSwitch,
    ScopeGuard,
    find_git_dir,
    normalize_remote,
    read_git_remotes,
    remote_matches,
)
from htw.errors import KillSwitchEngaged

from .conftest import NOW

GIT_CONFIG = """\
[core]
\trepositoryformatversion = 0
[remote "origin"]
\turl = https://x-access-token:FAKE-TOKEN-VALUE@github.com/Acme/Payments.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[remote "mirror"]
\turl = git@gitlab.acme.invalid:pay/payments.git
[branch "main"]
\tremote = origin
\turl = https://not-a-remote.invalid/x/y
"""


def fake_checkout(path: Path, config: str = GIT_CONFIG) -> Path:
    (path / ".git").mkdir(parents=True)
    (path / ".git" / "config").write_text(config, encoding="utf-8")
    return path


def repo_scope(tmp_path: Path, remote: str, **overrides: str) -> Path:
    values = {
        "expires": "2027-01-01",
        "authorized_on": "2026-01-01",
        "max_level": "L0",
        "limits": "",
    }
    values.update(overrides)
    scope = tmp_path / "htw.yaml"
    scope.write_text(
        f"""\
version: 1
assets:
  - id: payments
    type: repository
    path: checkout
    owner: payments-team
    max_level: {values["max_level"]}
    ownership:
      git_remote: {remote}
    authorization:
      authorized_by: Jane Doe
      authorized_on: {values["authorized_on"]}
      expires_on: {values["expires"]}
{values["limits"]}""",
        encoding="utf-8",
    )
    return scope


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/Acme/Payments.git", "github.com/acme/payments"),
        ("https://github.com/acme/payments", "github.com/acme/payments"),
        ("https://user:s3cr3t@github.com/acme/payments.git", "github.com/acme/payments"),
        ("git@github.com:acme/payments.git", "github.com/acme/payments"),
        ("ssh://git@github.com:22/acme/payments.git", "github.com/acme/payments"),
        (
            "https://gitlab.acme.invalid:8443/group/sub/repo.git/",
            "gitlab.acme.invalid/group/sub/repo",
        ),
        ("", None),
        ("/local/path/only", None),
    ],
)
def test_normalize_remote(url: str, expected: str | None) -> None:
    assert normalize_remote(url) == expected


def test_remote_credentials_never_survive_normalization(tmp_path: Path) -> None:
    remotes = read_git_remotes(fake_checkout(tmp_path / "checkout"))

    assert remotes == ["github.com/acme/payments", "gitlab.acme.invalid/pay/payments"]
    assert "FAKE-TOKEN-VALUE" not in " ".join(remotes)


def test_remotes_are_found_from_a_subdirectory_and_a_worktree(tmp_path: Path) -> None:
    checkout = fake_checkout(tmp_path / "checkout")
    nested = checkout / "services" / "api"
    nested.mkdir(parents=True)
    assert read_git_remotes(nested) == read_git_remotes(checkout)

    worktree = tmp_path / "worktree"
    worktree.mkdir()
    (worktree / ".git").write_text(f"gitdir: {checkout / '.git'}\n", encoding="utf-8")
    assert find_git_dir(worktree) == checkout / ".git"
    assert read_git_remotes(worktree) == read_git_remotes(checkout)


def test_remote_matching_is_case_insensitive_and_supports_wildcards() -> None:
    assert remote_matches("github.com/acme/payments", "github.com/Acme/Payments")
    assert remote_matches("github.com/acme/payments", "github.com/acme/*")
    assert not remote_matches("github.com/evil/payments", "github.com/acme/*")
    assert not remote_matches("github.com/acme-evil/payments", "github.com/acme/*")


def test_matching_remote_is_allowed_with_evidence(tmp_path: Path) -> None:
    fake_checkout(tmp_path / "checkout")
    asset = load_config(repo_scope(tmp_path, "github.com/acme/payments")).assets[0]

    decision = ScopeGuard(NOW).check(asset)

    assert decision.allowed
    assert decision.reasons == []
    assert "github.com/acme/payments" in decision.ownership_evidence


def test_checkout_of_someone_elses_repository_is_refused(tmp_path: Path) -> None:
    fake_checkout(tmp_path / "checkout")
    asset = load_config(repo_scope(tmp_path, "github.com/other-org/payments")).assets[0]

    decision = ScopeGuard(NOW).check(asset)

    assert not decision.allowed
    assert "ownership check failed" in decision.reasons[0]
    assert "FAKE-TOKEN-VALUE" not in " ".join(decision.reasons)


def test_repository_without_a_remote_is_refused(tmp_path: Path) -> None:
    (tmp_path / "checkout").mkdir()
    asset = load_config(repo_scope(tmp_path, "github.com/acme/payments")).assets[0]

    decision = ScopeGuard(NOW).check(asset)

    assert not decision.allowed
    assert "no git remote" in decision.reasons[0]


def test_missing_path_is_refused(tmp_path: Path) -> None:
    asset = load_config(repo_scope(tmp_path, "github.com/acme/payments")).assets[0]

    decision = ScopeGuard(NOW).check(asset)

    assert not decision.allowed
    assert "does not exist" in decision.reasons[0]


def test_expired_authorization_is_no_authorization(tmp_path: Path) -> None:
    fake_checkout(tmp_path / "checkout")
    asset = load_config(
        repo_scope(tmp_path, "github.com/acme/payments", expires="2026-11-09")
    ).assets[0]

    decision = ScopeGuard(NOW).check(asset)

    assert not decision.allowed
    assert "expired on 2026-11-09" in decision.reasons[0]


def test_authorization_is_valid_through_its_last_day_and_warns_before_expiry(
    tmp_path: Path,
) -> None:
    fake_checkout(tmp_path / "checkout")
    asset = load_config(
        repo_scope(tmp_path, "github.com/acme/payments", expires="2026-11-10")
    ).assets[0]

    decision = ScopeGuard(NOW).check(asset)

    assert decision.allowed
    assert any("expires on 2026-11-10" in warning for warning in decision.warnings)


def test_authorization_dated_in_the_future_is_refused(tmp_path: Path) -> None:
    fake_checkout(tmp_path / "checkout")
    asset = load_config(
        repo_scope(tmp_path, "github.com/acme/payments", authorized_on="2026-12-01")
    ).assets[0]

    decision = ScopeGuard(NOW).check(asset)

    assert not decision.allowed
    assert "only takes effect" in decision.reasons[0]


@pytest.mark.parametrize(
    ("max_level", "requested", "allowed", "reason"),
    [
        ("L0", ControlLevel.L0, True, ""),
        ("L0", ControlLevel.L1, False, "exceeds the asset's max_level L0"),
        ("L1", ControlLevel.L1, True, ""),
        ("L2", ControlLevel.L2, False, "human approval"),
        ("L2", ControlLevel.L3, False, "never run by agents"),
    ],
)
def test_control_levels(tmp_path: Path, max_level, requested, allowed, reason) -> None:
    fake_checkout(tmp_path / "checkout")
    asset = load_config(
        repo_scope(tmp_path, "github.com/acme/payments", max_level=max_level)
    ).assets[0]

    decision = ScopeGuard(NOW).check(asset, requested)

    assert decision.allowed is allowed
    if reason:
        assert reason in " ".join(decision.reasons)


WINDOW = """\
    limits:
      min_interval_minutes: 60
      windows:
        - days: [mon]
          start: "22:00"
          end: "02:00"
"""


@pytest.mark.parametrize(
    ("moment", "allowed"),
    [
        (datetime(2026, 11, 9, 21, 59, tzinfo=UTC), False),  # Monday, too early
        (datetime(2026, 11, 9, 22, 0, tzinfo=UTC), True),  # Monday, window opens
        (datetime(2026, 11, 10, 1, 59, tzinfo=UTC), True),  # Tuesday, still open
        (datetime(2026, 11, 10, 2, 0, tzinfo=UTC), False),  # Tuesday, closed
        (datetime(2026, 11, 10, 23, 0, tzinfo=UTC), False),  # Tuesday night, not listed
    ],
)
def test_scan_windows_wrap_past_midnight(tmp_path: Path, moment: datetime, allowed: bool) -> None:
    fake_checkout(tmp_path / "checkout")
    asset = load_config(repo_scope(tmp_path, "github.com/acme/payments", limits=WINDOW)).assets[0]

    decision = ScopeGuard(moment).check(asset)

    assert decision.allowed is allowed
    if not allowed:
        assert "outside the scan windows" in decision.reasons[0]


def test_minimum_interval_between_scans(tmp_path: Path) -> None:
    fake_checkout(tmp_path / "checkout")
    asset = load_config(repo_scope(tmp_path, "github.com/acme/payments", limits=WINDOW)).assets[0]
    moment = datetime(2026, 11, 9, 23, 0, tzinfo=UTC)

    too_soon = ScopeGuard(moment).check(asset, last_run_at=moment - timedelta(minutes=59))
    late_enough = ScopeGuard(moment).check(asset, last_run_at=moment - timedelta(minutes=60))

    assert not too_soon.allowed and "rate limit" in too_soon.reasons[0]
    assert late_enough.allowed


def test_directory_assets_rely_on_the_authorization_record(
    tmp_path: Path, make_scope, target
) -> None:
    asset = load_config(make_scope([{"id": "a", "path": "target"}])).assets[0]

    decision = ScopeGuard(NOW).check(asset)

    assert decision.allowed
    assert "authorization record" in decision.ownership_evidence


def test_filesystem_root_is_never_an_asset(tmp_path: Path, make_scope) -> None:
    asset = load_config(make_scope([{"id": "a", "path": "/"}])).assets[0]

    decision = ScopeGuard(NOW).check(asset)

    assert not decision.allowed
    assert "too broad" in decision.reasons[0]


def test_l2_runs_only_with_a_current_approval_for_that_control(tmp_path: Path) -> None:
    fake_checkout(tmp_path / "checkout")
    scope = repo_scope(tmp_path, "github.com/acme/payments", max_level="L2")
    text = scope.read_text()
    text = text.replace(
        "    authorization:\n",
        """\
    runtime:
      staging_url: https://staging.example.invalid
    approvals:
      - control: dast
        level: L2
        authorized_by: Jane Doe
        authorized_on: 2026-11-01
        expires_on: 2026-11-20
        target: https://staging.example.invalid
    authorization:
""",
    )
    scope.write_text(text, encoding="utf-8")
    asset = load_config(scope).assets[0]

    assert ScopeGuard(NOW).check(asset, ControlLevel.L2).allowed is False
    assert ScopeGuard(NOW).check(asset, ControlLevel.L2, control="dast").allowed
    later = ScopeGuard(datetime(2026, 11, 21, tzinfo=UTC)).check(
        asset, ControlLevel.L2, control="dast"
    )
    assert not later.allowed and "not yet in effect" not in later.reasons[0]
    assert "expired" in later.reasons[0]


def test_kill_switch_by_file_and_by_environment(tmp_path: Path) -> None:
    stop = tmp_path / "STOP"
    assert KillSwitch(stop, {}).reason() is None
    assert KillSwitch(stop, {"HTW_KILL_SWITCH": "0"}).reason() is None
    assert "HTW_KILL_SWITCH" in (KillSwitch(stop, {"HTW_KILL_SWITCH": "1"}).reason() or "")

    stop.touch()
    switch = KillSwitch(stop, {})
    assert "stop file" in (switch.reason() or "")
    with pytest.raises(KillSwitchEngaged):
        switch.raise_if_engaged()
