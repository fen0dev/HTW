"""Scope enforcement: the decision whether an asset may be scanned right now.

Everything is denied unless the scope file allows it. Every check that fails adds a
reason; an asset is scanned only when there are none.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from htw.core.config import Asset, TimeWindow
from htw.core.levels import MAX_AUTOMATIC_LEVEL, ControlLevel
from htw.errors import KillSwitchEngaged

EXPIRY_WARNING_DAYS = 14
KILL_SWITCH_ENV = "HTW_KILL_SWITCH"

_SECTION_RE = re.compile(r'^\[\s*remote\s+"(?P<name>[^"]+)"\s*\]\s*$')
_ANY_SECTION_RE = re.compile(r"^\[.*\]\s*$")
_URL_RE = re.compile(r"^\s*url\s*=\s*(?P<url>.+?)\s*$")


@dataclass
class ScopeDecision:
    asset_id: str
    level: ControlLevel
    allowed: bool = True
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    ownership_evidence: str = ""

    def deny(self, reason: str) -> None:
        self.allowed = False
        self.reasons.append(reason)


def normalize_remote(url: str) -> str | None:
    """Reduce a git remote URL to host/path, dropping scheme, credentials, port and .git.

    Credentials embedded in remote URLs must never reach logs or reports, so the
    normalized form is the only one used outside this function.
    """
    url = url.strip()
    if not url:
        return None
    match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://(?P<rest>.+)$", url)
    if match:
        rest = match.group("rest")
        authority, _, path = rest.partition("/")
        host = authority.rsplit("@", 1)[-1]
        host = re.sub(r":\d+$", "", host)
    else:
        scp = re.match(r"^(?:[^@/]+@)?(?P<host>[^:/]+):(?P<path>.+)$", url)
        if not scp:
            return None
        host, path = scp.group("host"), scp.group("path")
    path = path.strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    if not host or not path:
        return None
    return f"{host}/{path}".lower()


def find_git_dir(path: Path) -> Path | None:
    """Locate the git directory for `path` or the nearest ancestor checkout."""
    for candidate in (path, *path.parents):
        dot_git = candidate / ".git"
        if dot_git.is_dir():
            return dot_git
        if dot_git.is_file():
            try:
                content = dot_git.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return None
            match = re.match(r"^gitdir:\s*(.+)$", content.strip())
            if not match:
                return None
            git_dir = Path(match.group(1))
            if not git_dir.is_absolute():
                git_dir = (candidate / git_dir).resolve()
            common = git_dir / "commondir"
            if common.is_file():
                try:
                    return (git_dir / common.read_text(encoding="utf-8").strip()).resolve()
                except OSError:
                    return None
            return git_dir
    return None


def read_git_remotes(path: Path) -> list[str]:
    """Return normalized remote URLs of the checkout containing `path`.

    The git config is parsed directly so that no git binary is needed and no git
    hooks or config-driven commands can run.
    """
    git_dir = find_git_dir(path)
    if git_dir is None:
        return []
    try:
        lines = (git_dir / "config").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    remotes: list[str] = []
    in_remote = False
    for line in lines:
        if _ANY_SECTION_RE.match(line.strip()):
            in_remote = bool(_SECTION_RE.match(line.strip()))
            continue
        if in_remote:
            match = _URL_RE.match(line)
            if match:
                normalized = normalize_remote(match.group("url"))
                if normalized and normalized not in remotes:
                    remotes.append(normalized)
    return remotes


def remote_matches(remote: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(remote.lower(), pattern.lower().rstrip("/"))


def _in_window(window: TimeWindow, now: datetime) -> bool:
    minutes = now.hour * 60 + now.minute
    start = window.start.hour * 60 + window.start.minute
    end = window.end.hour * 60 + window.end.minute
    today, yesterday = now.weekday(), (now.weekday() - 1) % 7
    if start <= end:
        return today in window.days and start <= minutes < end
    return (today in window.days and minutes >= start) or (
        yesterday in window.days and minutes < end
    )


class ScopeGuard:
    """Decides whether a check at a given level may run against an asset."""

    def __init__(self, now: datetime | None = None):
        self._now = now

    def now(self) -> datetime:
        return self._now or datetime.now(UTC)

    def check(
        self,
        asset: Asset,
        level: ControlLevel = ControlLevel.L0,
        last_run_at: datetime | None = None,
    ) -> ScopeDecision:
        decision = ScopeDecision(asset_id=asset.id, level=level)
        now = self.now()
        today = now.date()

        auth = asset.authorization
        if today < auth.authorized_on:
            decision.deny(f"authorization only takes effect on {auth.authorized_on.isoformat()}")
        if today > auth.expires_on:
            decision.deny(
                f"authorization expired on {auth.expires_on.isoformat()}; "
                "an expired authorization is no authorization. Renew it in the scope file."
            )
        elif (auth.expires_on - today).days <= EXPIRY_WARNING_DAYS:
            decision.warnings.append(
                f"authorization expires on {auth.expires_on.isoformat()}; renew it soon"
            )

        if level >= ControlLevel.L3:
            decision.deny("L3 (intrusive) checks are never run by agents")
        elif level > asset.max_level:
            decision.deny(
                f"check level {level.name} exceeds the asset's max_level {asset.max_level.name}"
            )
        elif level > MAX_AUTOMATIC_LEVEL:
            decision.deny(
                f"{level.name} checks need a time-bound human approval, "
                "which this release does not implement; refusing"
            )

        self._check_path(asset, decision)
        if decision.allowed:
            self._check_ownership(asset, decision)

        if asset.windows and not any(_in_window(w, now) for w in asset.windows):
            decision.deny(
                f"outside the scan windows declared for this asset "
                f"(now {now.strftime('%a %H:%M')} UTC)"
            )
        if asset.min_interval_minutes and last_run_at is not None:
            earliest = last_run_at + timedelta(minutes=asset.min_interval_minutes)
            if now < earliest:
                decision.deny(
                    f"rate limit: last scan started {last_run_at.strftime('%Y-%m-%d %H:%M')} UTC, "
                    f"next allowed after {earliest.strftime('%Y-%m-%d %H:%M')} UTC "
                    f"(min_interval_minutes: {asset.min_interval_minutes})"
                )
        return decision

    @staticmethod
    def _check_path(asset: Asset, decision: ScopeDecision) -> None:
        path = asset.path
        if not path.is_dir():
            decision.deny(f"path {path} does not exist or is not a directory")
            return
        if path == Path(path.anchor) or path == Path.home():
            decision.deny(f"path {path} is too broad to be a single asset")
            return
        if not os.access(path, os.R_OK | os.X_OK):
            decision.deny(f"path {path} is not readable")

    @staticmethod
    def _check_ownership(asset: Asset, decision: ScopeDecision) -> None:
        patterns = asset.ownership.git_remotes
        if not patterns:
            decision.ownership_evidence = (
                "declared by the authorization record (no automated check for directory assets)"
            )
            return
        remotes = read_git_remotes(asset.path)
        if not remotes:
            decision.deny(
                "ownership check failed: no git remote found for this path, expected "
                + " or ".join(patterns)
            )
            return
        for remote in remotes:
            for pattern in patterns:
                if remote_matches(remote, pattern):
                    decision.ownership_evidence = f"git remote {remote} matches {pattern}"
                    return
        decision.deny(
            "ownership check failed: git remote(s) "
            + ", ".join(remotes)
            + " do not match the expected "
            + " or ".join(patterns)
        )


class KillSwitch:
    """Global stop: a STOP file in the state directory or HTW_KILL_SWITCH=1."""

    def __init__(self, path: Path, environ: dict[str, str] | None = None):
        self._path = path
        self._environ = os.environ if environ is None else environ

    @property
    def path(self) -> Path:
        return self._path

    def reason(self) -> str | None:
        value = self._environ.get(KILL_SWITCH_ENV, "").strip().lower()
        if value not in ("", "0", "false", "no"):
            return f"environment variable {KILL_SWITCH_ENV} is set"
        if self._path.exists():
            return f"stop file {self._path} exists"
        return None

    def raise_if_engaged(self) -> None:
        reason = self.reason()
        if reason:
            raise KillSwitchEngaged(f"kill switch engaged ({reason}); no scanner will run")
