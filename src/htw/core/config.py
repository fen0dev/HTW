"""Scope file loading and validation.

The scope file is the allowlist: nothing is scanned unless it is declared here with a
valid authorization record. Validation is strict on purpose. Unknown keys are errors,
because a typo in a guardrail setting must never silently fall back to a default.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import date, time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from htw.core.levels import MAX_DECLARABLE_LEVEL, ControlLevel
from htw.errors import ConfigError

CONFIG_VERSION = 1
DEFAULT_CONFIG_NAME = "htw.yaml"

SUPPORTED_ASSET_TYPES = ("repository", "directory")
PLANNED_ASSET_TYPES = (
    "container_image",
    "cloud_account",
    "kubernetes_cluster",
    "web_application",
    "host",
)
ENVIRONMENTS = ("development", "ci", "staging", "production", "other")
CRITICALITIES = ("low", "medium", "high", "critical")
AGENT_NAMES = ("deps_sbom", "secrets", "sast", "container", "iac", "pipeline", "dast")
AGENT_OPTIONS: dict[str, tuple[str, ...]] = {
    "deps_sbom": (),
    "secrets": ("history",),
    "sast": ("semgrep_rules",),
    "container": (),
    "iac": (),
    "pipeline": (),
    "dast": (),
}
APPROVAL_CONTROLS = ("dast",)
LLM_PROVIDERS = ("openai", "anthropic")
_API_KEY_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,60}$")
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

_ASSET_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_REMOTE_PATTERN_RE = re.compile(r"^[A-Za-z0-9.-]+(/[A-Za-z0-9._*?\[\]-]+)+$")


@dataclass(frozen=True)
class Authorization:
    authorized_by: str
    authorized_on: date
    expires_on: date
    reference: str | None = None


@dataclass(frozen=True)
class Ownership:
    git_remotes: tuple[str, ...] = ()


@dataclass(frozen=True)
class TimeWindow:
    """A UTC window in which scans may start. `end` before `start` wraps past midnight."""

    days: frozenset[int]
    start: time
    end: time


@dataclass(frozen=True)
class AgentSettings:
    enabled: bool = True
    tools: tuple[str, ...] | None = None  # None means automatic selection
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Asset:
    id: str
    type: str
    path: Path
    owner: str
    environment: str
    criticality: str
    max_level: ControlLevel
    authorization: Authorization
    ownership: Ownership
    exclude: tuple[str, ...]
    scanners: dict[str, AgentSettings]
    windows: tuple[TimeWindow, ...]
    min_interval_minutes: int
    staging_url: str | None = None
    approvals: tuple[Approval, ...] = ()


@dataclass(frozen=True)
class RunnerSettings:
    timeout_seconds: int = 900
    max_output_mb: int = 256
    env_passthrough: tuple[str, ...] = ()


@dataclass(frozen=True)
class Approval:
    """A time-bound human approval for one control above the automatic level."""

    control: str
    level: ControlLevel
    authorized_by: str
    authorized_on: date
    expires_on: date
    target: str


@dataclass(frozen=True)
class FixSettings:
    propose: bool = False
    # Open draft pull requests for proposals that have a patch. Never merges.
    pull_requests: bool = False
    # Required before a proposal that describes an unfixed weakness may be published.
    private_destination: bool = False


@dataclass(frozen=True)
class TriageSettings:
    """Deterministic triage is on by default. A model is never called unless configured."""

    enabled: bool = True
    llm: bool = False
    provider: str | None = None
    model: str | None = None
    api_key_env: str | None = None


@dataclass(frozen=True)
class Config:
    path: Path
    base_dir: Path
    config_hash: str
    assets: tuple[Asset, ...]
    state_dir: Path
    suppressions_path: Path
    runner: RunnerSettings
    fixes: FixSettings
    triage: TriageSettings

    @property
    def store_path(self) -> Path:
        return self.state_dir / "state.db"

    @property
    def audit_path(self) -> Path:
        return self.state_dir / "audit.jsonl"

    @property
    def reports_dir(self) -> Path:
        return self.state_dir / "reports"

    @property
    def kill_switch_path(self) -> Path:
        return self.state_dir / "STOP"

    def asset(self, asset_id: str) -> Asset:
        for asset in self.assets:
            if asset.id == asset_id:
                return asset
        known = ", ".join(a.id for a in self.assets) or "none"
        raise ConfigError(
            f"asset {asset_id!r} is not declared in {self.path} (declared: {known}). "
            "Only allowlisted assets can be scanned."
        )


class _Section:
    """A mapping from the YAML file that tracks which keys were consumed."""

    def __init__(self, data: object, where: str):
        if data is None:
            data = {}
        if not isinstance(data, dict):
            raise ConfigError(f"{where}: expected a mapping, got {type(data).__name__}")
        self._data = dict(data)
        self._where = where
        self._seen: set[str] = set()

    @property
    def where(self) -> str:
        return self._where

    def get(self, key: str, default: Any = None) -> Any:
        self._seen.add(key)
        return self._data.get(key, default)

    def require(self, key: str) -> Any:
        value = self.get(key)
        if value is None or value == "":
            raise ConfigError(f"{self._where}: `{key}` is required")
        return value

    def string(self, key: str, default: str | None = None, *, required: bool = False) -> str | None:
        value = self.require(key) if required else self.get(key, default)
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(f"{self._where}: `{key}` must be a non-empty string")
        return value.strip()

    def choice(self, key: str, choices: tuple[str, ...], default: str) -> str:
        value = self.get(key, default)
        if value not in choices:
            raise ConfigError(
                f"{self._where}: `{key}` must be one of {', '.join(choices)} (got {value!r})"
            )
        return str(value)

    def integer(self, key: str, default: int, *, minimum: int = 0) -> int:
        value = self.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise ConfigError(f"{self._where}: `{key}` must be an integer >= {minimum}")
        return value

    def boolean(self, key: str, default: bool) -> bool:
        value = self.get(key, default)
        if not isinstance(value, bool):
            raise ConfigError(f"{self._where}: `{key}` must be true or false")
        return value

    def strings(self, key: str) -> tuple[str, ...]:
        value = self.get(key)
        if value is None:
            return ()
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
            raise ConfigError(f"{self._where}: `{key}` must be a list of non-empty strings")
        return tuple(v.strip() for v in value)

    def section(self, key: str) -> _Section:
        return _Section(self.get(key), f"{self._where}.{key}")

    def finish(self) -> None:
        unknown = sorted(set(self._data) - self._seen)
        if unknown:
            raise ConfigError(
                f"{self._where}: unknown key(s) {', '.join(map(repr, unknown))}. "
                "Unknown keys are rejected so that a typo cannot weaken a guardrail."
            )


def _parse_date(value: object, where: str, key: str) -> date:
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            pass
    raise ConfigError(f"{where}: `{key}` must be an ISO date (YYYY-MM-DD)")


def _parse_time(value: object, where: str, key: str) -> time:
    # YAML 1.1 reads an unquoted 22:00 as the base-60 integer 1320.
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 24 * 60:
        return time(value // 60, value % 60)
    if isinstance(value, str) and re.fullmatch(r"\d{1,2}:\d{2}", value.strip()):
        hours, minutes = (int(part) for part in value.strip().split(":"))
        if hours < 24 and minutes < 60:
            return time(hours, minutes)
    raise ConfigError(f'{where}: `{key}` must be a UTC time written as "HH:MM"')


_FORBIDDEN_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.internal",
    }
)


def validate_target_url(url: str, where: str) -> str:
    """Accept an http(s) URL that names a host, and reject targets that are not an app.

    Loopback, link-local and cloud metadata addresses are refused even if someone
    writes them into the scope file: they are not the system under test.
    """
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme not in {"https", "http"} or not host or parts.username or parts.password:
        raise ConfigError(
            f"{where}: must be an http(s) URL with a host and no credentials (got {url!r})"
        )
    if host in _FORBIDDEN_HOSTS or host.endswith(".localhost"):
        raise ConfigError(f"{where}: {host} is not a scannable application target")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or address.is_reserved
    ):
        raise ConfigError(f"{where}: {host} is not a scannable application target")
    return url


def _parse_authorization(section: _Section) -> Authorization:
    hint = (
        " A named person must authorize scanning this asset; "
        "scans are refused without a complete, unexpired authorization record."
    )
    try:
        authorized_by = section.string("authorized_by", required=True)
        authorized_on = _parse_date(
            section.require("authorized_on"), section.where, "authorized_on"
        )
        expires_on = _parse_date(section.require("expires_on"), section.where, "expires_on")
    except ConfigError as exc:
        raise ConfigError(f"{exc}.{hint}") from None
    reference = section.string("reference")
    section.finish()
    if expires_on < authorized_on:
        raise ConfigError(f"{section.where}: `expires_on` is earlier than `authorized_on`")
    assert authorized_by is not None
    return Authorization(authorized_by, authorized_on, expires_on, reference)


def _parse_ownership(section: _Section, asset_type: str) -> Ownership:
    remotes = section.strings("git_remote")
    section.finish()
    for pattern in remotes:
        segments = pattern.split("/")
        if not _REMOTE_PATTERN_RE.match(pattern) or len(segments) < 2:
            raise ConfigError(
                f"{section.where}: git_remote {pattern!r} must look like host/owner/repo "
                "(for example github.com/acme/payments or github.com/acme/*)"
            )
        if any(ch in segment for segment in segments[:2] for ch in "*?["):
            raise ConfigError(
                f"{section.where}: git_remote {pattern!r} must name the host and the owner "
                "explicitly; wildcards are only allowed after them"
            )
    if asset_type == "repository" and not remotes:
        raise ConfigError(
            f"{section.where}: `git_remote` is required for repository assets. It names the "
            "remote the checkout must point to, and is verified before every scan."
        )
    return Ownership(git_remotes=remotes)


def _parse_approvals(raw: object, where: str, staging_url: str | None) -> tuple[Approval, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError(f"{where}: `approvals` must be a list")
    approvals = []
    for index, item in enumerate(raw):
        section = _Section(item, f"{where}.approvals[{index}]")
        control = section.choice("control", APPROVAL_CONTROLS, "dast")
        try:
            level = ControlLevel.parse(section.get("level", "L2"))
        except ValueError as exc:
            raise ConfigError(f"{section.where}: {exc}") from None
        if level <= ControlLevel.L1:
            raise ConfigError(
                f"{section.where}: an approval is only meaningful above L1 "
                "(L0 and L1 run when the asset is allowlisted)"
            )
        if level > MAX_DECLARABLE_LEVEL:
            raise ConfigError(
                f"{section.where}: L3 cannot be approved. Intrusive checks are never run by agents."
            )
        authorized_by = section.string("authorized_by", required=True)
        authorized_on = _parse_date(
            section.require("authorized_on"), section.where, "authorized_on"
        )
        expires_on = _parse_date(section.require("expires_on"), section.where, "expires_on")
        target = validate_target_url(section.string("target", required=True) or "", section.where)
        section.finish()
        if expires_on < authorized_on:
            raise ConfigError(f"{section.where}: `expires_on` is earlier than `authorized_on`")
        if control == "dast" and target != staging_url:
            raise ConfigError(
                f"{section.where}: `target` must be exactly `runtime.staging_url`. "
                "DAST cannot be approved for a different address than the one it will contact."
            )
        assert authorized_by is not None
        approvals.append(Approval(control, level, authorized_by, authorized_on, expires_on, target))
    return tuple(approvals)


def _parse_triage(section: _Section) -> TriageSettings:
    enabled = section.boolean("enabled", True)
    llm = section.boolean("llm", False)
    provider = section.string("provider")
    model = section.string("model")
    api_key_env = section.string("api_key_env")
    section.finish()
    if llm:
        if provider not in LLM_PROVIDERS:
            raise ConfigError(
                f"{section.where}: `provider` must be one of {', '.join(LLM_PROVIDERS)} "
                "when `llm` is true. HTW does not call a model unless the provider is named."
            )
        if not api_key_env or not _API_KEY_ENV_RE.match(api_key_env):
            raise ConfigError(
                f"{section.where}: `api_key_env` must name the environment variable that holds "
                "the provider credential. HTW does not accept a key inline and does not invent one."
            )
    elif provider or model or api_key_env:
        raise ConfigError(
            f"{section.where}: `provider`, `model` and `api_key_env` require `llm: true`"
        )
    if llm and not enabled:
        raise ConfigError(f"{section.where}: `llm: true` requires `enabled: true`")
    return TriageSettings(enabled, llm, provider, model, api_key_env)


def _parse_windows(raw: object, where: str) -> tuple[TimeWindow, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ConfigError(f"{where}: `windows` must be a list")
    windows = []
    for index, item in enumerate(raw):
        section = _Section(item, f"{where}.windows[{index}]")
        days = section.strings("days") or WEEKDAYS
        bad = [d for d in days if d.lower() not in WEEKDAYS]
        if bad:
            raise ConfigError(f"{section.where}: unknown day(s) {bad}; use {', '.join(WEEKDAYS)}")
        start = _parse_time(section.require("start"), section.where, "start")
        end = _parse_time(section.require("end"), section.where, "end")
        section.finish()
        windows.append(TimeWindow(frozenset(WEEKDAYS.index(d.lower()) for d in days), start, end))
    return tuple(windows)


def _check_option(name: str, value: object, where: str) -> object:
    if name == "history" and not isinstance(value, bool):
        raise ConfigError(f"{where}: `history` must be true or false")
    if name == "semgrep_rules":
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{where}: `semgrep_rules` must be a non-empty list of strings")
        if "auto" in value:
            raise ConfigError(
                f"{where}: semgrep_rules `auto` is not supported because it requires Semgrep "
                "metrics to be enabled. Name rulesets (for example p/default) or local rule paths."
            )
    return value


def _parse_agent_settings(
    section: _Section, agent: str, base: AgentSettings | None = None
) -> AgentSettings:
    base = base or AgentSettings()
    enabled = section.boolean("enabled", base.enabled)
    raw_tools = section.get("tools")
    tools = base.tools
    if raw_tools is not None and raw_tools != "auto":
        if not isinstance(raw_tools, list) or not all(isinstance(t, str) for t in raw_tools):
            raise ConfigError(f"{section.where}: `tools` must be `auto` or a list of tool names")
        tools = tuple(raw_tools)
    elif raw_tools == "auto":
        tools = None
    options = dict(base.options)
    for key in AGENT_OPTIONS[agent]:
        value = section.get(key)
        if value is not None:
            options[key] = _check_option(key, value, section.where)
    section.finish()
    return AgentSettings(enabled=enabled, tools=tools, options=options)


def _parse_scanners(
    section: _Section, base: dict[str, AgentSettings] | None = None
) -> dict[str, AgentSettings]:
    result = {}
    for name in AGENT_NAMES:
        result[name] = _parse_agent_settings(section.section(name), name, (base or {}).get(name))
    section.finish()
    return result


def _parse_asset(
    raw: object, index: int, base_dir: Path, defaults: dict[str, AgentSettings]
) -> Asset:
    section = _Section(raw, f"assets[{index}]")
    asset_id = section.string("id", required=True)
    assert asset_id is not None
    if not _ASSET_ID_RE.match(asset_id):
        raise ConfigError(
            f"{section.where}: id {asset_id!r} must be lowercase letters, digits, '.', '_' or '-'"
        )
    section = _Section(raw, f"asset {asset_id!r}")
    section.get("id")

    asset_type = section.string("type", required=True)
    if asset_type in PLANNED_ASSET_TYPES:
        raise ConfigError(
            f"{section.where}: asset type {asset_type!r} is planned but not supported by this "
            f"release, which only runs static (L0) checks on: {', '.join(SUPPORTED_ASSET_TYPES)}"
        )
    if asset_type not in SUPPORTED_ASSET_TYPES:
        raise ConfigError(
            f"{section.where}: unknown asset type {asset_type!r} "
            f"(supported: {', '.join(SUPPORTED_ASSET_TYPES)})"
        )

    raw_path = section.string("path", required=True)
    assert raw_path is not None
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    path = path.resolve()

    try:
        max_level = ControlLevel.parse(section.get("max_level", "L0"))
    except ValueError as exc:
        raise ConfigError(f"{section.where}: {exc}") from None
    if max_level > MAX_DECLARABLE_LEVEL:
        raise ConfigError(
            f"{section.where}: max_level L3 cannot be granted. Intrusive or potentially "
            "destructive checks are never run by agents."
        )

    limits = section.section("limits")
    windows = _parse_windows(limits.get("windows"), limits.where)
    min_interval = limits.integer("min_interval_minutes", 0)
    limits.finish()

    runtime = section.section("runtime")
    staging_raw = runtime.string("staging_url")
    runtime.finish()
    staging_url = (
        validate_target_url(staging_raw, f"{section.where}.runtime.staging_url")
        if staging_raw
        else None
    )
    approvals = _parse_approvals(section.get("approvals"), section.where, staging_url)

    owner = section.string("owner", required=True)
    assert asset_type is not None and owner is not None
    asset = Asset(
        id=asset_id,
        type=asset_type,
        path=path,
        owner=owner,
        environment=section.choice("environment", ENVIRONMENTS, "development"),
        criticality=section.choice("criticality", CRITICALITIES, "medium"),
        max_level=max_level,
        authorization=_parse_authorization(section.section("authorization")),
        ownership=_parse_ownership(section.section("ownership"), asset_type),
        exclude=section.strings("exclude"),
        scanners=_parse_scanners(section.section("scanners"), defaults),
        windows=windows,
        min_interval_minutes=min_interval,
        staging_url=staging_url,
        approvals=approvals,
    )
    if staging_url:
        dast = asset.scanners["dast"]
        scanners = dict(asset.scanners)
        scanners["dast"] = AgentSettings(
            dast.enabled, dast.tools, {**dast.options, "staging_url": staging_url}
        )
        asset = Asset(
            id=asset.id,
            type=asset.type,
            path=asset.path,
            owner=asset.owner,
            environment=asset.environment,
            criticality=asset.criticality,
            max_level=asset.max_level,
            authorization=asset.authorization,
            ownership=asset.ownership,
            exclude=asset.exclude,
            scanners=scanners,
            windows=asset.windows,
            min_interval_minutes=asset.min_interval_minutes,
            staging_url=staging_url,
            approvals=approvals,
        )
    section.finish()
    return asset


def load_config(path: str | Path) -> Config:
    """Load and validate the scope file. Raises ConfigError with an actionable message."""
    config_path = Path(path).expanduser().resolve()
    try:
        raw_bytes = config_path.read_bytes()
    except FileNotFoundError:
        raise ConfigError(
            f"scope file not found: {config_path}. Run `htw init` to create one. "
            "HTW scans nothing that is not declared in a scope file."
        ) from None
    except OSError as exc:
        raise ConfigError(f"cannot read scope file {config_path}: {exc}") from None
    try:
        data = yaml.safe_load(raw_bytes)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{config_path} is not valid YAML: {exc}") from None

    root = _Section(data, str(config_path.name))
    version = root.get("version")
    if version != CONFIG_VERSION:
        raise ConfigError(
            f"{config_path.name}: `version: {CONFIG_VERSION}` is required (got {version!r})"
        )
    base_dir = config_path.parent

    def resolve(value: str) -> Path:
        candidate = Path(value).expanduser()
        return (candidate if candidate.is_absolute() else base_dir / candidate).resolve()

    state_dir = resolve(root.string("state_dir", ".htw") or ".htw")
    suppressions_path = resolve(root.string("suppressions", "suppressions.yaml") or "")

    runner_section = root.section("runner")
    runner = RunnerSettings(
        timeout_seconds=runner_section.integer("timeout_seconds", 900, minimum=1),
        max_output_mb=runner_section.integer("max_output_mb", 256, minimum=1),
        env_passthrough=runner_section.strings("env_passthrough"),
    )
    runner_section.finish()

    fixes_section = root.section("fixes")
    fixes = FixSettings(
        propose=fixes_section.boolean("propose", False),
        pull_requests=fixes_section.boolean("pull_requests", False),
        private_destination=fixes_section.boolean("private_destination", False),
    )
    fixes_section.finish()
    if fixes.pull_requests and not fixes.propose:
        raise ConfigError(
            f"{config_path.name}: `fixes.pull_requests` requires `fixes.propose: true`. "
            "Pull requests are opened only for proposals, and only as drafts."
        )

    triage = _parse_triage(root.section("triage"))

    defaults = _parse_scanners(root.section("scanners"))

    raw_assets = root.get("assets")
    if not isinstance(raw_assets, list) or not raw_assets:
        raise ConfigError(
            f"{config_path.name}: `assets` must list at least one asset. "
            "Everything not listed is out of scope."
        )
    assets = tuple(
        _parse_asset(raw, index, base_dir, defaults) for index, raw in enumerate(raw_assets)
    )
    ids = [asset.id for asset in assets]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise ConfigError(f"{config_path.name}: duplicate asset id(s): {', '.join(duplicates)}")
    root.finish()

    return Config(
        path=config_path,
        base_dir=base_dir,
        config_hash=hashlib.sha256(raw_bytes).hexdigest(),
        assets=assets,
        state_dir=state_dir,
        suppressions_path=suppressions_path,
        runner=runner,
        fixes=fixes,
        triage=triage,
    )
