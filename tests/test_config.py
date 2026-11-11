from __future__ import annotations

from datetime import date, time
from pathlib import Path

import pytest

from htw.core.config import load_config
from htw.core.levels import ControlLevel
from htw.errors import ConfigError

VALID = """\
version: 1
state_dir: state
fixes:
  propose: true
runner:
  timeout_seconds: 60
  env_passthrough: [GRYPE_DB_CACHE_DIR]
scanners:
  sast:
    semgrep_rules: [p/default, p/python]
  secrets:
    history: false
assets:
  - id: payments-api
    type: repository
    path: checkout
    owner: payments-team
    environment: production
    criticality: critical
    max_level: L1
    ownership:
      git_remote: [github.com/acme/payments, "gitlab.acme.invalid/pay/*"]
    authorization:
      authorized_by: Jane Doe
      authorized_on: 2026-01-01
      expires_on: "2026-12-31"
      reference: SEC-42
    exclude: [vendor, "*.min.js"]
    limits:
      min_interval_minutes: 30
      windows:
        - days: [mon, tue]
          start: 22:00
          end: "06:00"
    scanners:
      sast:
        tools: [semgrep]
      deps_sbom:
        enabled: false
"""


def load(tmp_path: Path, text: str):
    path = tmp_path / "htw.yaml"
    path.write_text(text, encoding="utf-8")
    return load_config(path)


def test_loads_a_complete_scope_file(tmp_path: Path) -> None:
    config = load(tmp_path, VALID)

    assert config.fixes.propose is True
    assert config.state_dir == tmp_path / "state"
    assert config.store_path == tmp_path / "state" / "state.db"
    assert config.runner.timeout_seconds == 60
    assert config.runner.env_passthrough == ("GRYPE_DB_CACHE_DIR",)
    assert config.runner.sandbox == "auto"
    assert len(config.config_hash) == 64

    asset = config.asset("payments-api")
    assert asset.path == tmp_path / "checkout"
    assert asset.max_level is ControlLevel.L1
    assert asset.criticality == "critical"
    assert asset.authorization.authorized_by == "Jane Doe"
    assert asset.authorization.expires_on == date(2026, 12, 31)
    assert asset.ownership.git_remotes == ("github.com/acme/payments", "gitlab.acme.invalid/pay/*")
    assert asset.exclude == ("vendor", "*.min.js")
    assert asset.min_interval_minutes == 30
    # An unquoted 22:00 is a base-60 integer in YAML 1.1 and must still mean 22:00.
    assert asset.windows[0].start == time(22, 0)
    assert asset.windows[0].end == time(6, 0)
    assert asset.windows[0].days == frozenset({0, 1})


def test_asset_scanner_settings_override_the_global_ones(tmp_path: Path) -> None:
    asset = load(tmp_path, VALID).asset("payments-api")

    assert asset.scanners["sast"].tools == ("semgrep",)
    assert asset.scanners["sast"].options["semgrep_rules"] == ["p/default", "p/python"]
    assert asset.scanners["secrets"].options["history"] is False
    assert asset.scanners["secrets"].tools is None
    assert asset.scanners["deps_sbom"].enabled is False


def test_defaults_are_report_only_and_l0(tmp_path: Path, make_scope) -> None:
    config = load_config(make_scope([{"id": "a", "path": "."}]))

    assert config.fixes.propose is False
    assert config.assets[0].max_level is ControlLevel.L0
    assert config.state_dir == tmp_path / ".htw"


def test_unknown_asset_is_refused_with_the_declared_ids(tmp_path: Path, make_scope) -> None:
    config = load_config(make_scope([{"id": "a", "path": "."}]))

    with pytest.raises(ConfigError, match=r"not declared.*declared: a"):
        config.asset("somebody-elses-system")


def test_missing_file_explains_how_to_start(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="htw init"):
        load_config(tmp_path / "nope.yaml")


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (("max_level: L1", "max_levle: L1"), "unknown key.*max_levle"),
        (("max_level: L1", "max_level: L3"), "L3 cannot be granted"),
        (("max_level: L1", "max_level: root"), "unknown control level"),
        (("type: repository", "type: container_image"), "planned but not supported"),
        (("type: repository", "type: mainframe"), "unknown asset type"),
        (("      authorized_by: Jane Doe\n", ""), "authorized_by.*required.*named person"),
        (("authorized_by: Jane Doe", 'authorized_by: ""'), "authorized_by.*required"),
        (('expires_on: "2026-12-31"', "expires_on: someday"), "ISO date"),
        (('expires_on: "2026-12-31"', "expires_on: 2025-01-01"), "earlier than"),
        (('      expires_on: "2026-12-31"\n', ""), "expires_on.*required"),
        (("version: 1", "version: 2"), "version: 1"),
        (("id: payments-api", "id: ../escape"), "must be lowercase"),
        (("owner: payments-team", "owner: ''"), "owner.*required"),
        (("criticality: critical", "criticality: extreme"), "criticality"),
        (("start: 22:00", "start: 25:99"), "HH:MM"),
        (("days: [mon, tue]", "days: [funday]"), "unknown day"),
        (("tools: [semgrep]", "tools: semgrep"), "tools"),
        (("history: false", "history: maybe"), "history"),
        (("semgrep_rules: [p/default, p/python]", "semgrep_rules: [auto]"), "auto.*not supported"),
        (("  secrets:\n    history: false", "  sast:\n    history: false"), "unknown key"),
        (("timeout_seconds: 60", "timeout_seconds: 0"), "timeout_seconds"),
        (("propose: true", "propose: yes please"), "true or false"),
    ],
)
def test_invalid_scope_files_are_rejected(tmp_path: Path, mutation, message) -> None:
    old, new = mutation
    assert old in VALID
    with pytest.raises(ConfigError, match=message):
        load(tmp_path, VALID.replace(old, new, 1))


def test_repository_assets_must_name_their_remote(tmp_path: Path) -> None:
    text = VALID.replace(
        '    ownership:\n      git_remote: [github.com/acme/payments, "gitlab.acme.invalid/pay/*"]\n',
        "",
    )
    with pytest.raises(ConfigError, match=r"git_remote.*required for repository"):
        load(tmp_path, text)


@pytest.mark.parametrize(
    "pattern",
    [
        "github.com/*",
        "github.com/*/payments",
        "*/acme/payments",
        "github.com",
        "https://github.com/a/b",
    ],
)
def test_ownership_patterns_must_name_host_and_owner(tmp_path: Path, pattern: str) -> None:
    text = VALID.replace(
        'git_remote: [github.com/acme/payments, "gitlab.acme.invalid/pay/*"]',
        f'git_remote: "{pattern}"',
    )
    with pytest.raises(ConfigError, match="git_remote"):
        load(tmp_path, text)


def test_assets_are_required_and_unique(tmp_path: Path, make_scope) -> None:
    with pytest.raises(ConfigError, match="at least one asset"):
        load(tmp_path, "version: 1\nassets: []\n")
    with pytest.raises(ConfigError, match="duplicate asset id"):
        load_config(make_scope([{"id": "a", "path": "."}, {"id": "a", "path": "."}]))


def test_invalid_yaml_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not valid YAML"):
        load(tmp_path, "version: 1\nassets: [\n")


def test_the_example_files_in_the_repository_are_valid() -> None:
    from datetime import date

    from htw.core.suppressions import load_suppressions

    examples = Path(__file__).parent.parent / "config"
    config = load_config(examples / "htw.example.yaml")
    suppressions = load_suppressions(examples / "suppressions.example.yaml", date(2026, 1, 1))

    assert [asset.id for asset in config.assets] == ["payments-api", "build-scripts"]
    assert config.fixes.propose is False
    assert config.triage.llm is False
    assert config.triage.provider is None
    assert all(asset.max_level is ControlLevel.L0 for asset in config.assets)
    assert len(suppressions.active) == 2
