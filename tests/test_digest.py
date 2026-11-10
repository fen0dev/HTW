"""The local digest is read from finished reports and is not uploaded."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from htw.agents.digest import DigestError, write_digest
from htw.cli import main
from htw.core.config import load_config

from .conftest import scope_yaml
from .test_orchestrator import MARKER, Harness, Scanners

NOW = datetime(2026, 11, 10, 16, 35, tzinfo=UTC)
RUN = "20261110T120000Z-aaaaaa"
SECRET = "TOP-SECRET-VALUE-IN-SARIF"


def _scope(tmp_path: Path, assets: list[str] | None = None) -> Path:
    entries = [{"id": asset_id, "path": "."} for asset_id in assets or ["app"]]
    path = tmp_path / "htw.yaml"
    path.write_text(scope_yaml(entries), encoding="utf-8")
    return path


def _summary(
    *,
    new: list[str] | None = None,
    reappeared: list[str] | None = None,
    resolved: list[str] | None = None,
    unchanged: int = 0,
    unverified: int = 0,
    suppressed: int = 0,
    gaps: list[str] | None = None,
    scanners: list[dict[str, str]] | None = None,
    run: str = RUN,
) -> dict:
    return {
        "asset": "app",
        "run": run,
        "status": "complete",
        "started_at": "2026-11-10T12:00:00+00:00",
        "delta": {
            "new": new or [],
            "reappeared": reappeared or [],
            "resolved": resolved or [],
            "unchanged": unchanged,
            "unverified": unverified,
            "suppressed": suppressed,
        },
        "gaps": gaps or [],
        "scanners": scanners or [],
    }


def _result(state: str, priority: str, *, suppressed: bool = False, message: str = SECRET) -> dict:
    result: dict = {
        "message": {"text": message},
        "properties": {"htw/state": state, "htw/priority": priority},
    }
    if suppressed:
        result["suppressions"] = [{"kind": "external", "justification": message}]
    return result


def _write_run(root: Path, asset: str, name: str, summary: dict, results: list[dict]) -> Path:
    directory = root / ".htw" / "reports" / asset / name
    directory.mkdir(parents=True)
    (directory / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    (directory / "findings.sarif").write_text(
        json.dumps({"runs": [{"results": results}]}), encoding="utf-8"
    )
    (directory / "report.md").write_text("# report\n", encoding="utf-8")
    return directory


def test_digest_counts_open_findings_and_skips_secret_text(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    _write_run(
        tmp_path,
        "app",
        RUN,
        _summary(
            new=["fp-new"],
            resolved=["fp-old"],
            unchanged=1,
            suppressed=1,
            gaps=["static analysis of Python code", "click [here](http://evil.example) <script>"],
            scanners=[
                {"tool": "semgrep", "status": "error"},
                {"tool": "bandit", "status": "missing"},
            ],
        ),
        [
            _result("new", "P0"),
            _result("unchanged", "P1"),
            _result("new", "P0", suppressed=True),
            _result("resolved", "P0"),
        ],
    )
    path, text = write_digest(load_config(scope), now=NOW)
    assert path == tmp_path / ".htw" / "digest.md"
    assert path.stat().st_mode & 0o777 == 0o600
    assert "Read at 2026-11-10 16:35 UTC" in text
    assert "Open findings: 2 (1 P0, 1 P1)" in text
    assert "1 new, 0 reappeared, 1 resolved" in text
    assert "Still open | Open by priority" in text
    assert "1 scanner failed (semgrep)" in text
    assert "1 not installed" in text
    assert "static analysis of Python code" in text
    assert "\\[here\\]" in text
    assert "<script>" not in text
    assert SECRET not in text
    assert "Nothing was uploaded" in text
    assert str(tmp_path / ".htw" / "reports" / "app" / RUN / "report.md") in text


def test_older_run_and_a_symlink_are_not_the_digest(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    _write_run(tmp_path, "app", "20261101T000000Z-older", _summary(new=["a", "b", "c", "d"]), [])
    _write_run(
        tmp_path, "app", RUN, _summary(new=["only-new"], unchanged=0), [_result("new", "P2")]
    )
    outside = tmp_path / "outside"
    _write_run(
        outside, "leaked", "20261112T000000Z-link", _summary(new=[f"x{i}" for i in range(9)]), []
    )
    link = tmp_path / ".htw" / "reports" / "app" / "20261112T000000Z-link"
    link.symlink_to(outside / ".htw" / "reports" / "leaked" / "20261112T000000Z-link")
    _text_path = write_digest(load_config(scope), now=NOW)
    text = _text_path[1]
    assert "1 new" in text
    assert "4 new" not in text
    assert "9 new" not in text
    assert "outside" not in text


def test_a_corrupt_latest_report_is_not_replaced_by_an_older_one(tmp_path: Path) -> None:
    scope = _scope(tmp_path)
    _write_run(tmp_path, "app", "20261101T000000Z-older", _summary(new=["a", "b", "c", "d"]), [])
    latest = tmp_path / ".htw" / "reports" / "app" / "20261112T000000Z-bad"
    latest.mkdir(parents=True)
    (latest / "summary.json").write_text("{", encoding="utf-8")
    with pytest.raises(DigestError, match="No finished scan"):
        write_digest(load_config(scope), now=NOW)
    assert not (tmp_path / ".htw" / "digest.md").exists()


def test_undeclared_report_directories_are_ignored(tmp_path: Path) -> None:
    scope = _scope(tmp_path, ["app", "other"])
    _write_run(tmp_path, "app", RUN, _summary(unchanged=1), [_result("unchanged", "P3")])
    _write_run(
        tmp_path,
        "stranger",
        RUN,
        _summary(new=["secret-asset"], unchanged=5),
        [_result("new", "P0", message="stranger-secret")],
    )
    text = write_digest(load_config(scope), now=NOW)[1]
    assert "stranger" not in text
    assert "stranger-secret" not in text
    assert "no finished scan" in text
    assert "Open findings: 1 (1 P3)" in text


def test_digest_command_prints_the_file_and_refuses_an_unknown_asset(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    scope = _scope(tmp_path)
    _write_run(tmp_path, "app", RUN, _summary(unchanged=1), [_result("unchanged", "P2")])
    assert main(["digest", "-c", str(scope)]) == 0
    out = capsys.readouterr().out
    assert "Open findings: 1 (1 P2)" in out
    assert f"digest: {tmp_path / '.htw' / 'digest.md'}" in out
    assert main(["digest", "-c", str(scope), "--asset", "missing"]) == 2
    assert "not declared" in capsys.readouterr().err


def test_digest_of_a_real_scan_matches_the_run(tmp_path: Path) -> None:
    harness = Harness(tmp_path, Scanners())
    run = harness.scan()
    text = write_digest(load_config(tmp_path / "htw.yaml"), now=NOW)[1]
    assert run.report_dir is not None
    assert str(run.report_dir / "report.md") in text
    assert f"{len(run.delta.new)} new" in text
    assert MARKER not in text
    assert "Nothing was uploaded" in text
