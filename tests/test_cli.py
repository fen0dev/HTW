from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from htw import __version__
from htw.cli import AUTHORIZED_USE, main
from htw.core.config import load_config

from .conftest import scope_yaml, write_tree


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A directory asset with a valid scope file, and no scanner binaries on PATH."""
    write_tree(
        tmp_path / "project",
        {
            "app.py": "print('hello')\n",
            "requirements.txt": "flask==3.0.0\n",
            "Dockerfile": "FROM scratch\n",
        },
    )
    (tmp_path / "htw.yaml").write_text(
        scope_yaml([{"id": "app", "path": "project"}]), encoding="utf-8"
    )
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    monkeypatch.setenv("PATH", str(empty_bin))
    monkeypatch.delenv("HTW_KILL_SWITCH", raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_version_and_help_state_the_authorized_use_rule(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as version:
        main(["--version"])
    assert version.value.code == 0
    assert capsys.readouterr().out.strip() == f"htw {__version__}"

    with pytest.raises(SystemExit):
        main(["--help"])
    assert "Only scan systems you own or are explicitly authorized to test." in " ".join(
        capsys.readouterr().out.split()
    )


def test_module_entry_point() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "htw", "--version"], capture_output=True, text=True, check=True
    )

    assert result.stdout.strip() == f"htw {__version__}"


def test_init_writes_a_scope_file_that_is_invalid_until_a_person_fills_it_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    workdir = tmp_path / "My Service"
    workdir.mkdir()
    monkeypatch.chdir(workdir)

    assert main(["init"]) == 0
    out = capsys.readouterr().out
    assert AUTHORIZED_USE in out

    text = (workdir / "htw.yaml").read_text()
    assert "id: my-service" in text and "type: directory" in text and "propose: false" in text
    # Nothing can be scanned on the strength of a generated file.
    assert main(["validate"]) == 2
    assert "required" in capsys.readouterr().err
    assert main(["scan"]) == 2

    assert main(["init"]) == 2
    assert "already exists" in capsys.readouterr().err


def test_init_in_a_git_checkout_proposes_the_remote_for_the_ownership_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(
        tmp_path, {".git/config": '[remote "origin"]\n\turl = git@github.com:acme/payments.git\n'}
    )
    monkeypatch.chdir(tmp_path)

    assert main(["init", "-c", "scope.yaml"]) == 0

    text = (tmp_path / "scope.yaml").read_text()
    assert "type: repository" in text and "git_remote: github.com/acme/payments" in text


def test_validate_reports_scope_status(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate"]) == 0
    assert "app: in scope" in capsys.readouterr().out

    (project / "htw.yaml").write_text(
        scope_yaml([{"id": "app", "path": "project", "expires": "2026-02-01"}]), encoding="utf-8"
    )
    assert main(["validate"]) == 2
    out = capsys.readouterr().out
    assert "app: WOULD BE REFUSED" in out and "expired on 2026-02-01" in out


def test_config_errors_exit_2_without_a_traceback(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["validate", "-c", "missing.yaml"]) == 2
    assert capsys.readouterr().err.startswith("htw: ")

    (project / "htw.yaml").write_text(
        scope_yaml(
            [{"id": "app", "path": "project"}], top="scanners:\n  sast:\n    tools: [nessus]\n"
        ),
        encoding="utf-8",
    )
    for command in (["validate"], ["detect"], ["scan"]):
        assert main(command) == 2
        assert "unknown tool 'nessus'" in capsys.readouterr().err


def test_detect_prints_the_stack_and_the_plan(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["detect"]) == 0
    out = capsys.readouterr().out

    assert "Python (1): app.py" in out
    assert "pip (1): requirements.txt" in out
    assert "Dockerfile (1): Dockerfile" in out
    assert "missing: semgrep is not installed" in out
    assert "not covered: static analysis of Python code" in out
    assert not (project / ".htw").exists(), "detect must not write state"


def test_detect_json_is_machine_readable(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["detect", "--json", "--asset", "app"]) == 0
    (entry,) = json.loads(capsys.readouterr().out)

    assert entry["asset"] == "app"
    assert [c["name"] for c in entry["stack"]["components"]["language"]] == ["Python"]
    sast = next(p for p in entry["plan"] if p["agent"] == "sast")
    assert sast["tools"] == [] and sast["missing_tools"] == ["semgrep", "bandit"]
    assert sast["uncovered"] == ["static analysis of Python code"]


def test_detect_and_scan_refuse_undeclared_targets(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for command in ("detect", "scan"):
        assert main([command, "--asset", "/etc"]) == 2
        err = capsys.readouterr().err
        assert "asset '/etc' is not declared" in err
        assert "Only allowlisted assets can be scanned." in err
    assert not (project / ".htw" / "reports").exists()


def test_scan_without_scanners_warns_and_succeeds(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["scan"]) == 0
    out = capsys.readouterr().out

    assert "[app] complete: 0 new, 0 reappeared, 0 resolved, 0 still open" in out
    assert "warning: gitleaks is not installed (no `gitleaks` on PATH). Install:" in out
    assert "not covered: credentials in files" in out
    reports = list((project / ".htw" / "reports" / "app").iterdir())
    assert len(reports) == 1 and (reports[0] / "report.md").exists()

    assert main(["scan", "--strict"]) == 3
    assert main(["audit-verify"]) == 0
    assert "hash chain intact" in capsys.readouterr().out


def test_scan_exit_codes_for_refusal_and_kill_switch(
    project: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HTW_KILL_SWITCH", "1")
    assert main(["scan"]) == 2
    assert "kill switch engaged" in capsys.readouterr().err
    monkeypatch.delenv("HTW_KILL_SWITCH")

    state = load_config(project / "htw.yaml").state_dir
    (state / "STOP").touch()
    assert main(["scan"]) == 2
    (state / "STOP").unlink()

    (project / "htw.yaml").write_text(
        scope_yaml([{"id": "app", "path": "project", "expires": "2026-02-01"}]), encoding="utf-8"
    )
    assert main(["scan"]) == 2
    assert "[app] REFUSED: not scanned." in capsys.readouterr().out


def test_audit_verify_detects_tampering(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan"]) == 0
    audit = project / ".htw" / "audit.jsonl"
    audit.write_text(audit.read_text().replace('"allowed": true', '"allowed": false', 1))
    capsys.readouterr()

    assert main(["audit-verify"]) == 1
    assert "TAMPERING OR DAMAGE DETECTED" in capsys.readouterr().err


def test_doctor_lists_every_scanner_with_install_and_network_notes(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out

    for tool in (
        "syft",
        "grype",
        "osv-scanner",
        "trivy",
        "gitleaks",
        "trufflehog",
        "semgrep",
        "bandit",
        "gosec",
    ):
        assert f"[missing] {tool}:" in out
    assert out.count("network:") == 9
    assert "A missing scanner is skipped with a warning" in out
