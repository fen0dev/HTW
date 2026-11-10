"""The process sandbox hides the home directory and does not widen the asset."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

from htw.core.runner import ToolRunner, _writable_mount
from htw.errors import ConfigError, ToolError
from htw.scanners.checkov import Checkov
from htw.scanners.grype import Grype
from htw.scanners.zizmor import Zizmor

from .conftest import scope_yaml
from .test_config import load


def test_offline_tools_drop_the_network_and_advisory_tools_do_not() -> None:
    assert Zizmor().isolates_network is True
    assert Checkov("iac").isolates_network is True
    assert Grype().isolates_network is False


def test_the_asset_and_the_home_directory_cannot_be_made_writable(tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="writable"):
        _writable_mount(tmp_path, tmp_path)
    with pytest.raises(ToolError, match="writable"):
        _writable_mount(Path.home(), tmp_path)


def test_sandbox_off_is_the_only_other_accepted_value(tmp_path: Path) -> None:
    config = load(
        tmp_path,
        scope_yaml([{"id": "app", "path": "."}]).replace(
            "version: 1\n", "version: 1\nrunner:\n  sandbox: off\n"
        ),
    )
    assert config.runner.sandbox == "off"
    broken = scope_yaml([{"id": "app", "path": "."}]).replace(
        "version: 1\n", "version: 1\nrunner:\n  sandbox: allow-all\n"
    )
    with pytest.raises(ConfigError, match="sandbox"):
        load(tmp_path, broken)


def test_bubblewrap_hides_the_home_directory_and_git_is_not_wrapped(tmp_path: Path) -> None:
    log = tmp_path / "bwrap.log"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "bwrap"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        "open(os.environ['HTW_BWRAP_LOG'], 'w').write('\\n'.join(sys.argv[1:]))\n"
        "if '--' in sys.argv:\n"
        "    rest = sys.argv[sys.argv.index('--') + 1:]\n"
        "    if rest == ['true']:\n"
        "        raise SystemExit(0)\n"
        "    os.execvp(rest[0], rest)\n"
        "raise SystemExit('no command')\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    asset = tmp_path / "asset"
    asset.mkdir()
    env = {
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "HOME": "/home/someone",
        "HTW_BWRAP_LOG": str(log),
        "AWS_SECRET_ACCESS_KEY": "must-not-leak",
    }
    tool = ToolRunner(environ=env, env_passthrough=["HTW_BWRAP_LOG"], sandbox="auto")
    result = tool.run([sys.executable, "-c", "print('ok')"], asset, offline=True)

    assert result.stdout.strip() == "ok"
    assert result.sandboxed is True
    recorded = log.read_text(encoding="utf-8").splitlines()
    assert "--unshare-net" in recorded
    assert "--ro-bind" in recorded
    assert str(asset.resolve()) in recorded
    assert "/home/someone" not in recorded
    assert "must-not-leak" not in recorded
    assert "AWS_SECRET_ACCESS_KEY" not in recorded

    log.unlink()
    plain = tool.run([sys.executable, "-c", "print('plain')"], asset, sandbox=False)
    assert plain.stdout.strip() == "plain"
    assert plain.sandboxed is False
    assert not log.exists()


def test_a_real_sandbox_cannot_read_or_modify_outside_the_asset(tmp_path: Path) -> None:
    if shutil.which("bwrap") is None:
        pytest.skip("bwrap is not installed")
    tool = ToolRunner(sandbox="auto")
    tool.ensure_sandbox()
    if not tool._sandbox_ready:
        pytest.skip(tool.sandbox_note or "bwrap cannot start")
    secret = tmp_path / "secret.txt"
    secret.write_text("top-secret")
    asset = tmp_path / "asset"
    asset.mkdir()
    (asset / "inside.txt").write_text("inside")
    report = tmp_path / "report"
    report.mkdir()
    code = (
        "from pathlib import Path\n"
        "print(Path('inside.txt').read_text())\n"
        "try:\n"
        "    Path('inside.txt').write_text('changed')\n"
        "    print('asset-write-ok')\n"
        "except OSError:\n"
        "    print('asset-write-blocked')\n"
        f"Path({str(report / 'out.txt')!r}).write_text('report')\n"
        "try:\n"
        f"    print(Path({str(secret)!r}).read_text())\n"
        "except OSError:\n"
        "    print('secret-blocked')\n"
    )
    result = tool.run([sys.executable, "-c", code], asset, offline=True, writable=(report,))

    assert "inside" in result.stdout
    assert "asset-write-blocked" in result.stdout
    assert "secret-blocked" in result.stdout
    assert "top-secret" not in result.stdout
    assert (asset / "inside.txt").read_text(encoding="utf-8") == "inside"
    assert (report / "out.txt").read_text(encoding="utf-8") == "report"
    assert result.sandboxed is True
