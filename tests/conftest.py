from __future__ import annotations

import shutil
import textwrap
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from htw.core.runner import CommandResult

FIXTURES = Path(__file__).parent / "fixtures"
STACKS = FIXTURES / "stacks"
VULNERABLE_APP = FIXTURES / "vulnerable-app"

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip tests that need an external scanner binary that is not installed."""
    for item in items:
        for marker in item.iter_markers(name="scanner"):
            missing = [name for name in marker.args if shutil.which(name) is None]
            if missing:
                item.add_marker(
                    pytest.mark.skip(reason=f"external scanner not installed: {', '.join(missing)}")
                )


def write_tree(root: Path, files: Mapping[str, str]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
    return root


ASSET_TEMPLATE = """\
  - id: {id}
    type: directory
    path: {path}
    owner: platform-team
    criticality: {criticality}
    authorization:
      authorized_by: Test Owner
      authorized_on: 2026-01-01
      expires_on: {expires}
{extra}"""


def scope_yaml(
    assets: Sequence[Mapping[str, str]],
    top: str = "",
) -> str:
    rendered = []
    for asset in assets:
        extra = textwrap.indent(textwrap.dedent(asset.get("extra", "")).strip("\n"), "    ")
        rendered.append(
            ASSET_TEMPLATE.format(
                id=asset["id"],
                path=asset["path"],
                criticality=asset.get("criticality", "medium"),
                expires=asset.get("expires", "2027-01-01"),
                extra=extra + "\n" if extra else "",
            )
        )
    return "version: 1\n" + textwrap.dedent(top) + "assets:\n" + "".join(rendered)


@pytest.fixture
def make_scope(tmp_path: Path) -> Callable[..., Path]:
    """Write a scope file in tmp_path and return its path."""

    def _make(assets: Sequence[Mapping[str, str]], top: str = "") -> Path:
        path = tmp_path / "htw.yaml"
        path.write_text(scope_yaml(assets, top), encoding="utf-8")
        return path

    return _make


@pytest.fixture
def target(tmp_path: Path) -> Path:
    """An empty directory to use as a scan target."""
    directory = tmp_path / "target"
    directory.mkdir()
    return directory


class FakeRunner:
    """Stands in for ToolRunner: answers from canned handlers instead of running binaries."""

    def __init__(self, handlers: Mapping[str, Callable[[list[str], Path], CommandResult | tuple]]):
        self.handlers = dict(handlers)
        self.calls: list[list[str]] = []

    def which(self, binary: str) -> str | None:
        return f"/fake/bin/{binary}" if binary in self.handlers else None

    def run(self, argv, cwd, timeout_seconds=None, extra_env=None, **_kwargs) -> CommandResult:
        argv = list(argv)
        self.calls.append(argv)
        result = self.handlers[argv[0]](argv, Path(cwd))
        if isinstance(result, CommandResult):
            return result
        returncode, stdout, *rest = result
        return CommandResult(tuple(argv), returncode, stdout, rest[0] if rest else "", 0.01)
