"""End-to-end tests against the real scanner binaries.

Each test is skipped when its scanner is not installed. They only ever scan a
temporary copy of `tests/fixtures/vulnerable-app`: a copy, because Semgrep's default
ignore list skips directories named `tests`, and so that the tests can modify it.

Semgrep, Grype, OSV-Scanner and Trivy need network access for rules or advisory data.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from htw.cli import main
from htw.core.config import AgentSettings, load_config
from htw.core.runner import ToolRunner
from htw.detect import detect_stack
from htw.scanners.bandit import Bandit
from htw.scanners.base import ScanContext
from htw.scanners.gitleaks import Gitleaks
from htw.scanners.gosec import Gosec
from htw.scanners.grype import Grype
from htw.scanners.osv_scanner import OsvScanner
from htw.scanners.semgrep import Semgrep
from htw.scanners.syft import Syft
from htw.scanners.trivy import Trivy
from htw.scanners.trufflehog import TruffleHog

from .conftest import VULNERABLE_APP, scope_yaml

# The synthetic values committed in the fixture. They must never appear in output.
FIXTURE_VALUES = ("9f2c7a41d8e6b3505c1a9e7d4f2b8a63", "Zx8Kq2LmVt4Rw9Yb7Nc1Hd6Jf3Pg5Sa0")


@pytest.fixture
def app(tmp_path: Path) -> Path:
    target = tmp_path / "vulnerable-app"
    shutil.copytree(VULNERABLE_APP, target)
    return target


@pytest.fixture
def context(app: Path, tmp_path: Path):
    def _make(options: dict | None = None) -> ScanContext:
        (tmp_path / "htw.yaml").write_text(
            scope_yaml([{"id": "fixture", "path": "vulnerable-app"}]), encoding="utf-8"
        )
        artifacts = tmp_path / "artifacts"
        artifacts.mkdir(exist_ok=True)
        return ScanContext(
            asset=load_config(tmp_path / "htw.yaml").assets[0],
            root=app,
            profile=detect_stack(app),
            runner=ToolRunner(timeout_seconds=600),
            settings=AgentSettings(options=options or {}),
            config_dir=tmp_path,
            artifacts_dir=artifacts,
        )

    return _make


def git(cwd: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=HTW Test", "-c", "user.email=test@example.invalid",
         "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *arguments],
        cwd=cwd, check=True, capture_output=True,
    )  # fmt: skip


def dump(findings) -> str:
    return json.dumps([f.to_dict() for f in findings]) + "".join(f.context or "" for f in findings)


@pytest.mark.scanner("gitleaks")
def test_gitleaks_finds_the_fixture_credentials_without_reading_them_out(context) -> None:
    ctx = context()
    adapter = Gitleaks()

    findings = adapter.scan(ctx)

    assert adapter.version(ctx.runner, ctx.root)
    located = {(f.location.path, f.location.start_line) for f in findings}
    assert {("app/settings.py", 6), ("app/settings.py", 7)} <= located
    assert all(f.category == "secret" and f.rule_id for f in findings)
    for value in FIXTURE_VALUES:
        assert value not in dump(findings)


@pytest.mark.scanner("gitleaks")
def test_gitleaks_finds_credentials_that_only_exist_in_git_history(context, app: Path) -> None:
    git(app, "init", "-q")
    git(app, "add", "-A")
    git(app, "commit", "-q", "-m", "initial")
    (app / "app" / "settings.py").write_text('"""Credentials removed."""\n')
    git(app, "commit", "-q", "-am", "remove credentials")

    in_history = Gitleaks().scan(context())
    in_files = Gitleaks().scan(context({"history": False}))

    assert {f.location.path for f in in_history} == {"app/settings.py"}
    assert all(f.location.commit for f in in_history)
    assert in_files == []


@pytest.mark.scanner("trufflehog")
def test_trufflehog_reports_a_detector_and_a_location_only(context, app: Path) -> None:
    # Assembled here rather than committed: a connection string is the kind of literal
    # push protection exists to catch.
    password = "fixture-only-" + "pass" * 3
    url = "postgres://" + "fixture_user:" + password + "@db.fixture.invalid:5432/app"
    (app / "app" / "database.py").write_text(f'DATABASE_URL = "{url}"\n')

    findings = TruffleHog().scan(context())

    assert [(f.location.path, f.location.start_line) for f in findings] == [("app/database.py", 1)]
    assert findings[0].rule_id
    assert password not in dump(findings)


@pytest.mark.scanner("bandit")
def test_bandit_finds_the_unsafe_python(context) -> None:
    findings = Bandit().scan(context())

    rules = {f.rule_id for f in findings}
    assert {"B602", "B301", "B506", "B307", "B608"} <= rules
    assert all(f.location.start_line and f.identifiers for f in findings)
    # Bandit quotes hardcoded passwords in its message (B105); the wrapper masks them.
    assert "B105" in rules
    for value in FIXTURE_VALUES:
        assert value not in dump(findings)


@pytest.mark.scanner("gosec", "go")
def test_gosec_finds_the_unsafe_go(context) -> None:
    findings = Gosec().scan(context())

    assert {"G204", "G401"} <= {f.rule_id for f in findings}
    assert {f.location.path for f in findings} == {"cmd/tool/main.go"}


@pytest.mark.scanner("semgrep")
def test_semgrep_finds_unsafe_code_in_several_languages(context) -> None:
    findings = Semgrep().scan(context())

    paths = {f.location.path for f in findings}
    assert {"app/server.py", "web/index.js"} <= paths
    assert all(f.location.start_line and f.message for f in findings)
    # Semgrep withholds matched lines from logged-out users; HTW does not copy them either.
    assert "request.args" not in dump(findings)


@pytest.mark.scanner("syft", "grype")
def test_syft_writes_an_sbom_and_grype_matches_it(context) -> None:
    ctx = context()

    assert Syft().scan(ctx) == []
    sbom = json.loads(ctx.artifacts["sbom"].read_text())
    names = {component["name"].lower() for component in sbom["components"]}
    findings = Grype().scan(ctx)

    assert sbom["bomFormat"] == "CycloneDX"
    assert {"jinja2", "pyyaml", "requests", "lodash", "minimist"} <= names
    assert_dependency_findings(findings)


@pytest.mark.scanner("osv-scanner")
def test_osv_scanner_matches_the_outdated_pins(context) -> None:
    assert_dependency_findings(OsvScanner().scan(context()))


@pytest.mark.scanner("trivy")
def test_trivy_matches_the_outdated_pins(context) -> None:
    assert_dependency_findings(Trivy().scan(context()))


def assert_dependency_findings(findings) -> None:
    by_package = {}
    for finding in findings:
        by_package.setdefault((finding.package.ecosystem, finding.package.name.lower()), []).append(
            finding
        )

    assert ("PyPI", "jinja2") in by_package and ("npm", "lodash") in by_package
    jinja = by_package[("PyPI", "jinja2")]
    assert {f.location.path for f in jinja} == {"requirements.txt"}
    # OSV-Scanner normalizes the pin to 2.10.0; the other tools report it as written.
    assert {f.package.version for f in jinja} <= {"2.10", "2.10.0"}
    assert any(f.package.fixed_versions for f in jinja)
    assert all(f.rule_id.startswith(("GHSA-", "CVE-", "PYSEC-")) for f in jinja)
    assert {f.location.path for f in by_package[("npm", "lodash")]} == {"package-lock.json"}


@pytest.mark.scanner("gitleaks", "bandit")
def test_full_pipeline_with_offline_scanners(
    app: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Scan, rescan, fix, rescan: through the CLI, with real binaries, without network."""
    (tmp_path / "htw.yaml").write_text(
        scope_yaml(
            [{"id": "fixture", "path": "vulnerable-app"}],
            top="scanners:\n  deps_sbom:\n    enabled: false\n  secrets:\n    tools: [gitleaks]\n"
            "  sast:\n    tools: [bandit]\n",
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("HTW_KILL_SWITCH", raising=False)
    before = sorted(p.relative_to(app).as_posix() for p in app.rglob("*"))

    def latest_summary() -> dict:
        reports = sorted((tmp_path / ".htw" / "reports" / "fixture").iterdir())
        return json.loads((reports[-1] / "summary.json").read_text())

    assert main(["scan", "--fail-on", "high"]) == 1
    first = latest_summary()
    assert first["status"] == "complete" and len(first["delta"]["new"]) >= 8
    assert sorted(p.relative_to(app).as_posix() for p in app.rglob("*")) == before

    # Nothing changed: nothing to report, and nothing to fail on.
    assert main(["scan", "--fail-on", "low"]) == 0
    second = latest_summary()
    assert second["delta"]["new"] == [] and second["delta"]["resolved"] == []
    assert second["delta"]["unchanged"] == len(first["delta"]["new"])

    # Remove the credentials and one unsafe call; add a header so every line moves.
    (app / "app" / "settings.py").write_text('"""Credentials now come from the environment."""\n')
    server = app / "app" / "server.py"
    source = server.read_text().replace("    return eval(expression)", "    return int(expression)")
    server.write_text("# reviewed\n# reviewed\n" + source)
    assert main(["scan", "--fail-on", "low"]) == 0
    third = latest_summary()
    assert third["delta"]["new"] == []
    assert len(third["delta"]["resolved"]) >= 3
    assert set(third["delta"]["resolved"]) <= set(first["delta"]["new"])

    assert main(["audit-verify"]) == 0
    capsys.readouterr()
    state = tmp_path / ".htw"
    for path in (p for p in state.rglob("*") if p.is_file()):
        content = path.read_bytes()
        for value in FIXTURE_VALUES:
            assert value.encode() not in content, path
