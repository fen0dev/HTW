"""The whole pipeline with the real agents and adapters, and canned scanner binaries."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import timedelta
from pathlib import Path

import pytest

from htw.agents.orchestrator import Orchestrator
from htw.agents.reporting import console_summary
from htw.agents.run import COMPLETE, INCOMPLETE, REFUSED, STOPPED
from htw.cli import _exit_code
from htw.core.audit import AuditLog
from htw.core.config import load_config
from htw.core.finding import Severity
from htw.errors import EXIT_FINDINGS, EXIT_INCOMPLETE, EXIT_OK, EXIT_REFUSED, KillSwitchEngaged

from .conftest import NOW, FakeRunner, scope_yaml, write_tree

MARKER = "SYNTHETIC-VALUE-THAT-MUST-NOT-BE-STORED"

PROJECT = {
    "app/server.py": """
        import subprocess

        def run(request):
            return eval(request.args["q"])

        def shell(request):
            return subprocess.call(request.args["cmd"], shell=True)
    """,
    "app/settings.py": "DEBUG = True\nAPI_KEY = 'placeholder'\n",
    "requirements.txt": "flask==3.0.0\njinja2==2.10\n",
    "vendor/lib/util.py": "eval('1')\n",
}


def semgrep_result(
    path: str, line: int, rule: str, severity: str = "ERROR", message: str = ""
) -> dict:
    return {
        "check_id": rule,
        "path": path,
        "start": {"line": line},
        "end": {"line": line},
        "extra": {"message": message or f"{rule} matched", "severity": severity, "metadata": {}},
    }


def grype_match(
    advisory: str, name: str, version: str, fixed: list[str], severity: str = "High"
) -> dict:
    return {
        "vulnerability": {
            "id": advisory,
            "severity": severity,
            "description": f"{name} is vulnerable",
            "fix": {"versions": fixed},
            "dataSource": f"https://github.com/advisories/{advisory}",
        },
        "artifact": {
            "name": name,
            "version": version,
            "type": "python",
            "locations": [{"path": "/requirements.txt"}],
        },
    }


def gitleaks_entry(path: str, line: int, secret: str = "REDACTED") -> dict:
    return {
        "RuleID": "generic-api-key",
        "Description": "Detected a Generic API Key",
        "StartLine": line,
        "EndLine": line,
        "Match": f"API_KEY = '{secret}'",
        "Secret": secret,
        "File": path,
    }


class Scanners:
    """Canned scanner binaries whose output the test can change between runs."""

    def __init__(self, installed=("syft", "grype", "gitleaks", "semgrep")):
        self.semgrep = [
            semgrep_result("app/server.py", 4, "python.eval-detected"),
            semgrep_result("app/server.py", 7, "python.subprocess-shell-true", "WARNING"),
            semgrep_result("vendor/lib/util.py", 1, "python.eval-detected"),
        ]
        self.grype = [
            grype_match("GHSA-462w-v97r-4m45", "jinja2", "2.10", ["2.10.1"]),
            grype_match("GHSA-g3rq-g295-4j3m", "jinja2", "2.10", ["2.11.3"], "Medium"),
        ]
        self.gitleaks = [gitleaks_entry("app/settings.py", 2)]
        self.broken: set[str] = set()
        self.stop_during: str | None = None
        handlers = {
            "syft": self._syft,
            "grype": self._json("grype", lambda: {"matches": self.grype}),
            "gitleaks": self._gitleaks,
            "semgrep": self._json("semgrep", lambda: {"results": self.semgrep, "errors": []}),
        }
        self.runner = FakeRunner({name: handlers[name] for name in installed})

    def _check(self, tool: str, argv: list[str]):
        if "version" in argv or "--version" in argv:
            return 0, "1.2.3\n"
        if self.stop_during == tool:
            raise KillSwitchEngaged(f"kill switch engaged; {tool} was stopped")
        if tool in self.broken:
            return 2, "", f"{tool}: something went wrong"
        return None

    def _json(self, tool: str, payload):
        def handler(argv, cwd):
            return self._check(tool, argv) or (0, json.dumps(payload()))

        return handler

    def _syft(self, argv, cwd):
        early = self._check("syft", argv)
        if early:
            return early
        for argument in argv:
            kind, _, path = argument.partition("=")
            if kind in ("cyclonedx-json", "syft-json"):
                Path(path).write_text('{"bomFormat": "CycloneDX"}')
        return 0, ""

    def _gitleaks(self, argv, cwd):
        early = self._check("gitleaks", argv)
        if early:
            return early
        Path(argv[argv.index("--report-path") + 1]).write_text(json.dumps(self.gitleaks))
        return 0, ""

    @property
    def scans(self) -> list[str]:
        return [c[0] for c in self.runner.calls if "version" not in c and "--version" not in c]


class Harness:
    def __init__(self, tmp_path: Path, scanners: Scanners, top: str = "", extra: str = "", **asset):
        self.tmp = tmp_path
        self.scanners = scanners
        self.root = write_tree(tmp_path / "project", PROJECT)
        self.clock = NOW
        self.write_scope(top, extra, **asset)

    def write_scope(self, top: str = "", extra: str = "", **asset) -> None:
        entry = {"id": "app", "path": "project", "extra": extra or "exclude: [vendor]", **asset}
        (self.tmp / "htw.yaml").write_text(scope_yaml([entry], top), encoding="utf-8")

    def scan(self, environ: dict[str, str] | None = None, feed_transport=None):
        self.clock += timedelta(hours=1)
        config = load_config(self.tmp / "htw.yaml")
        orchestrator = Orchestrator(
            config,
            now=lambda: self.clock,
            runner=self.scanners.runner,  # type: ignore[arg-type]
            environ=environ or {},
            feed_transport=feed_transport,
        )
        return orchestrator.scan()[0]

    @property
    def state(self) -> Path:
        return self.tmp / ".htw"

    def audit_events(self) -> list[dict]:
        path = self.state / "audit.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


@pytest.fixture
def scanners() -> Scanners:
    return Scanners()


@pytest.fixture
def harness(tmp_path: Path, scanners: Scanners) -> Harness:
    return Harness(tmp_path, scanners)


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


# --- the recurring-scan contract --------------------------------------------------


def test_first_scan_reports_everything_and_writes_the_reports(harness: Harness) -> None:
    before = tree_digest(harness.root)

    run = harness.scan()

    assert run.status == COMPLETE
    assert run.delta.counts()["new"] == 5
    assert {f.category for f in run.delta.new} == {"dependency", "secret", "sast"}
    assert all(f.fingerprint.startswith("htw1:") and f.priority for f in run.delta.new)
    assert harness.scanners.scans == ["syft", "grype", "gitleaks", "semgrep"]
    assert sorted(p.name for p in run.report_dir.iterdir()) == [
        "findings.sarif", "report.md", "sbom.cdx.json", "sbom.syft.json", "summary.json",
    ]  # fmt: skip
    # Report-only: the scanned tree is untouched and no proposals are written.
    assert tree_digest(harness.root) == before
    assert run.proposals == []

    report = (run.report_dir / "report.md").read_text()
    assert "## New findings" in report
    assert "Mode: report only" in report
    assert "Authorization: Test Owner, valid until 2027-01-01" in report
    summary = json.loads((run.report_dir / "summary.json").read_text())
    assert summary["status"] == "complete" and len(summary["delta"]["new"]) == 5
    assert summary["mode"] == "report-only"
    assert summary["stack"]["components"]["language"][0]["name"] == "Python"


def test_recurring_scans_report_only_what_changed(harness: Harness, scanners: Scanners) -> None:
    first = harness.scan()
    eval_fp = next(f.fingerprint for f in first.delta.new if f.rule_id == "python.eval-detected")

    second = harness.scan()
    assert not second.delta.changed
    assert second.delta.counts()["unchanged"] == 5
    assert "Nothing changed." in (second.report_dir / "report.md").read_text()
    assert "0 new, 0 reappeared, 0 resolved, 5 still open" in console_summary(second)

    # The eval is fixed, and unrelated lines are added above the other finding.
    scanners.semgrep = [
        semgrep_result("app/server.py", 9, "python.subprocess-shell-true", "WARNING")
    ]
    source = harness.root / "app/server.py"
    lines = [line for line in source.read_text().splitlines() if "eval(" not in line]
    source.write_text("# header\n# header\n# header\n" + "\n".join(lines) + "\n")
    third = harness.scan()
    assert [f.fingerprint for f in third.delta.resolved] == [eval_fp]
    assert third.delta.new == []
    assert third.delta.counts()["unchanged"] == 4

    # A new advisory is published for a package that has not changed.
    scanners.grype.append(
        grype_match("GHSA-h5c8-rqwp-cp95", "jinja2", "2.10", ["3.1.3"], "Critical")
    )
    fourth = harness.scan()
    assert [f.rule_id for f in fourth.delta.new] == ["GHSA-h5c8-rqwp-cp95"]
    assert fourth.delta.resolved == []

    # The same eval comes back, at another line, pushing the other finding down.
    source.write_text(
        source.read_text().replace(
            "def shell", 'def again(request):\n    return eval(request.args["q"])\n\ndef shell'
        )
    )
    scanners.semgrep = [
        semgrep_result("app/server.py", 9, "python.eval-detected"),
        semgrep_result("app/server.py", 12, "python.subprocess-shell-true", "WARNING"),
    ]
    fifth = harness.scan()
    assert [f.fingerprint for f in fifth.delta.reappeared] == [eval_fp]
    assert fifth.delta.new == [] and fifth.delta.resolved == []


def test_reappeared_findings_are_reported_as_such(harness: Harness, scanners: Scanners) -> None:
    harness.scan()
    kept = scanners.gitleaks
    scanners.gitleaks = []
    assert len(harness.scan().delta.resolved) == 1

    scanners.gitleaks = kept
    run = harness.scan()

    assert len(run.delta.reappeared) == 1 and run.delta.new == []
    assert "## Reappeared findings" in (run.report_dir / "report.md").read_text()
    assert "1 reappeared" in console_summary(run)


# --- graceful degradation ---------------------------------------------------------


def test_missing_scanners_are_skipped_with_install_instructions(tmp_path: Path) -> None:
    harness = Harness(tmp_path, Scanners(installed=("gitleaks",)))

    run = harness.scan()

    assert run.status == COMPLETE
    assert [f.category for f in run.delta.new] == ["secret"]
    missing = {o.tool: o for o in run.outcomes if o.status == "missing"}
    # Fallbacks were tried too, and every one says how to install it.
    assert set(missing) == {"syft", "grype", "osv-scanner", "trivy", "semgrep", "bandit"}
    assert all(
        "is not installed" in o.message and "Install:" in o.message for o in missing.values()
    )
    assert run.gaps == [
        "known vulnerabilities in dependencies (pip)",
        "software bill of materials (pip)",
        "static analysis of Python code",
    ]
    summary = console_summary(run)
    assert "warning: semgrep is not installed (no `semgrep` on PATH). Install:" in summary
    assert "not covered: static analysis of Python code" in summary
    report = (run.report_dir / "report.md").read_text()
    assert "**not installed**" in report and "### Not covered" in report
    assert _exit_code([run], None, strict=False) == EXIT_OK
    assert _exit_code([run], None, strict=True) == EXIT_INCOMPLETE


def test_fallback_tool_is_used_when_the_preferred_one_is_missing(tmp_path: Path) -> None:
    scanners = Scanners(installed=("gitleaks", "syft"))
    scanners.runner.handlers["bandit"] = lambda argv, cwd: (0, json.dumps({"results": []}))
    harness = Harness(tmp_path, scanners)

    run = harness.scan()

    assert [o.tool for o in run.outcomes if o.status == "ok"] == ["syft", "gitleaks", "bandit"]
    # Bandit covers Python, so the missing semgrep is not a gap and is not reported.
    assert "semgrep" not in {o.tool for o in run.outcomes}
    assert run.gaps == ["known vulnerabilities in dependencies (pip)"]


def test_no_scanners_at_all_still_produces_a_report(tmp_path: Path) -> None:
    harness = Harness(tmp_path, Scanners(installed=()))

    run = harness.scan()

    assert run.status == COMPLETE and run.delta.new == []
    assert len(run.gaps) == 4
    assert (run.report_dir / "report.md").exists()


def test_a_failing_scanner_makes_the_run_incomplete_and_resolves_nothing(
    harness: Harness, scanners: Scanners
) -> None:
    harness.scan()
    scanners.broken.add("semgrep")

    run = harness.scan()

    assert run.status == INCOMPLETE and run.has_errors
    failed = next(o for o in run.outcomes if o.tool == "semgrep")
    assert "semgrep failed (exit 2): semgrep: something went wrong" in failed.message
    assert run.delta.resolved == []
    assert len(run.delta.unverified) == 2
    assert "Open, not re-checked" in (run.report_dir / "report.md").read_text()
    assert "error: semgrep:" in console_summary(run)
    assert _exit_code([run], None, strict=False) == EXIT_INCOMPLETE

    scanners.broken.clear()
    assert harness.scan().delta.counts()["unchanged"] == 5


def test_a_wrapper_bug_costs_one_tool_not_the_run(harness: Harness, scanners: Scanners) -> None:
    def explode(argv, cwd):
        raise RuntimeError("unexpected shape")

    scanners.runner.handlers["grype"] = explode

    run = harness.scan()

    assert run.status == INCOMPLETE
    assert "could not be processed (RuntimeError)" in next(
        o.message for o in run.outcomes if o.tool == "grype"
    )
    assert {f.category for f in run.delta.new} == {"secret", "sast"}


# --- guardrails -------------------------------------------------------------------


def test_expired_authorization_refuses_before_anything_runs(
    tmp_path: Path, scanners: Scanners
) -> None:
    harness = Harness(tmp_path, scanners, expires="2026-06-30")

    run = harness.scan()

    assert run.status == REFUSED
    assert "expired on 2026-06-30" in run.decision.reasons[0]
    assert scanners.runner.calls == []
    assert run.report_dir is None and not (harness.state / "reports").exists()
    assert "REFUSED: not scanned" in console_summary(run)
    assert _exit_code([run], None, strict=False) == EXIT_REFUSED
    (event,) = harness.audit_events()
    assert (event["event"], event["allowed"]) == ("scope_decision", False)


def test_rate_limit_refuses_a_scan_that_comes_too_soon(tmp_path: Path, scanners: Scanners) -> None:
    harness = Harness(
        tmp_path, scanners, extra="exclude: [vendor]\nlimits:\n  min_interval_minutes: 120"
    )

    assert harness.scan().status == COMPLETE
    second = harness.scan()
    assert second.status == REFUSED and "rate limit" in second.decision.reasons[0]
    assert harness.scan().status == COMPLETE


def test_kill_switch_blocks_the_scan(harness: Harness, scanners: Scanners) -> None:
    harness.state.mkdir()
    (harness.state / "STOP").touch()

    with pytest.raises(KillSwitchEngaged, match="stop file"):
        harness.scan()
    with pytest.raises(KillSwitchEngaged, match="HTW_KILL_SWITCH"):
        (harness.state / "STOP").unlink()
        harness.scan(environ={"HTW_KILL_SWITCH": "1"})

    assert scanners.runner.calls == []
    assert [e["event"] for e in harness.audit_events()] == ["kill_switch", "kill_switch"]


def test_kill_switch_during_a_run_discards_partial_results(
    harness: Harness, scanners: Scanners
) -> None:
    harness.scan()
    scanners.stop_during = "gitleaks"
    scanners.semgrep = []

    run = harness.scan()

    assert run.status == STOPPED
    assert "semgrep" not in scanners.scans[4:]
    # Nothing was resolved or recorded on the strength of half a run.
    assert run.delta.counts() == {
        "new": 0,
        "reappeared": 0,
        "unchanged": 0,
        "resolved": 0,
        "unverified": 0,
    }
    assert not (run.report_dir / "report.md").exists()
    assert _exit_code([run], None, strict=False) == EXIT_REFUSED
    scanners.stop_during = None
    assert len(harness.scan().delta.resolved) == 2


def test_stopped_run_does_not_continue_with_other_assets(
    tmp_path: Path, scanners: Scanners
) -> None:
    write_tree(tmp_path / "project", PROJECT)
    write_tree(tmp_path / "other", {"main.py": "print(1)\n"})
    (tmp_path / "htw.yaml").write_text(
        scope_yaml([{"id": "app", "path": "project"}, {"id": "other", "path": "other"}]),
        encoding="utf-8",
    )
    scanners.stop_during = "syft"
    orchestrator = Orchestrator(
        load_config(tmp_path / "htw.yaml"),
        now=lambda: NOW,
        runner=scanners.runner,  # type: ignore[arg-type]
        environ={},
    )

    runs = orchestrator.scan()

    assert [(r.asset.id, r.status) for r in runs] == [("app", STOPPED)]


def test_only_declared_assets_can_be_scanned(harness: Harness, scanners: Scanners) -> None:
    from htw.errors import ConfigError

    orchestrator = Orchestrator(
        load_config(harness.tmp / "htw.yaml"),
        runner=scanners.runner,
        environ={},  # type: ignore[arg-type]
    )

    for target in ("/etc", "../somewhere-else", "https://example.invalid"):
        with pytest.raises(ConfigError, match="not declared"):
            orchestrator.scan([target])
    assert scanners.runner.calls == []


def test_excluded_paths_are_not_reported(harness: Harness) -> None:
    run = harness.scan()

    assert not any((f.location.path or "").startswith("vendor/") for f in run.delta.new)


def test_disabled_agents_do_not_run(tmp_path: Path, scanners: Scanners) -> None:
    harness = Harness(
        tmp_path,
        scanners,
        top="scanners:\n  sast:\n    enabled: false\n  deps_sbom:\n    tools: [syft]\n",
    )

    run = harness.scan()

    assert scanners.scans == ["syft", "gitleaks"]
    sast = next(p for p in run.plans if p.agent == "sast")
    assert not sast.applicable and sast.reason == "disabled in the scope file"
    assert "not applicable" in (run.report_dir / "report.md").read_text()


def test_secret_values_never_reach_any_output(harness: Harness, scanners: Scanners) -> None:
    # A scanner that fails to redact, and messages that quote the value.
    scanners.gitleaks = [gitleaks_entry("app/settings.py", 2, secret=MARKER)]
    scanners.semgrep = [
        semgrep_result(
            "app/settings.py", 2, "python.hardcoded", message=f"Hardcoded api_key = '{MARKER}'"
        )
    ]

    run = harness.scan()
    harness.scan()

    assert len(run.delta.new) == 4
    leaked = [
        path.relative_to(harness.state).as_posix()
        for path in harness.state.rglob("*")
        if path.is_file() and MARKER.encode() in path.read_bytes()
    ]
    assert leaked == []
    assert MARKER not in console_summary(run)


def test_hostile_scanner_text_cannot_inject_into_reports(
    harness: Harness, scanners: Scanners
) -> None:
    scanners.semgrep = [
        semgrep_result(
            "app/server.py",
            4,
            "rule.<img src=x onerror=alert(1)>",
            message="![pixel](https://evil.invalid/t.png) [approve](https://evil.invalid) \x1b[2J|a|b|",
        )
    ]
    scanners.grype = [
        grype_match("GHSA-462w-v97r-4m45", "evil`pkg\x1b]0;pwned\x07", "1.0", ["2.0"])
    ]

    run = harness.scan()
    report = (run.report_dir / "report.md").read_text()
    text = report + console_summary(run) + (run.report_dir / "findings.sarif").read_text()

    assert "\x1b" not in text and "\x07" not in text
    assert "![pixel]" not in report and "[approve](" not in report
    # Inside a code span the text is inert; anywhere else it must be escaped.
    assert "<img" not in re.sub(r"`[^`\n]*`", "", report)
    # The injected pipes are escaped, so the table keeps its shape.
    table_rows = [line for line in report.splitlines() if line.startswith("| P")]
    assert all(line.replace("\\|", "").count("|") == 7 for line in table_rows)


# --- suppressions, priorities, exit codes -----------------------------------------


def test_suppressed_findings_are_hidden_until_the_suppression_expires(harness: Harness) -> None:
    first = harness.scan()
    target = next(f for f in first.delta.new if f.category == "secret")
    (harness.tmp / "suppressions.yaml").write_text(
        f"""\
suppressions:
  - fingerprint: "{target.fingerprint}"
    kind: false_positive
    reason: Placeholder value in a sample settings file
    author: jane@example.invalid
    expires: 2026-11-12
""",
        encoding="utf-8",
    )

    second = harness.scan()
    assert list(second.suppressed) == [target.fingerprint]
    assert len(second.visible(second.delta.unchanged)) == 4
    report = (second.report_dir / "report.md").read_text()
    assert (
        "| Suppressed | 1 | |" in report and "Placeholder value in a sample settings file" in report
    )
    sarif = json.loads((second.report_dir / "findings.sarif").read_text())
    suppressed = [
        r for sarif_run in sarif["runs"] for r in sarif_run["results"] if r.get("suppressions")
    ]
    assert [r["partialFingerprints"]["htw/v1"] for r in suppressed] == [target.fingerprint]
    assert "false_positive" in suppressed[0]["suppressions"][0]["justification"]

    harness.clock += timedelta(days=3)
    third = harness.scan()
    assert third.suppressed == {}
    assert [s.fingerprint for s in third.expired_suppressions] == [target.fingerprint]
    assert "**expired** on 2026-11-12" in (third.report_dir / "report.md").read_text()


def test_new_findings_under_suppression_do_not_fail_the_build(
    harness: Harness, scanners: Scanners
) -> None:
    first = harness.scan()
    assert _exit_code([first], Severity.HIGH, strict=False) == EXIT_FINDINGS
    assert _exit_code([first], Severity.CRITICAL, strict=False) == EXIT_OK
    assert _exit_code([first], None, strict=False) == EXIT_OK

    # Unchanged findings never fail a later run: only what is new does.
    second = harness.scan()
    assert _exit_code([second], Severity.LOW, strict=False) == EXIT_OK


def test_asset_criticality_raises_priority(tmp_path: Path, scanners: Scanners) -> None:
    normal = Harness(tmp_path / "a", scanners).scan()
    critical = Harness(tmp_path / "b", scanners, criticality="critical").scan()

    def priority(run, rule):
        return next(f.priority for f in run.delta.new if f.rule_id == rule)

    assert priority(normal, "python.eval-detected") == "P1"
    assert priority(critical, "python.eval-detected") == "P0"
    assert priority(normal, "GHSA-g3rq-g295-4j3m") == "P2"
    assert priority(critical, "GHSA-g3rq-g295-4j3m") == "P1"


# --- audit trail ------------------------------------------------------------------


def test_every_run_leaves_a_verifiable_audit_trail(harness: Harness) -> None:
    harness.scan(environ={"GITHUB_ACTOR": "octo", "GITHUB_TOKEN": "must-not-be-logged"})
    harness.scan()

    events = harness.audit_events()
    first_run = [e["event"] for e in events[:7]]
    assert first_run == [
        "scope_decision", "run_started",
        "tool_executed", "tool_executed", "tool_executed", "tool_executed",
        "run_finished",
    ]  # fmt: skip
    assert events[0]["authorized_by"] == "Test Owner"
    assert events[0]["authorization_expires"] == "2027-01-01"
    assert events[1]["initiator"]["github_actor"] == "octo"
    assert events[1]["mode"] == "report-only"
    assert [(e["tool"], e["tool_version"], e["level"]) for e in events[2:6]] == [
        ("syft", "1.2.3", "L0"), ("grype", "1.2.3", "L0"),
        ("gitleaks", "1.2.3", "L0"), ("semgrep", "1.2.3", "L0"),
    ]  # fmt: skip
    assert events[6]["delta"]["new"] == 5
    assert "must-not-be-logged" not in json.dumps(events)
    result = AuditLog(harness.state / "audit.jsonl").verify()
    assert result.ok and result.records == 14


def test_state_files_are_private_to_the_operator(harness: Harness) -> None:
    harness.scan()

    for name in (".", "state.db", "audit.jsonl"):
        assert (harness.state / name).stat().st_mode & 0o077 == 0, name
    assert os.access(harness.state, os.W_OK)
