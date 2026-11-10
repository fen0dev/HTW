"""Suppressions, audit log, redaction, Markdown escaping, paths, scoring, runner."""

from __future__ import annotations

import json
import os
import sys
from datetime import date
from pathlib import Path

import pytest

from htw.core.audit import AuditLog, initiator
from htw.core.finding import Finding, Severity, sanitize_finding
from htw.core.markdown import code, link, md
from htw.core.paths import is_excluded, safe_read_lines, to_relative
from htw.core.redact import REDACTED, clean_text, redact_text
from htw.core.runner import ToolRunner
from htw.core.scope import KillSwitch
from htw.core.scoring import priority_for
from htw.core.suppressions import load_suppressions
from htw.errors import ConfigError, KillSwitchEngaged, ToolError

from .helpers import (
    FAKE_AWS_KEY_ID,
    FAKE_DATABASE_URL,
    FAKE_GITHUB_TOKEN,
    FAKE_OPAQUE_TOKEN,
    FAKE_PRIVATE_KEY,
    dependency_finding,
    sast_finding,
)

TODAY = date(2026, 11, 10)
FP_A = "htw1:" + "a" * 32
FP_B = "htw1:" + "b" * 32


# --- suppressions -----------------------------------------------------------------


def suppressions_file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "suppressions.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_suppressions_split_into_active_and_expired(tmp_path: Path) -> None:
    path = suppressions_file(
        tmp_path,
        f"""\
suppressions:
  - fingerprint: "{FP_A}"
    kind: false_positive
    reason: Test fixture, not a real key
    author: jane@example.invalid
    expires: 2026-11-10
  - fingerprint: "{FP_B}"
    kind: accepted_risk
    reason: Internal-only service
    author: jane@example.invalid
    expires: "2026-11-09"
""",
    )

    loaded = load_suppressions(path, TODAY)

    # Valid through its last day; the day after it no longer applies.
    assert list(loaded.active) == [FP_A]
    assert loaded.get(FP_A).kind == "false_positive"
    assert loaded.get(FP_B) is None
    assert [s.fingerprint for s in loaded.expired] == [FP_B]


def test_missing_or_empty_suppressions_file_means_none(tmp_path: Path) -> None:
    assert load_suppressions(tmp_path / "absent.yaml", TODAY).active == {}
    assert load_suppressions(suppressions_file(tmp_path, ""), TODAY).active == {}
    assert load_suppressions(suppressions_file(tmp_path, "suppressions: []\n"), TODAY).active == {}


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (
            "{fingerprint: abc, kind: false_positive, reason: r, author: a, expires: 2027-01-01}",
            "finding id",
        ),
        (
            f'{{fingerprint: "{FP_A}", kind: wontfix, reason: r, author: a, expires: 2027-01-01}}',
            "kind",
        ),
        (
            f'{{fingerprint: "{FP_A}", kind: accepted_risk, author: a, expires: 2027-01-01}}',
            "reason",
        ),
        (
            f'{{fingerprint: "{FP_A}", kind: accepted_risk, reason: r, expires: 2027-01-01}}',
            "author",
        ),
        (
            f'{{fingerprint: "{FP_A}", kind: accepted_risk, reason: r, author: a}}',
            "cannot be permanent",
        ),
        (
            f'{{fingerprint: "{FP_A}", kind: accepted_risk, reason: r, author: a, expires: never}}',
            "cannot be permanent",
        ),
        (
            f'{{fingerprint: "{FP_A}", kind: accepted_risk, reason: r, author: a, expires: 2027-01-01, path: "*"}}',
            "unknown key",
        ),
    ],
)
def test_incomplete_suppressions_are_rejected(tmp_path: Path, entry: str, message: str) -> None:
    path = suppressions_file(tmp_path, f"suppressions:\n  - {entry}\n")

    with pytest.raises(ConfigError, match=message):
        load_suppressions(path, TODAY)


# --- audit log --------------------------------------------------------------------


def test_audit_log_chains_records_and_verifies(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("run_started", asset="app")
    log.append("tool_executed", tool="semgrep", argv=["semgrep", "scan"])
    # A new process continues the same chain.
    AuditLog(path).append("run_finished", status="complete")

    records = [json.loads(line) for line in path.read_text().splitlines()]

    assert [r["seq"] for r in records] == [1, 2, 3]
    assert records[0]["prev_hash"] == "0" * 64
    assert records[1]["prev_hash"] == records[0]["hash"]
    assert records[2]["prev_hash"] == records[1]["hash"]
    result = AuditLog(path).verify()
    assert result.ok and result.records == 3
    assert (path.stat().st_mode & 0o777) == 0o600


def tampered(tmp_path: Path, mutate) -> AuditLog:
    path = tmp_path / "audit.jsonl"
    path.unlink(missing_ok=True)
    log = AuditLog(path)
    for index in range(4):
        log.append("tool_executed", tool=f"tool-{index}")
    lines = path.read_text().splitlines()
    path.write_text("\n".join(mutate(lines)) + "\n")
    return AuditLog(path)


def test_audit_log_detects_an_edited_record(tmp_path: Path) -> None:
    result = tampered(
        tmp_path, lambda lines: [lines[0], lines[1].replace("tool-1", "tool-x"), *lines[2:]]
    ).verify()

    assert not result.ok
    assert result.records == 1
    assert "line 2: record was modified" in result.error


def test_audit_log_detects_a_removed_record(tmp_path: Path) -> None:
    result = tampered(tmp_path, lambda lines: [lines[0], *lines[2:]]).verify()

    assert not result.ok
    assert "chain broken" in result.error


def test_audit_log_detects_reordering_and_garbage(tmp_path: Path) -> None:
    reordered = tampered(tmp_path, lambda lines: [lines[1], lines[0], *lines[2:]]).verify()
    assert not reordered.ok

    garbage = tampered(tmp_path, lambda lines: [*lines[:2], "not json", *lines[2:]]).verify()
    assert not garbage.ok and "line 3: not a valid record" in garbage.error


def test_audit_log_of_nothing_is_valid(tmp_path: Path) -> None:
    assert AuditLog(tmp_path / "none.jsonl").verify().ok


def test_initiator_records_ci_identity_without_other_environment() -> None:
    info = initiator({"GITHUB_ACTOR": "octo", "CI": "true", "AWS_SECRET_ACCESS_KEY": "nope"})

    assert info["github_actor"] == "octo"
    assert info["ci"] == "true"
    assert "user" in info
    assert "nope" not in json.dumps(info)


# --- redaction --------------------------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        FAKE_AWS_KEY_ID,
        FAKE_GITHUB_TOKEN,
        FAKE_OPAQUE_TOKEN,
        FAKE_PRIVATE_KEY,
    ],
)
def test_credential_shaped_text_is_masked(secret: str) -> None:
    redacted = redact_text(f"Found credential {secret} in file")

    assert secret not in redacted
    assert REDACTED in redacted
    assert redacted.startswith("Found credential") and redacted.endswith("in file")


def test_assignments_and_url_credentials_are_masked() -> None:
    # Built from parts so that this file does not itself look like it holds a credential.
    name = "pass" + "word"
    assert redact_text(f"{name} = 'hunter2-is-bad'") == f"{name} = '{REDACTED}'"
    assert redact_text("DB_TOKEN: 8f3k2j5h") == f"DB_TOKEN: {REDACTED}"
    assert redact_text(FAKE_DATABASE_URL) == f"postgres://{REDACTED}@db.fixture.invalid:5432/app"


def test_ordinary_scanner_prose_is_left_alone() -> None:
    prose = [
        "Detected a hardcoded password: consider using a secrets manager",
        "The secret = required argument is missing",
        "sha256 digest 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 changed",
        "See https://example.invalid/rules/python.lang.security.audit.eval-detected.eval-detected",
        "Upgrade org.apache.logging.log4j:log4j-core to 2.17.1",
    ]

    for text in prose:
        assert redact_text(text) == text


def test_clean_text_flattens_redacts_and_bounds() -> None:
    cleaned = clean_text(f"line one\n\tline two   token={FAKE_OPAQUE_TOKEN}\n")
    assert cleaned == f"line one line two token={REDACTED}"

    long = clean_text("word " * 500, limit=50)
    assert len(long) <= 50 and long.endswith("…")
    assert clean_text(None) == ""


# --- markdown and terminal safety -------------------------------------------------


def test_markdown_escaping_neutralizes_injected_markup() -> None:
    hostile = "![x](https://evil.invalid/p.png) <script>alert(1)</script> [click](javascript:x) | a"

    escaped = md(hostile)

    assert "![" not in escaped and "<script>" not in escaped and "[click]" not in escaped
    assert "\\|" in escaped
    assert md("line\nbreak\r\n# heading") == "line break \\# heading"
    assert md(None) == ""


def test_code_spans_cannot_be_broken_out_of() -> None:
    assert code("pkg`; rm -rf /`") == "`pkg'; rm -rf /'`"
    assert code("a|b\nc") == "`a\\|b c`"
    assert code("") == ""


def test_links_are_only_rendered_for_plain_http_urls() -> None:
    assert link("https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc") == (
        "<https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc>"
    )
    assert link("javascript:alert(1)") is None
    assert link("https://example.invalid/a b") is None
    assert link("https://example.invalid/>[x](y)") is None
    assert link("https://example.invalid/" + "a" * 400) is None


def test_control_characters_are_stripped_from_scanner_strings() -> None:
    finding = dependency_finding(name="evil\x1b[2J\x1b[Hpkg")
    finding.message = "first\x07 line\nsecond\x1b]0;title\x07"
    finding.location.path = "dir/\x1b[31mred.txt"

    sanitize_finding(finding)

    for text in (finding.package.name, finding.message, finding.location.path):
        assert not any(ord(c) < 32 or ord(c) == 127 for c in text)
    assert finding.package.name == "evil [2J [Hpkg"


def test_findings_round_trip_through_storage_form() -> None:
    original = dependency_finding()
    original.fingerprint, original.priority, original.context = "htw1:x", "P1", "never stored"

    data = original.to_dict()
    restored = Finding.from_dict(json.loads(json.dumps(data)))

    assert "context" not in data
    assert restored.context is None
    restored.context = original.context
    assert restored == original
    assert "package" not in sast_finding().to_dict()


# --- paths ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "patterns", "expected"),
    [
        ("vendor/lib/a.go", ["vendor"], True),
        ("vendor/lib/a.go", ["vendor/"], True),
        ("vendor/lib/a.go", ["vendor/**"], True),
        ("src/vendor/a.go", ["vendor"], False),
        ("src/vendor/a.go", ["*/vendor/*"], True),
        ("web/app.min.js", ["*.min.js"], True),
        ("web/app.js", ["*.min.js"], False),
        ("tests/fixtures/x/y.py", ["tests/fixtures"], True),
        ("tests/fixtures-extra/y.py", ["tests/fixtures"], False),
        ("a.py", [], False),
        ("a.py", ["", "/"], False),
    ],
)
def test_is_excluded(path: str, patterns: list[str], expected: bool) -> None:
    assert is_excluded(path, patterns) is expected


def test_to_relative_rejects_paths_outside_the_root(tmp_path: Path) -> None:
    root = tmp_path / "asset"
    (root / "src").mkdir(parents=True)

    assert to_relative("src/app.py", root) == "src/app.py"
    assert to_relative(str(root / "src" / "app.py"), root) == "src/app.py"
    assert to_relative("./src/app.py", root) == "src/app.py"
    assert to_relative("../other/app.py", root) is None
    assert to_relative("/etc/passwd", root) is None
    assert to_relative(str(root), root) is None
    assert to_relative("", root) is None


def test_safe_read_lines_stays_inside_the_root(tmp_path: Path) -> None:
    root = tmp_path / "asset"
    root.mkdir()
    (root / "a.txt").write_text("one\ntwo\nthree\n", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("outside\n", encoding="utf-8")
    (root / "link.txt").symlink_to(tmp_path / "outside.txt")

    assert safe_read_lines(root, "a.txt", 2, 3) == ["two", "three"]
    assert safe_read_lines(root, "a.txt", 9, 9) == []
    assert safe_read_lines(root, "a.txt", 0, 1) == []
    assert safe_read_lines(root, "link.txt", 1, 1) == []
    assert safe_read_lines(root, "../outside.txt", 1, 1) == []
    assert safe_read_lines(root, "missing.txt", 1, 1) == []


# --- scoring ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "criticality", "priority"),
    [
        (Severity.CRITICAL, "medium", "P0"),
        (Severity.HIGH, "critical", "P0"),
        (Severity.HIGH, "medium", "P1"),
        (Severity.HIGH, "low", "P2"),
        (Severity.MEDIUM, "high", "P2"),
        (Severity.LOW, "medium", "P3"),
        (Severity.INFO, "critical", "P3"),
    ],
)
def test_priority(severity: Severity, criticality: str, priority: str) -> None:
    assert priority_for(sast_finding(severity=severity), criticality) == priority


def test_severity_parsing() -> None:
    assert Severity.parse("ERROR") is Severity.HIGH
    assert Severity.parse("moderate") is Severity.MEDIUM
    assert Severity.parse("Negligible") is Severity.LOW
    assert Severity.parse("???") is Severity.MEDIUM
    assert Severity.parse(None, Severity.LOW) is Severity.LOW
    assert [Severity.from_cvss(s) for s in (9.8, 7.0, 4.0, 0.1, 0.0)] == [
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO,
    ]  # fmt: skip


# --- runner -----------------------------------------------------------------------

PYTHON = sys.executable


def runner(**kwargs) -> ToolRunner:
    kwargs.setdefault("sandbox", "off")
    environ = {
        "PATH": os.environ["PATH"],
        "HOME": "/home/someone",
        "AWS_SECRET_ACCESS_KEY": "must-not-leak",
        "GITHUB_TOKEN": "must-not-leak",
        "CUSTOM_CACHE": "/cache",
    }
    return ToolRunner(environ=environ, **kwargs)


def test_scanners_get_a_scrubbed_environment(tmp_path: Path) -> None:
    script = "import os, json; print(json.dumps(sorted(os.environ)))"

    result = runner(env_passthrough=["CUSTOM_CACHE"]).run([PYTHON, "-c", script], tmp_path)
    seen = set(json.loads(result.stdout))

    assert {"PATH", "HOME", "CUSTOM_CACHE"} <= seen
    assert not {"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN"} & seen
    assert "must-not-leak" not in result.stdout


def test_non_zero_exit_is_returned_not_raised(tmp_path: Path) -> None:
    script = "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"

    result = runner().run([PYTHON, "-c", script], tmp_path, extra_env={"EXTRA": "1"})

    assert (result.returncode, result.stdout.strip(), result.stderr_tail) == (3, "out", "err")


def test_timeout_stops_the_scanner(tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="timed out after 1s"):
        runner(timeout_seconds=1).run([PYTHON, "-c", "import time; time.sleep(60)"], tmp_path)


def test_runaway_output_stops_the_scanner(tmp_path: Path) -> None:
    script = "import sys\nwhile True: sys.stdout.write('x' * 65536)"

    with pytest.raises(ToolError, match="output exceeded"):
        runner(max_output_bytes=1024 * 1024).run([PYTHON, "-c", script], tmp_path)


def test_kill_switch_prevents_and_interrupts_runs(tmp_path: Path) -> None:
    stop = tmp_path / "STOP"
    switch = KillSwitch(stop, {})
    marker = tmp_path / "started"
    script = (
        "import pathlib, sys, time\n"
        f"pathlib.Path({str(marker)!r}).touch()\n"
        f"pathlib.Path({str(stop)!r}).touch()\n"
        "time.sleep(60)\n"
    )

    with pytest.raises(KillSwitchEngaged, match="was stopped"):
        runner(kill_switch=switch).run([PYTHON, "-c", script], tmp_path)
    assert marker.exists()

    marker.unlink()
    with pytest.raises(KillSwitchEngaged):
        runner(kill_switch=switch).run([PYTHON, "-c", f"open({str(marker)!r}, 'w')"], tmp_path)
    assert not marker.exists()


def test_missing_binary_is_a_tool_error_and_which_uses_the_scrubbed_path(tmp_path: Path) -> None:
    with pytest.raises(ToolError, match="could not be started"):
        runner().run(["htw-no-such-binary"], tmp_path)

    assert runner().which("htw-no-such-binary") is None
    assert ToolRunner(environ={"PATH": str(tmp_path)}).which("python3") is None
