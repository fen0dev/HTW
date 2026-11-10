from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from htw.core.finding import Finding, Severity
from htw.core.fingerprint import assign_fingerprints
from htw.core.store import Store

from .conftest import NOW
from .helpers import dependency_finding, sast_finding, secret_finding


@pytest.fixture
def store(tmp_path: Path):
    with Store(tmp_path / "state" / "state.db") as opened:
        yield opened


def fingerprinted(*findings: Finding) -> list[Finding]:
    items = list(findings)
    assign_fingerprints(items)
    return items


def run(store: Store, number: int, findings: list[Finding], completed=("semgrep", "grype")):
    run_id = f"run-{number}"
    at = NOW + timedelta(hours=number)
    store.begin_run(run_id, "app", at, "hash")
    return store.apply_run(run_id, "app", at, findings, completed)


def test_first_scan_reports_everything_as_new(store: Store) -> None:
    findings = fingerprinted(sast_finding(), dependency_finding())

    delta = run(store, 1, findings)

    assert delta.counts() == {
        "new": 2,
        "reappeared": 0,
        "unchanged": 0,
        "resolved": 0,
        "unverified": 0,
    }
    assert delta.changed
    assert {f.fingerprint for f in store.open_findings("app")} == {f.fingerprint for f in findings}


def test_an_identical_second_scan_reports_nothing(store: Store) -> None:
    findings = fingerprinted(sast_finding(), dependency_finding())
    run(store, 1, findings)

    delta = run(store, 2, findings)

    assert delta.counts()["unchanged"] == 2
    assert not delta.changed
    # First-seen is the first run's timestamp, not this one's.
    assert set(delta.first_seen.values()) == {"2026-11-10T13:00:00Z"}


def test_a_finding_that_disappears_is_resolved(store: Store) -> None:
    eval_finding, dependency = fingerprinted(sast_finding(), dependency_finding())
    run(store, 1, [eval_finding, dependency])

    delta = run(store, 2, [dependency])

    assert [f.fingerprint for f in delta.resolved] == [eval_finding.fingerprint]
    assert [f.fingerprint for f in store.open_findings("app")] == [dependency.fingerprint]


def test_a_resolved_finding_that_returns_is_reappeared_not_new(store: Store) -> None:
    (finding,) = fingerprinted(sast_finding())
    run(store, 1, [finding])
    run(store, 2, [])

    delta = run(store, 3, [finding])

    assert delta.counts()["reappeared"] == 1 and delta.counts()["new"] == 0
    assert delta.first_seen[finding.fingerprint] == "2026-11-10T13:00:00Z"
    assert run(store, 4, [finding]).counts()["unchanged"] == 1


def test_a_scanner_that_did_not_complete_resolves_nothing(store: Store) -> None:
    eval_finding, dependency = fingerprinted(sast_finding(), dependency_finding())
    run(store, 1, [eval_finding, dependency])

    # Semgrep is missing or failed in this run: its finding must stay open.
    delta = run(store, 2, [dependency], completed=("grype",))

    assert delta.resolved == []
    assert [f.fingerprint for f in delta.unverified] == [eval_finding.fingerprint]
    assert not delta.changed
    assert len(store.open_findings("app")) == 2

    # Once semgrep completes again without it, it is resolved.
    assert len(run(store, 3, [dependency]).resolved) == 1


def test_assets_do_not_share_state(store: Store) -> None:
    (finding,) = fingerprinted(sast_finding())
    run(store, 1, [finding])

    store.begin_run("other-1", "other", NOW, "hash")
    delta = store.apply_run("other-1", "other", NOW, [], ["semgrep"])

    assert delta.resolved == []
    assert len(store.open_findings("app")) == 1
    assert store.open_findings("other") == []


def test_results_are_ordered_by_severity(store: Store) -> None:
    findings = fingerprinted(
        sast_finding(rule="low", severity=Severity.LOW),
        sast_finding(rule="critical", severity=Severity.CRITICAL),
        sast_finding(rule="medium", severity=Severity.MEDIUM),
    )

    delta = run(store, 1, findings)

    assert [f.rule_id for f in delta.new] == ["critical", "medium", "low"]


def test_last_run_and_run_summary(store: Store) -> None:
    assert store.last_run_started("app") is None
    run(store, 1, [])
    run(store, 2, [])
    store.finish_run("run-2", NOW + timedelta(hours=3), "complete", {"new": 0})

    assert store.last_run_started("app") == NOW + timedelta(hours=2)
    assert store.last_run_started("other") is None


def test_state_survives_reopening_and_never_stores_fingerprint_context(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    (secret,) = fingerprinted(secret_finding(context="API_KEY = marker-context-value"))
    with Store(path) as first:
        run(first, 1, [secret], completed=("gitleaks",))

    with Store(path) as second:
        delta = run(second, 2, [secret], completed=("gitleaks",))
        restored = second.open_findings("app")[0]

    assert delta.counts()["unchanged"] == 1
    assert restored.context is None
    assert restored.location.path == "app/settings.py"
    assert b"marker-context-value" not in path.read_bytes()
    assert (path.stat().st_mode & 0o777) == 0o600


def test_history_is_recorded_as_events(store: Store, tmp_path: Path) -> None:
    (finding,) = fingerprinted(sast_finding())
    run(store, 1, [finding])
    run(store, 2, [])
    run(store, 3, [finding])

    with sqlite3.connect(store.path) as db:
        events = [row[0] for row in db.execute("SELECT event FROM finding_events ORDER BY id")]
        reopened = db.execute("SELECT reopen_count FROM findings").fetchone()[0]

    assert events == ["new", "resolved", "reappeared"]
    assert reopened == 1
