"""Finding state and history (SQLite).

The store is what makes a recurring scan quiet: each run is compared with the state
left by the previous one, and every finding is classified as new, still open,
resolved or reappeared.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from htw.core.finding import Finding

SCHEMA_VERSION = 1

NEW = "new"
REAPPEARED = "reappeared"
UNCHANGED = "unchanged"
RESOLVED = "resolved"
UNVERIFIED = "unverified"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    summary TEXT
);
CREATE INDEX IF NOT EXISTS runs_by_asset ON runs (asset_id, started_at);
CREATE TABLE IF NOT EXISTS findings (
    asset_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    tool TEXT NOT NULL,
    status TEXT NOT NULL,
    first_seen_run TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_run TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    resolved_run TEXT,
    resolved_at TEXT,
    reopen_count INTEGER NOT NULL DEFAULT 0,
    data TEXT NOT NULL,
    PRIMARY KEY (asset_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS finding_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    event TEXT NOT NULL,
    at TEXT NOT NULL
);
"""


@dataclass
class Delta:
    """How this run's findings differ from the stored state."""

    new: list[Finding] = field(default_factory=list)
    reappeared: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    # Previously open findings whose scanner did not complete in this run. They stay
    # open: a scanner that did not run proves nothing about them.
    unverified: list[Finding] = field(default_factory=list)
    first_seen: dict[str, str] = field(default_factory=dict)

    @property
    def changed(self) -> bool:
        return bool(self.new or self.reappeared or self.resolved)

    def counts(self) -> dict[str, int]:
        return {
            NEW: len(self.new),
            REAPPEARED: len(self.reappeared),
            UNCHANGED: len(self.unchanged),
            RESOLVED: len(self.resolved),
            UNVERIFIED: len(self.unverified),
        }


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.row_factory = sqlite3.Row
        with self._db:
            self._db.executescript(_SCHEMA)
            self._db.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def last_run_started(self, asset_id: str) -> datetime | None:
        with closing(
            self._db.execute(
                "SELECT started_at FROM runs WHERE asset_id = ? ORDER BY started_at DESC LIMIT 1",
                (asset_id,),
            )
        ) as cursor:
            row = cursor.fetchone()
        if row is None:
            return None
        return datetime.strptime(row["started_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)

    def begin_run(self, run_id: str, asset_id: str, started_at: datetime, config_hash: str) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO runs (run_id, asset_id, started_at, status, config_hash) "
                "VALUES (?, ?, ?, 'running', ?)",
                (run_id, asset_id, _iso(started_at), config_hash),
            )

    def finish_run(
        self, run_id: str, finished_at: datetime, status: str, summary: Mapping[str, object]
    ) -> None:
        with self._db:
            self._db.execute(
                "UPDATE runs SET finished_at = ?, status = ?, summary = ? WHERE run_id = ?",
                (_iso(finished_at), status, json.dumps(summary, sort_keys=True), run_id),
            )

    def open_findings(self, asset_id: str) -> list[Finding]:
        with closing(
            self._db.execute(
                "SELECT data FROM findings WHERE asset_id = ? AND status = 'open' "
                "ORDER BY fingerprint",
                (asset_id,),
            )
        ) as cursor:
            return [Finding.from_dict(json.loads(row["data"])) for row in cursor.fetchall()]

    def apply_run(
        self,
        run_id: str,
        asset_id: str,
        at: datetime,
        findings: Iterable[Finding],
        completed_tools: Iterable[str],
    ) -> Delta:
        """Record this run's findings and return the delta against the previous state.

        `completed_tools` names the scanners that ran to completion. Only their
        findings can be declared resolved by being absent.
        """
        now = _iso(at)
        completed = set(completed_tools)
        current = {finding.fingerprint: finding for finding in findings}
        delta = Delta()
        with self._db:
            with closing(
                self._db.execute("SELECT * FROM findings WHERE asset_id = ?", (asset_id,))
            ) as cursor:
                stored = {row["fingerprint"]: row for row in cursor.fetchall()}

            for fingerprint, finding in current.items():
                row = stored.get(fingerprint)
                data = json.dumps(finding.to_dict(), sort_keys=True)
                if row is None:
                    delta.new.append(finding)
                    delta.first_seen[fingerprint] = now
                    self._db.execute(
                        "INSERT INTO findings (asset_id, fingerprint, tool, status, "
                        "first_seen_run, first_seen_at, last_seen_run, last_seen_at, data) "
                        "VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?)",
                        (asset_id, fingerprint, finding.tool, run_id, now, run_id, now, data),
                    )
                    self._event(run_id, asset_id, fingerprint, NEW, now)
                    continue
                delta.first_seen[fingerprint] = row["first_seen_at"]
                if row["status"] == "resolved":
                    delta.reappeared.append(finding)
                    self._db.execute(
                        "UPDATE findings SET status = 'open', tool = ?, last_seen_run = ?, "
                        "last_seen_at = ?, resolved_run = NULL, resolved_at = NULL, "
                        "reopen_count = reopen_count + 1, data = ? "
                        "WHERE asset_id = ? AND fingerprint = ?",
                        (finding.tool, run_id, now, data, asset_id, fingerprint),
                    )
                    self._event(run_id, asset_id, fingerprint, REAPPEARED, now)
                else:
                    delta.unchanged.append(finding)
                    self._db.execute(
                        "UPDATE findings SET tool = ?, last_seen_run = ?, last_seen_at = ?, "
                        "data = ? WHERE asset_id = ? AND fingerprint = ?",
                        (finding.tool, run_id, now, data, asset_id, fingerprint),
                    )

            for fingerprint, row in stored.items():
                if fingerprint in current or row["status"] != "open":
                    continue
                finding = Finding.from_dict(json.loads(row["data"]))
                delta.first_seen[fingerprint] = row["first_seen_at"]
                if row["tool"] in completed:
                    delta.resolved.append(finding)
                    self._db.execute(
                        "UPDATE findings SET status = 'resolved', resolved_run = ?, "
                        "resolved_at = ? WHERE asset_id = ? AND fingerprint = ?",
                        (run_id, now, asset_id, fingerprint),
                    )
                    self._event(run_id, asset_id, fingerprint, RESOLVED, now)
                else:
                    delta.unverified.append(finding)
        for group in (
            delta.new,
            delta.reappeared,
            delta.unchanged,
            delta.resolved,
            delta.unverified,
        ):
            group.sort(key=lambda f: (-f.severity.rank, f.location.path or "", f.rule_id))
        return delta

    def _event(self, run_id: str, asset_id: str, fingerprint: str, event: str, at: str) -> None:
        self._db.execute(
            "INSERT INTO finding_events (run_id, asset_id, fingerprint, event, at) "
            "VALUES (?, ?, ?, ?, ?)",
            (run_id, asset_id, fingerprint, event, at),
        )
