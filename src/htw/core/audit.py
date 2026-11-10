"""Append-only audit log.

One JSON object per line. Each record carries the hash of the previous one, so edits
and deletions inside the file are detectable with `htw audit-verify`. Truncating the
end of the file is not detectable from the file alone, which is why the log should be
shipped to storage the scanned repositories cannot write to.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64
_CI_VARIABLES = ("CI", "GITHUB_ACTOR", "GITHUB_RUN_ID", "GITHUB_WORKFLOW", "GITLAB_USER_LOGIN",
                 "CI_PIPELINE_ID", "BUILD_ID", "JENKINS_URL")  # fmt: skip


def _digest(previous: str, record: Mapping[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256((previous + payload).encode("utf-8")).hexdigest()


def initiator(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Who or what started this process, as far as the environment says."""
    source = os.environ if environ is None else environ
    try:
        user = getpass.getuser()
    except (KeyError, OSError):
        user = "unknown"
    info = {"user": user}
    for name in _CI_VARIABLES:
        if source.get(name):
            info[name.lower()] = source[name][:200]
    return info


@dataclass
class VerificationResult:
    ok: bool
    records: int
    error: str = ""


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self._last_hash: str | None = None
        self._seq = 0

    def _load_tail(self) -> None:
        self._last_hash, self._seq = GENESIS_HASH, 0
        if not self.path.exists():
            return
        last = None
        with open(self.path, "rb") as handle:
            for line in handle:
                if line.strip():
                    last = line
        if last is not None:
            try:
                record = json.loads(last)
                self._last_hash, self._seq = str(record["hash"]), int(record["seq"])
            except (ValueError, KeyError, TypeError):
                # A damaged tail is reported by `verify`; keep appending rather than lose events.
                self._last_hash = hashlib.sha256(last).hexdigest()
                self._seq += 1

    def append(self, event: str, at: datetime | None = None, **fields: Any) -> dict[str, Any]:
        if self._last_hash is None:
            self._load_tail()
        assert self._last_hash is not None
        moment = (at or datetime.now(UTC)).astimezone(UTC)
        record: dict[str, Any] = {
            "seq": self._seq + 1,
            "ts": moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "event": event,
            **fields,
            "prev_hash": self._last_hash,
        }
        record["hash"] = _digest(self._last_hash, record)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n")
        self._last_hash, self._seq = record["hash"], record["seq"]
        return record

    def verify(self) -> VerificationResult:
        if not self.path.exists():
            return VerificationResult(True, 0)
        previous, count = GENESIS_HASH, 0
        with open(self.path, encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    claimed = record.pop("hash")
                except (ValueError, KeyError, AttributeError):
                    return VerificationResult(False, count, f"line {number}: not a valid record")
                if record.get("prev_hash") != previous:
                    return VerificationResult(
                        False,
                        count,
                        f"line {number}: chain broken (a record was removed or reordered)",
                    )
                if _digest(previous, record) != claimed:
                    return VerificationResult(False, count, f"line {number}: record was modified")
                if record.get("seq") != count + 1:
                    return VerificationResult(False, count, f"line {number}: sequence gap")
                previous, count = claimed, count + 1
        return VerificationResult(True, count)
