"""Suppressions: reviewed decisions to stop reporting a finding.

They live in a versioned file so that they go through code review, and each one needs
a reason, an author and an expiry date. An expired suppression stops applying.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml

from htw.core.fingerprint import FINGERPRINT_PREFIX
from htw.errors import ConfigError

KINDS = ("false_positive", "accepted_risk")


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    kind: str
    reason: str
    author: str
    expires: date

    def expired(self, today: date) -> bool:
        return today > self.expires


@dataclass
class SuppressionSet:
    active: dict[str, Suppression]
    expired: list[Suppression]

    def get(self, fingerprint: str) -> Suppression | None:
        return self.active.get(fingerprint)


def load_suppressions(path: Path, today: date) -> SuppressionSet:
    """Load the suppression file. A missing file means no suppressions."""
    if not path.exists():
        return SuppressionSet({}, [])
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read suppressions file {path}: {exc}") from None
    entries = data.get("suppressions") if isinstance(data, dict) else None
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise ConfigError(f"{path}: `suppressions` must be a list")

    active: dict[str, Suppression] = {}
    expired: list[Suppression] = []
    for index, entry in enumerate(entries):
        where = f"{path.name}: suppressions[{index}]"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: expected a mapping")
        unknown = set(entry) - {"fingerprint", "kind", "reason", "author", "expires"}
        if unknown:
            raise ConfigError(f"{where}: unknown key(s) {sorted(unknown)}")
        fingerprint = str(entry.get("fingerprint") or "")
        if not fingerprint.startswith(FINGERPRINT_PREFIX):
            raise ConfigError(
                f"{where}: `fingerprint` must be a finding id ({FINGERPRINT_PREFIX}...)"
            )
        kind = entry.get("kind")
        if kind not in KINDS:
            raise ConfigError(f"{where}: `kind` must be one of {', '.join(KINDS)}")
        reason = str(entry.get("reason") or "").strip()
        author = str(entry.get("author") or "").strip()
        if not reason or not author:
            raise ConfigError(f"{where}: `reason` and `author` are required")
        expires = entry.get("expires")
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError:
                expires = None
        if not isinstance(expires, date):
            raise ConfigError(
                f"{where}: `expires` (YYYY-MM-DD) is required; suppressions cannot be permanent"
            )
        suppression = Suppression(fingerprint, kind, reason, author, expires)
        if suppression.expired(today):
            expired.append(suppression)
        else:
            active[fingerprint] = suppression
    return SuppressionSet(active, expired)
