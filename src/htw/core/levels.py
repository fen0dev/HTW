"""Control levels: how intrusive a check is and what authorization it needs."""

from __future__ import annotations

from enum import IntEnum


class ControlLevel(IntEnum):
    """L0 static analysis, L1 passive reads, L2 active non-destructive tests, L3 intrusive."""

    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3

    @classmethod
    def parse(cls, value: object) -> ControlLevel:
        if isinstance(value, cls):
            return value
        if isinstance(value, str) and value.upper() in cls.__members__:
            return cls[value.upper()]
        raise ValueError(f"unknown control level {value!r} (expected L0, L1 or L2)")


# Runs without per-run human approval when the asset is allowlisted.
MAX_AUTOMATIC_LEVEL = ControlLevel.L1
# The highest level an asset may declare. L3 is never run by agents.
MAX_DECLARABLE_LEVEL = ControlLevel.L2
