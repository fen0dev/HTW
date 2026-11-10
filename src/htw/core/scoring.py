"""Priority (P0-P3): scanner severity adjusted by how much the asset matters.

This is the deterministic baseline. Public EPSS and CISA KEV data can raise it by
one step each, and only when that feed was fetched or is still in a fresh cache
(`exploitability.py`). A missing feed does not raise priority. Reachability is not
part of this score. Triage may then lower a low-confidence finding by one step.
"""

from __future__ import annotations

from htw.core.finding import Finding

PRIORITIES = ("P0", "P1", "P2", "P3")

_CRITICALITY_ADJUSTMENT = {"critical": 1, "high": 0, "medium": 0, "low": -1}


def priority_for(finding: Finding, criticality: str) -> str:
    score = finding.severity.rank + _CRITICALITY_ADJUSTMENT.get(criticality, 0)
    if score >= 4:
        return "P0"
    if score == 3:
        return "P1"
    if score == 2:
        return "P2"
    return "P3"


def assign_priorities(findings: list[Finding], criticality: str) -> None:
    for finding in findings:
        finding.priority = priority_for(finding, criticality)
