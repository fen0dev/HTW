from __future__ import annotations

import json
import os
from datetime import date
from pathlib import Path

import pytest

from htw import __version__
from htw.core.finding import Severity
from htw.core.fingerprint import assign_fingerprints
from htw.core.sarif import FINGERPRINT_KEY, SarifEntry, SarifTool, build_sarif
from htw.core.suppressions import Suppression

from .helpers import dependency_finding, sast_finding, secret_finding


def sample_log() -> dict:
    findings = [
        sast_finding(severity=Severity.CRITICAL, identifiers=("CWE-95",)),
        sast_finding(line=20, rule="python.sql-injection", severity=Severity.LOW),
        sast_finding(path="dir with space/a#b.py", line=3),
        dependency_finding(),
        secret_finding(),
    ]
    findings[3].cvss_score = 8.6
    findings[3].references = ("https://github.com/advisories/GHSA-aaaa-bbbb-cccc",)
    findings[4].location.commit = "0123456789abcdef"
    assign_fingerprints(findings)
    for finding in findings:
        finding.priority = "P1"
    suppression = Suppression(
        findings[4].fingerprint,
        "false_positive",
        "Sample value",
        "jane@example.invalid",
        date(2027, 1, 1),
    )
    entries = [
        SarifEntry(findings[0], "new", "2026-11-10T12:00:00Z"),
        SarifEntry(findings[1], "resolved", "2026-10-01T12:00:00Z"),
        SarifEntry(findings[2], "unverified"),
        SarifEntry(findings[3], "reappeared"),
        SarifEntry(findings[4], "unchanged", suppression=suppression),
    ]
    tools = {
        "semgrep": SarifTool("semgrep", "1.150.0", "https://github.com/semgrep/semgrep"),
        "grype": SarifTool("grype", "0.100.0"),
        "bandit": SarifTool("bandit", "1.9.2"),
    }
    return build_sarif("app", "20261110T120000Z-abc123", entries, tools)


def by_tool(log: dict) -> dict[str, dict]:
    return {run["tool"]["driver"]["name"]: run for run in log["runs"]}


def test_one_run_per_tool_including_tools_that_found_nothing() -> None:
    log = sample_log()
    runs = by_tool(log)

    assert log["version"] == "2.1.0" and log["$schema"].endswith("sarif-schema-2.1.0.json")
    # gitleaks has a finding on record but is not in the tool list: it still gets a run.
    assert list(runs) == ["bandit", "gitleaks", "grype", "semgrep"]
    assert runs["bandit"]["results"] == []
    assert runs["semgrep"]["tool"]["driver"]["version"] == "1.150.0"
    assert "version" not in runs["gitleaks"]["tool"]["driver"]
    for run in log["runs"]:
        assert run["conversion"]["tool"]["driver"] == {
            "name": "htw", "version": __version__, "informationUri": "https://github.com/fen0dev/HTW",
        }  # fmt: skip
        assert run["automationDetails"]["id"].startswith("htw/app/")


def test_results_carry_stable_fingerprints_and_baseline_state() -> None:
    runs = by_tool(sample_log())
    results = {r["properties"]["htw/state"]: r for run in runs.values() for r in run["results"]}

    assert {state: r["baselineState"] for state, r in results.items()} == {
        "new": "new", "reappeared": "new", "unchanged": "unchanged",
        "unverified": "unchanged", "resolved": "absent",
    }  # fmt: skip
    for result in results.values():
        assert result["partialFingerprints"][FINGERPRINT_KEY].startswith("htw1:")
    assert results["new"]["level"] == "error" and results["resolved"]["level"] == "note"
    assert results["new"]["properties"]["htw/firstSeen"] == "2026-11-10T12:00:00Z"
    assert results["reappeared"]["properties"]["htw/package"] == {
        "ecosystem": "PyPI", "name": "jinja2", "version": "2.10", "fixedVersions": ["2.11.3"],
    }  # fmt: skip
    assert results["unchanged"]["properties"]["htw/commit"] == "0123456789abcdef"
    assert results["unchanged"]["suppressions"] == [
        {
            "kind": "external",
            "justification": "false_positive: Sample value (jane@example.invalid, expires 2027-01-01)",
        }
    ]


def test_rules_are_deduplicated_and_indexed() -> None:
    semgrep = by_tool(sample_log())["semgrep"]
    rules = semgrep["tool"]["driver"]["rules"]

    assert sorted(rule["id"] for rule in rules) == [
        "python.lang.security.eval",
        "python.sql-injection",
    ]
    for result in semgrep["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
    eval_rule = next(rule for rule in rules if rule["id"] == "python.lang.security.eval")
    assert "security" in eval_rule["properties"]["tags"]
    grype_rule = by_tool(sample_log())["grype"]["tool"]["driver"]["rules"][0]
    assert grype_rule["properties"]["security-severity"] == "8.6"
    assert grype_rule["helpUri"] == "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"


def test_locations_are_relative_uris() -> None:
    results = [r for run in sample_log()["runs"] for r in run["results"]]
    locations = [r["locations"][0]["physicalLocation"] for r in results if "locations" in r]

    uris = {loc["artifactLocation"]["uri"] for loc in locations}
    assert "dir%20with%20space/a%23b.py" in uris
    assert all(loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%" for loc in locations)
    dependency = next(
        loc for loc in locations if loc["artifactLocation"]["uri"] == "requirements.txt"
    )
    assert "region" not in dependency


def test_output_is_deterministic() -> None:
    assert json.dumps(sample_log(), sort_keys=True) == json.dumps(sample_log(), sort_keys=True)


def test_log_validates_against_the_official_schema() -> None:
    """Runs when HTW_SARIF_SCHEMA points at a copy of the OASIS SARIF 2.1.0 JSON schema.

    The schema is not vendored. CI downloads it; locally, see CONTRIBUTING.md.
    """
    schema_path = os.environ.get("HTW_SARIF_SCHEMA")
    if not schema_path:
        pytest.skip("HTW_SARIF_SCHEMA is not set")
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))

    validator = jsonschema.Draft7Validator(schema)
    errors = [
        f"{'/'.join(map(str, e.absolute_path))}: {e.message}"
        for e in validator.iter_errors(sample_log())
    ]

    assert errors == []
