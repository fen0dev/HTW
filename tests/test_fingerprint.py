from __future__ import annotations

from pathlib import Path

from htw.core.finding import Severity
from htw.core.fingerprint import (
    FINGERPRINT_PREFIX,
    assign_fingerprints,
    normalize_context,
    normalize_package_name,
)

from .helpers import dependency_finding, sast_finding, secret_finding

SOURCE = """\
import os

def handler(request):
    value = request.args["q"]
    return eval(value)
"""


def fingerprint_of(root: Path, finding) -> str:
    assign_fingerprints([finding], root)
    return finding.fingerprint


def write(root: Path, text: str, name: str = "app/server.py") -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_fingerprint_format(tmp_path: Path) -> None:
    write(tmp_path, SOURCE)

    fingerprint = fingerprint_of(tmp_path, sast_finding(line=5))

    assert fingerprint.startswith(FINGERPRINT_PREFIX)
    assert len(fingerprint) == len(FINGERPRINT_PREFIX) + 32
    assert all(c in "0123456789abcdef" for c in fingerprint.removeprefix(FINGERPRINT_PREFIX))


def test_moving_code_does_not_change_the_fingerprint(tmp_path: Path) -> None:
    write(tmp_path, SOURCE)
    before = fingerprint_of(tmp_path, sast_finding(line=5))

    write(tmp_path, "# a new header comment\n\n\n" + SOURCE)
    after = fingerprint_of(tmp_path, sast_finding(line=8))

    assert before == after


def test_reformatting_whitespace_does_not_change_the_fingerprint(tmp_path: Path) -> None:
    write(tmp_path, SOURCE)
    before = fingerprint_of(tmp_path, sast_finding(line=5))

    write(tmp_path, SOURCE.replace("    return eval(value)", "\t\treturn   eval(value)  "))
    after = fingerprint_of(tmp_path, sast_finding(line=5))

    assert before == after


def test_changing_the_flagged_code_changes_the_fingerprint(tmp_path: Path) -> None:
    write(tmp_path, SOURCE)
    before = fingerprint_of(tmp_path, sast_finding(line=5))

    write(tmp_path, SOURCE.replace("eval(value)", "eval(value, {})"))
    after = fingerprint_of(tmp_path, sast_finding(line=5))

    assert before != after


def test_rule_path_tool_and_asset_are_part_of_the_identity(tmp_path: Path) -> None:
    write(tmp_path, SOURCE)
    write(tmp_path, SOURCE, "app/other.py")
    base = fingerprint_of(tmp_path, sast_finding(line=5))

    assert base != fingerprint_of(tmp_path, sast_finding(line=5, rule="other.rule"))
    assert base != fingerprint_of(tmp_path, sast_finding(line=5, path="app/other.py"))
    assert base != fingerprint_of(tmp_path, sast_finding(line=5, tool="bandit"))
    assert base != fingerprint_of(tmp_path, sast_finding(line=5, asset="another-asset"))
    # Severity and wording are scanner opinions that change between releases.
    assert base == fingerprint_of(tmp_path, sast_finding(line=5, severity=Severity.LOW))


def test_identical_lines_get_distinct_stable_fingerprints(tmp_path: Path) -> None:
    write(tmp_path, "eval(a)\nprint(1)\neval(a)\n")
    first, second = sast_finding(line=1), sast_finding(line=3)
    assign_fingerprints([second, first], tmp_path)
    assert first.fingerprint != second.fingerprint

    # The same two findings after the file gained a line, reported in another order.
    write(tmp_path, "# header\neval(a)\nprint(1)\neval(a)\n")
    moved_first, moved_second = sast_finding(line=2), sast_finding(line=4)
    assign_fingerprints([moved_first, moved_second], tmp_path)

    assert (moved_first.fingerprint, moved_second.fingerprint) == (
        first.fingerprint,
        second.fingerprint,
    )


def test_unreadable_location_falls_back_to_the_line_number(tmp_path: Path) -> None:
    gone = fingerprint_of(tmp_path, sast_finding(path="deleted.py", line=4))

    assert gone == fingerprint_of(tmp_path, sast_finding(path="deleted.py", line=4))
    assert gone != fingerprint_of(tmp_path, sast_finding(path="deleted.py", line=5))


def test_files_outside_the_asset_are_never_read(tmp_path: Path) -> None:
    root = tmp_path / "asset"
    root.mkdir()
    (tmp_path / "outside.py").write_text("eval(a)\n", encoding="utf-8")
    (root / "link.py").symlink_to(tmp_path / "outside.py")

    by_symlink = fingerprint_of(root, sast_finding(path="link.py", line=1))
    (tmp_path / "outside.py").write_text("something_else()\n", encoding="utf-8")

    # Had the target been read, its new content would have changed the fingerprint.
    assert by_symlink == fingerprint_of(root, sast_finding(path="link.py", line=1))
    assert by_symlink != fingerprint_of(root, sast_finding(path="link.py", line=2))


def test_dependency_fingerprint_survives_a_still_vulnerable_upgrade() -> None:
    old = dependency_finding(version="2.10")
    new = dependency_finding(version="2.10.1")
    assign_fingerprints([old])
    assign_fingerprints([new])

    assert old.fingerprint == new.fingerprint


def test_dependency_fingerprint_is_independent_of_the_reporting_tool() -> None:
    by_grype = dependency_finding(tool="grype", name="Flask_Login")
    by_osv = dependency_finding(tool="osv-scanner", name="flask-login", severity=Severity.LOW)
    assign_fingerprints([by_grype])
    assign_fingerprints([by_osv])

    assert by_grype.fingerprint == by_osv.fingerprint


def test_dependency_identity_is_advisory_package_and_manifest() -> None:
    findings = [
        dependency_finding(),
        dependency_finding(advisory="GHSA-xxxx-yyyy-zzzz"),
        dependency_finding(name="pyyaml"),
        dependency_finding(path="services/api/requirements.txt"),
        dependency_finding(ecosystem="npm"),
    ]
    assign_fingerprints(findings)

    assert len({f.fingerprint for f in findings}) == len(findings)


def test_secret_fingerprints_use_the_redacted_match_not_the_file(tmp_path: Path) -> None:
    write(tmp_path, "API_KEY = 'value-one'\n", "app/settings.py")
    before = fingerprint_of(tmp_path, secret_finding(line=1))

    # Rotating the value in place keeps the redacted match, and the file is not read.
    write(tmp_path, "\n\nAPI_KEY = 'value-two'\n", "app/settings.py")
    after = fingerprint_of(tmp_path, secret_finding(line=3))

    assert before == after


def test_secret_without_context_never_hashes_the_line(tmp_path: Path) -> None:
    write(tmp_path, "API_KEY = 'value-one'\n", "app/settings.py")
    before = fingerprint_of(tmp_path, secret_finding(line=1, context=None))

    write(tmp_path, "API_KEY = 'value-two'\n", "app/settings.py")

    assert before == fingerprint_of(tmp_path, secret_finding(line=1, context=None))
    assert before != fingerprint_of(tmp_path, secret_finding(line=2, context=None))


def test_normalization_helpers() -> None:
    assert normalize_context("  a   b \n\n\tc\n") == "a b\nc"
    assert normalize_context(["x  y", "   "]) == "x y"
    assert normalize_package_name("PyPI", "Flask_Login.ext") == "flask-login-ext"
    assert normalize_package_name("npm", "@Scope/Name") == "@Scope/Name"
