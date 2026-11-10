"""Tool adapters against canned scanner output.

The payloads keep the shape of each tool's real JSON (captured from the versions
listed in the README) but are trimmed to the fields the adapters read, plus the
fields they must ignore.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from htw.core.config import AgentSettings, load_config
from htw.core.finding import Severity
from htw.detect import detect_stack
from htw.errors import ConfigError, ToolError
from htw.scanners.bandit import Bandit
from htw.scanners.base import ScanContext
from htw.scanners.common import as_float, as_int, cwe_ids, ecosystem_for, http_links
from htw.scanners.gitleaks import Gitleaks
from htw.scanners.gosec import Gosec
from htw.scanners.grype import Grype
from htw.scanners.osv_scanner import OsvScanner, primary_id
from htw.scanners.semgrep import Semgrep
from htw.scanners.syft import Syft, anchore_excludes
from htw.scanners.trivy import Trivy
from htw.scanners.trufflehog import TruffleHog

from .conftest import FakeRunner, scope_yaml, write_tree

MARKER = "SYNTHETIC-VALUE-THAT-MUST-NOT-BE-STORED"


@pytest.fixture
def context(tmp_path: Path):
    """Build a ScanContext for a small project with a canned runner."""

    def _make(
        handlers,
        files=None,
        options=None,
        exclude: str = "",
    ) -> ScanContext:
        root = write_tree(
            tmp_path / "target",
            files
            or {
                "app/server.py": "import os\n\ndef run(q):\n    return eval(q)\n",
                "requirements.txt": "jinja2==2.10\n",
                "go.mod": "module example.invalid/app\n",
                "cmd/main.go": "package main\n",
            },
        )
        (tmp_path / "htw.yaml").write_text(
            scope_yaml([{"id": "app", "path": "target", "extra": exclude}]), encoding="utf-8"
        )
        asset = load_config(tmp_path / "htw.yaml").assets[0]
        artifacts = tmp_path / "artifacts"
        artifacts.mkdir(exist_ok=True)
        return ScanContext(
            asset=asset,
            root=root,
            profile=detect_stack(root),
            runner=FakeRunner(handlers),  # type: ignore[arg-type]
            settings=AgentSettings(options=options or {}),
            config_dir=tmp_path,
            artifacts_dir=artifacts,
        )

    return _make


def json_out(payload, returncode: int = 0):
    return lambda argv, cwd: (returncode, json.dumps(payload))


# --- gitleaks ---------------------------------------------------------------------


def gitleaks_handler(entries, version: str = "8.30.0", calls=None):
    def handler(argv, cwd):
        if argv[1] == "version":
            return 0, f"{version}\n"
        if calls is not None:
            calls.append(argv)
        Path(argv[argv.index("--report-path") + 1]).write_text(json.dumps(entries))
        return 0, ""

    return handler


GITLEAKS_ENTRY = {
    "RuleID": "generic-api-key",
    "Description": "Detected a Generic API Key, potentially exposing access to various services.",
    "StartLine": 3,
    "EndLine": 3,
    "Match": "API_KEY = REDACTED",
    "Secret": "REDACTED",
    "File": "app/settings.py",
    "Commit": "0123456789abcdef0123456789abcdef01234567",
    "Entropy": 4.1,
    "Author": "Someone",
    "Email": "someone@example.invalid",
    "Fingerprint": "0123456789abcdef:app/settings.py:generic-api-key:3",
}


def test_gitleaks_findings_carry_location_and_type_but_no_value(context) -> None:
    ctx = context({"gitleaks": gitleaks_handler([GITLEAKS_ENTRY])})

    (finding,) = Gitleaks().scan(ctx)

    assert (finding.rule_id, finding.category, finding.severity) == (
        "generic-api-key", "secret", Severity.HIGH,
    )  # fmt: skip
    assert finding.location.path == "app/settings.py"
    assert finding.location.start_line == 3
    assert finding.location.commit == GITLEAKS_ENTRY["Commit"]
    assert finding.identifiers == ("CWE-798",)
    assert finding.context == "generic-api-key\nAPI_KEY = REDACTED"
    # Author details from git history are not copied into findings.
    assert "someone@example.invalid" not in json.dumps(finding.to_dict())


def test_gitleaks_value_is_masked_even_if_the_tool_did_not_redact(context) -> None:
    entry = {**GITLEAKS_ENTRY, "Match": f"API_KEY = {MARKER}", "Secret": MARKER}
    ctx = context({"gitleaks": gitleaks_handler([entry])})

    (finding,) = Gitleaks().scan(ctx)

    assert MARKER not in json.dumps(finding.to_dict())
    assert MARKER not in (finding.context or "")


def test_gitleaks_scans_history_only_for_git_checkouts(context) -> None:
    calls: list[list[str]] = []
    ctx = context({"gitleaks": gitleaks_handler([], calls=calls)})
    Gitleaks().scan(ctx)
    (ctx.root / ".git").mkdir()
    Gitleaks().scan(ctx)
    ctx.settings.options["history"] = False
    Gitleaks().scan(ctx)

    assert [argv[1] for argv in calls] == ["dir", "git", "dir"]
    assert all("--redact" in argv for argv in calls)


def test_gitleaks_command_for_modern_and_legacy_versions(tmp_path: Path) -> None:
    report = tmp_path / "r.json"
    modern = Gitleaks.command("8.30.0", tmp_path, history=True, report=report)
    modern_dir = Gitleaks.command("8.19.0", tmp_path, history=False, report=report)
    legacy = Gitleaks.command("8.18.4", tmp_path, history=True, report=report)
    legacy_dir = Gitleaks.command("8.18.4", tmp_path, history=False, report=report)
    unknown = Gitleaks.command(None, tmp_path, history=True, report=report)

    assert modern[:3] == ["gitleaks", "git", str(tmp_path)]
    assert modern_dir[:3] == ["gitleaks", "dir", str(tmp_path)]
    assert legacy[:4] == ["gitleaks", "detect", "--source", str(tmp_path)]
    assert "--no-git" not in legacy and "--no-git" in legacy_dir
    assert unknown[1] == "git"
    for argv in (modern, modern_dir, legacy, legacy_dir):
        assert "--redact" in argv
        assert argv[argv.index("--exit-code") + 1] == "0"


def test_gitleaks_failure_is_a_tool_error(context) -> None:
    def handler(argv, cwd):
        return (0, "8.30.0") if argv[1] == "version" else (1, "", "fatal: not a git repository")

    with pytest.raises(ToolError, match=r"gitleaks failed \(exit 1\): fatal: not a git repository"):
        Gitleaks().scan(context({"gitleaks": handler}))


def test_findings_outside_the_asset_are_dropped(context) -> None:
    entries = [
        {**GITLEAKS_ENTRY, "File": "/etc/passwd"},
        {**GITLEAKS_ENTRY, "File": "../other-repo/config.py"},
        {**GITLEAKS_ENTRY, "File": ""},
    ]

    assert Gitleaks().scan(context({"gitleaks": gitleaks_handler(entries)})) == []


# --- trufflehog -------------------------------------------------------------------


def test_trufflehog_never_reads_the_raw_credential(context) -> None:
    line = {
        "SourceMetadata": {"Data": {"Filesystem": {"file": "PLACEHOLDER", "line": 7}}},
        "DetectorName": "Postgres",
        "Verified": False,
        "Raw": MARKER,
        "RawV2": MARKER,
        "Redacted": MARKER[:8],
        "ExtraData": {"note": MARKER},
    }
    calls: list[list[str]] = []

    def handler(argv, cwd):
        calls.append(argv)
        line["SourceMetadata"]["Data"]["Filesystem"]["file"] = str(cwd / "app/db.py")
        log = {"level": "info-0", "msg": "running source"}
        return 0, "\n".join([json.dumps(log), "not json", json.dumps(line), "{broken"])

    (finding,) = TruffleHog().scan(context({"trufflehog": handler}))

    assert finding.rule_id == "Postgres"
    assert finding.location.path == "app/db.py" and finding.location.start_line == 7
    assert MARKER[:8] not in json.dumps(finding.to_dict()) + (finding.context or "")
    assert "--no-verification" in calls[0] and "--no-update" in calls[0]
    assert calls[0][1] == "filesystem"


def test_trufflehog_reads_git_metadata_for_history_scans(context) -> None:
    line = {
        "SourceMetadata": {"Data": {"Git": {"file": "app/db.py", "line": 2, "commit": "abc123"}}},
        "DetectorName": "URI",
    }
    calls: list[list[str]] = []

    def handler(argv, cwd):
        calls.append(argv)
        return 0, json.dumps(line)

    ctx = context({"trufflehog": handler})
    (ctx.root / ".git").mkdir()
    (finding,) = TruffleHog().scan(ctx)

    assert calls[0][1:3] == ["git", ctx.root.as_uri()]
    assert finding.location.commit == "abc123"


# --- semgrep ----------------------------------------------------------------------

SEMGREP_REPORT = {
    "version": "1.150.0",
    "results": [
        {
            "check_id": "python.lang.security.audit.eval-detected.eval-detected",
            "path": "app/server.py",
            "start": {"line": 4, "col": 12},
            "end": {"line": 4, "col": 19},
            "extra": {
                "message": "Detected the use of eval().  This can be dangerous\nif used on user input.",
                "severity": "WARNING",
                "lines": "requires login",
                "fingerprint": "requires login",
                "metadata": {
                    "cwe": ["CWE-95: Improper Neutralization of Directives ('Eval Injection')"],
                    "confidence": "LOW",
                    "source": "https://semgrep.dev/r/python.lang.security.audit.eval-detected",
                    "references": ["https://owasp.org/Top10/A03_2021-Injection", "ftp://nope"],
                },
            },
        },
        {"check_id": "x.y", "path": "/outside/the/root.py", "start": {"line": 1}, "extra": {}},
    ],
    "errors": [],
}


def test_semgrep_findings(context) -> None:
    calls: list[list[str]] = []

    def handler(argv, cwd):
        calls.append(argv)
        return 1, json.dumps(SEMGREP_REPORT)

    ctx = context({"semgrep": handler}, exclude="exclude: [vendor, '*.min.js']")
    (finding,) = Semgrep().scan(ctx)

    assert finding.rule_id == "python.lang.security.audit.eval-detected.eval-detected"
    assert finding.title == "eval-detected"
    assert finding.severity is Severity.MEDIUM
    assert (
        finding.message
        == "Detected the use of eval(). This can be dangerous if used on user input."
    )
    assert finding.location.path == "app/server.py"
    assert (finding.location.start_line, finding.location.end_line) == (4, 4)
    assert finding.identifiers == ("CWE-95",)
    assert finding.confidence == "low"
    assert finding.references == (
        "https://semgrep.dev/r/python.lang.security.audit.eval-detected",
        "https://owasp.org/Top10/A03_2021-Injection",
    )
    argv = calls[0]
    assert argv[:4] == ["semgrep", "scan", "--config", "p/default"]
    assert "--metrics=off" in argv and "--disable-version-check" in argv
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--exclude"] == ["vendor", "*.min.js"]


def test_semgrep_rules_can_be_local_files_but_must_exist(context, tmp_path: Path) -> None:
    (tmp_path / "rules").mkdir()
    ctx = context({}, options={"semgrep_rules": ["p/python", "rules"]})
    assert Semgrep.rule_arguments(ctx) == [
        "--config", "p/python", "--config", str(tmp_path / "rules"),
    ]  # fmt: skip

    ctx.settings.options["semgrep_rules"] = ["missing-rules.yaml"]
    with pytest.raises(ConfigError, match="neither a registry ruleset"):
        Semgrep.rule_arguments(ctx)


def test_semgrep_errors_are_reported(context) -> None:
    failed = {"results": [], "errors": [{"message": "Failed to download config p/default"}]}

    with pytest.raises(ToolError, match=r"semgrep failed \(exit 2\): Failed to download"):
        Semgrep().scan(context({"semgrep": json_out(failed, 2)}))
    with pytest.raises(ToolError, match="did not produce valid JSON"):
        Semgrep().scan(context({"semgrep": lambda argv, cwd: (0, "<html>proxy error</html>")}))
    with pytest.raises(ToolError, match="semgrep failed"):
        Semgrep().scan(context({"semgrep": lambda argv, cwd: (2, "", "boom")}))


def test_semgrep_coverage_follows_detected_languages(context) -> None:
    ctx = context({})

    assert Semgrep().coverage(ctx.profile) == {"sast:Python", "sast:Go"}


# --- bandit and gosec -------------------------------------------------------------


def test_bandit_findings(context) -> None:
    report = {
        "results": [
            {
                "code": f"3 def run(q):\n4     return eval('{MARKER}')\n",
                "filename": "./app/server.py",
                "issue_confidence": "HIGH",
                "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
                "issue_severity": "MEDIUM",
                "issue_text": "Use of possibly insecure function - consider using safer ast.literal_eval.",
                "line_number": 4,
                "line_range": [4, 5],
                "more_info": "https://bandit.readthedocs.io/en/1.9.2/blacklists/blacklist_calls.html",
                "test_id": "B307",
                "test_name": "blacklist",
            }
        ]
    }

    (finding,) = Bandit().scan(context({"bandit": json_out(report, 1)}))

    assert (finding.rule_id, finding.title, finding.severity) == (
        "B307",
        "blacklist",
        Severity.MEDIUM,
    )
    assert finding.location.path == "app/server.py"
    assert (finding.location.start_line, finding.location.end_line) == (4, 5)
    assert finding.identifiers == ("CWE-78",)
    assert finding.confidence == "high"
    # The source snippet is not copied.
    assert MARKER not in json.dumps(finding.to_dict())


def test_bandit_crash_is_a_tool_error(context) -> None:
    with pytest.raises(ToolError, match=r"bandit failed \(exit 2\)"):
        Bandit().scan(context({"bandit": lambda argv, cwd: (2, "", "usage: bandit")}))


def test_gosec_runs_per_module_and_parses_line_ranges(context) -> None:
    seen: list[Path] = []

    def handler(argv, cwd):
        seen.append(cwd)
        issue = {
            "severity": "HIGH",
            "confidence": "MEDIUM",
            "cwe": {"id": "78", "url": "https://cwe.mitre.org/data/definitions/78.html"},
            "rule_id": "G204",
            "details": "Subprocess launched with a potential tainted input or cmd arguments",
            "file": str(cwd / "main.go"),
            "code": f"12: exec.Command({MARKER})",
            "line": "12-14",
            "column": "9",
        }
        return 0, json.dumps({"Golang errors": {}, "Issues": [issue], "Stats": {"files": 1}})

    files = {
        "go.mod": "module a\n",
        "main.go": "package main\n",
        "tools/gen/go.mod": "module b\n",
        "tools/gen/main.go": "package main\n",
        "vendor/dep/go.mod": "module c\n",
        "node_modules/x/go.mod": "module d\n",
        "skipme/go.mod": "module e\n",
    }
    ctx = context(
        {"gosec": handler, "go": lambda argv, cwd: (0, "")}, files, exclude="exclude: [skipme]"
    )

    findings = Gosec().scan(ctx)

    assert [p.relative_to(ctx.root).as_posix() for p in seen] == [".", "tools/gen"]
    assert [f.location.path for f in findings] == ["main.go", "tools/gen/main.go"]
    assert (findings[0].location.start_line, findings[0].location.end_line) == (12, 14)
    assert findings[0].identifiers == ("CWE-78",)
    assert MARKER not in json.dumps([f.to_dict() for f in findings])


def test_gosec_needs_a_module_and_loadable_packages(context) -> None:
    with pytest.raises(ToolError, match=r"no go.mod"):
        Gosec().scan(context({"gosec": json_out({})}, {"main.go": "package main\n"}))

    broken = {
        "Golang errors": {"pkg/x": [{"error": "could not import"}]},
        "Issues": [],
        "Stats": {"files": 0},
    }
    with pytest.raises(ToolError, match="could not load any Go package"):
        Gosec().scan(context({"gosec": json_out(broken)}))


def test_gosec_is_only_available_with_the_go_toolchain() -> None:
    assert Gosec().available(FakeRunner({"gosec": None, "go": None}))  # type: ignore[arg-type]
    assert not Gosec().available(FakeRunner({"gosec": None}))  # type: ignore[arg-type]
    assert "Go toolchain" in Gosec().missing_message()


# --- syft, grype, osv-scanner, trivy ----------------------------------------------


def syft_handler(calls=None, write_native: bool = True):
    def handler(argv, cwd):
        if calls is not None:
            calls.append(argv)
        for argument in argv:
            kind, _, path = argument.partition("=")
            if kind == "cyclonedx-json" or (kind == "syft-json" and write_native):
                Path(path).write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
        return 0, ""

    return handler


def test_syft_writes_the_sbom_into_the_run_directory(context) -> None:
    calls: list[list[str]] = []
    ctx = context(
        {"syft": syft_handler(calls)}, exclude="exclude: [vendor, 'tests/fixtures', '*.lock']"
    )
    (ctx.root / "vendor").mkdir()

    assert Syft().scan(ctx) == []

    assert ctx.artifacts["sbom"] == ctx.artifacts_dir / "sbom.cdx.json"
    assert ctx.artifacts["sbom-syft"].exists()
    argv = calls[0]
    assert argv[argv.index("--source-name") + 1] == "app"
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--exclude"] == [
        "./vendor/**", "./tests/fixtures", "**/*.lock",
    ]  # fmt: skip


def test_syft_failure_is_a_tool_error(context) -> None:
    with pytest.raises(ToolError, match=r"syft failed \(exit 1\): cannot catalog"):
        Syft().scan(context({"syft": lambda argv, cwd: (1, "", "cannot catalog")}))


def test_anchore_excludes(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "a.txt").touch()

    assert anchore_excludes(tmp_path, ("docs/**", "a.txt", "*.min.js", "", "/")) == [
        "--exclude", "./docs/**", "--exclude", "./a.txt", "--exclude", "**/*.min.js",
    ]  # fmt: skip


GRYPE_REPORT = {
    "matches": [
        {
            "vulnerability": {
                "id": "GHSA-462w-v97r-4m45",
                "dataSource": "https://github.com/advisories/GHSA-462w-v97r-4m45",
                "severity": "High",
                "urls": [],
                "description": "High severity vulnerability that affects Jinja2",
                "cvss": [{"version": "3.1", "metrics": {"baseScore": 8.6}}],
                "cwes": [{"cve": "CVE-2019-10906", "cwe": "CWE-693"}],
                "fix": {"versions": ["2.10.1"], "state": "fixed"},
            },
            "relatedVulnerabilities": [
                {
                    "id": "CVE-2019-10906",
                    "cvss": [{"metrics": {"baseScore": 9.0}}, {"metrics": {"baseScore": "bad"}}],
                }
            ],
            "artifact": {
                "name": "jinja2",
                "version": "2.10",
                "type": "python",
                "locations": [{"path": "/requirements.txt"}],
                "purl": "pkg:pypi/jinja2@2.10",
            },
        },
        {"vulnerability": {"id": ""}, "artifact": {"name": "ignored"}},
        "not an object",
    ]
}


def test_grype_findings(context) -> None:
    calls: list[list[str]] = []

    def handler(argv, cwd):
        calls.append(argv)
        return 0, json.dumps(GRYPE_REPORT)

    ctx = context({"grype": handler})
    (finding,) = Grype().scan(ctx)

    assert finding.rule_id == "GHSA-462w-v97r-4m45"
    assert finding.severity is Severity.HIGH
    assert finding.cvss_score == 9.0
    assert finding.location.path == "requirements.txt"
    package = finding.package
    assert (package.ecosystem, package.name, package.version) == ("PyPI", "jinja2", "2.10")
    assert package.fixed_versions == ("2.10.1",)
    assert finding.identifiers == ("GHSA-462w-v97r-4m45", "CVE-2019-10906", "CWE-693")
    assert finding.references == ("https://github.com/advisories/GHSA-462w-v97r-4m45",)
    assert calls[0][1] == "dir:."


def test_grype_prefers_the_sbom_from_syft(context) -> None:
    calls: list[list[str]] = []

    def handler(argv, cwd):
        calls.append(argv)
        return 0, json.dumps({"matches": []})

    ctx = context({"grype": handler, "syft": syft_handler()})
    Syft().scan(ctx)

    assert Grype().scan(ctx) == []
    assert calls[0][1] == f"sbom:{ctx.artifacts_dir / 'sbom.syft.json'}"


def test_grype_database_failure_is_a_tool_error(context) -> None:
    handler = lambda argv, cwd: (1, "", "failed to load vulnerability db: unable to update")  # noqa: E731

    with pytest.raises(ToolError, match="unable to update"):
        Grype().scan(context({"grype": handler}))


OSV_REPORT = {
    "results": [
        {
            "source": {"path": "PLACEHOLDER", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"},
                    "vulnerabilities": [
                        {
                            "id": "GHSA-462w-v97r-4m45",
                            "summary": "Jinja2 sandbox escape via string formatting",
                            "aliases": ["CVE-2019-10906"],
                            "affected": [
                                {
                                    "package": {"ecosystem": "PyPI", "name": "Jinja2"},
                                    "ranges": [
                                        {
                                            "type": "ECOSYSTEM",
                                            "events": [{"introduced": "0"}, {"fixed": "2.10.1"}],
                                        },
                                        {"type": "GIT", "events": [{"fixed": "deadbeefdeadbeef"}]},
                                    ],
                                },
                                {
                                    "package": {"ecosystem": "PyPI", "name": "another-package"},
                                    "ranges": [
                                        {"type": "ECOSYSTEM", "events": [{"fixed": "9.9.9"}]}
                                    ],
                                },
                            ],
                            "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-693"]},
                            "references": [
                                {
                                    "type": "WEB",
                                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10906",
                                }
                            ],
                        },
                        {"id": "PYSEC-2019-217", "details": "Same issue, PyPA record"},
                        {
                            "id": "GHSA-g3rq-g295-4j3m",
                            "summary": "Regular expression denial of service",
                            "database_specific": {"severity": "MODERATE"},
                        },
                    ],
                    "groups": [
                        {
                            "ids": ["PYSEC-2019-217", "GHSA-462w-v97r-4m45"],
                            "aliases": ["CVE-2019-10906", "GHSA-462w-v97r-4m45", "PYSEC-2019-217"],
                            "max_severity": "8.6",
                        },
                        {
                            "ids": ["GHSA-g3rq-g295-4j3m"],
                            "aliases": ["GHSA-g3rq-g295-4j3m"],
                            "max_severity": "",
                        },
                        {"ids": []},
                    ],
                }
            ],
        }
    ]
}


def osv_handler(report, returncode: int = 1, version: str = "2.3.1", calls=None):
    def handler(argv, cwd):
        if "--version" in argv:
            return 0, f"osv-scanner version: {version}\ncommit: abc\n"
        if calls is not None:
            calls.append(argv)
        if report:
            report["results"][0]["source"]["path"] = str(cwd / "requirements.txt")
        return returncode, json.dumps(report) if report else ""

    return handler


def test_osv_scanner_groups_aliases_into_one_finding(context) -> None:
    calls: list[list[str]] = []

    first, second = OsvScanner().scan(
        context({"osv-scanner": osv_handler(OSV_REPORT, calls=calls)})
    )

    assert first.rule_id == "GHSA-462w-v97r-4m45"
    assert first.severity is Severity.HIGH and first.cvss_score == 8.6
    assert first.message == "Jinja2 sandbox escape via string formatting"
    assert first.location.path == "requirements.txt"
    assert first.package.fixed_versions == ("2.10.1",)
    assert first.identifiers == (
        "GHSA-462w-v97r-4m45", "CVE-2019-10906", "PYSEC-2019-217", "CWE-693",
    )  # fmt: skip
    assert first.references == ("https://nvd.nist.gov/vuln/detail/CVE-2019-10906",)
    # No CVSS score in the group: fall back to the advisory database's own rating.
    assert second.severity is Severity.MEDIUM and second.cvss_score is None
    assert calls[0] == ["osv-scanner", "scan", "source", "--format", "json", "-r", "."]


def test_osv_scanner_command_for_v1_and_v2() -> None:
    assert OsvScanner.command("1.9.2") == ["osv-scanner", "--format", "json", "-r", "."]
    assert OsvScanner.command("2.0.0")[1:3] == ["scan", "source"]
    assert OsvScanner.command(None)[1:3] == ["scan", "source"]


def test_osv_scanner_exit_codes(context) -> None:
    no_packages = context({"osv-scanner": osv_handler(None, returncode=128)})
    assert OsvScanner().scan(no_packages) == []

    with pytest.raises(ToolError, match=r"osv-scanner failed \(exit 127\)"):
        OsvScanner().scan(context({"osv-scanner": osv_handler(None, returncode=127)}))


def test_primary_advisory_id_is_deterministic() -> None:
    assert primary_id(["PYSEC-1", "CVE-2020-1", "GHSA-b", "GHSA-a"]) == "GHSA-a"
    assert primary_id(["PYSEC-1", "CVE-2020-2", "CVE-2020-1"]) == "CVE-2020-1"
    assert primary_id(["RUSTSEC-2", "PYSEC-1"]) == "PYSEC-1"


def test_trivy_findings(context) -> None:
    report = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2020-8203",
                        "VendorIDs": ["GHSA-p6mc-m468-83gw"],
                        "PkgName": "lodash",
                        "PkgIdentifier": {"PURL": "pkg:npm/lodash@4.17.15"},
                        "InstalledVersion": "4.17.15",
                        "FixedVersion": "4.17.19, 4.17.20",
                        "Severity": "HIGH",
                        "Title": "nodejs-lodash: prototype pollution in zipObjectDeep function",
                        "CweIDs": ["CWE-1321", "CWE-770"],
                        "CVSS": {"ghsa": {"V3Score": 7.4}, "nvd": {"V3Score": 7.4, "V2Score": 5.8}},
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8203",
                        "References": ["https://github.com/lodash/lodash/issues/4874"],
                    },
                    {"VulnerabilityID": "", "PkgName": "skipped"},
                ],
            },
            {"Target": "go.mod", "Type": "gomod"},
        ]
    }
    calls: list[list[str]] = []

    def handler(argv, cwd):
        calls.append(argv)
        return 0, json.dumps(report)

    ctx = context({"trivy": handler}, exclude="exclude: [cmd, '*.min.js']")
    (finding,) = Trivy().scan(ctx)

    assert finding.rule_id == "CVE-2020-8203"
    assert finding.severity is Severity.HIGH and finding.cvss_score == 7.4
    assert finding.location.path == "package-lock.json"
    assert finding.package.ecosystem == "npm"
    assert finding.package.fixed_versions == ("4.17.19", "4.17.20")
    assert finding.identifiers == ("CVE-2020-8203", "GHSA-p6mc-m468-83gw", "CWE-1321", "CWE-770")
    assert calls[0][:5] == ["trivy", "fs", "--scanners", "vuln", "--format"]
    # Only directories can be skipped; glob patterns are filtered after the scan.
    assert [calls[0][i + 1] for i, a in enumerate(calls[0]) if a == "--skip-dirs"] == ["cmd"]


def test_dependency_scanners_only_apply_when_packages_exist(context, tmp_path: Path) -> None:
    with_packages = context({}).profile
    without = detect_stack(write_tree(tmp_path / "docs-only", {"docs/readme.md": "# docs\n"}))

    for adapter in (Syft(), Grype(), OsvScanner(), Trivy()):
        assert adapter.coverage(with_packages)
        assert adapter.coverage(without) == set()


# --- shared behaviour -------------------------------------------------------------


def test_version_detection_and_missing_message(context, tmp_path: Path) -> None:
    runner = FakeRunner(
        {
            "semgrep": lambda argv, cwd: (0, "1.150.0\n"),
            "trivy": lambda argv, cwd: (0, "Version: 0.69.3\nVulnerability DB:\n"),
            "bandit": lambda argv, cwd: (0, "", "no version here"),
        }
    )

    assert Semgrep().version(runner, tmp_path) == "1.150.0"  # type: ignore[arg-type]
    assert Trivy().version(runner, tmp_path) == "0.69.3"  # type: ignore[arg-type]
    assert Bandit().version(runner, tmp_path) is None  # type: ignore[arg-type]
    assert not Grype().available(runner)  # type: ignore[arg-type]
    message = Grype().missing_message()
    assert "grype is not installed" in message and "Install:" in message


def test_defensive_parsing_helpers() -> None:
    assert (
        as_int("12-14") == 12 and as_int(0) is None and as_int(True) is None and as_int("x") is None
    )
    assert as_float("8.6") == 8.6 and as_float("11") is None and as_float(None) is None
    assert cwe_ids(["CWE-79: XSS", "cwe-89"], 22, {"id": "78"}, None, "nothing") == (
        "CWE-79", "CWE-89", "CWE-22", "CWE-78",
    )  # fmt: skip
    assert http_links(["https://a.invalid", "javascript:alert(1)", None, "https://a.invalid"]) == (
        "https://a.invalid",
    )
    assert ecosystem_for("python") == "PyPI" and ecosystem_for("go-module") == "Go"
    assert ecosystem_for("made-up") == "made-up" and ecosystem_for(None) == "unknown"
