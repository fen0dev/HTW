"""Container, IaC, pipeline and DAST adapters against canned output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from htw.core.config import AgentSettings, load_config
from htw.core.finding import Severity
from htw.detect import detect_stack
from htw.errors import ConfigError, ScopeViolation, ToolError
from htw.scanners.base import ScanContext
from htw.scanners.checkov import Checkov
from htw.scanners.hadolint import Hadolint
from htw.scanners.trivy_config import TrivyConfig
from htw.scanners.zap import Zap
from htw.scanners.zizmor import Zizmor

from .conftest import FakeRunner, scope_yaml, write_tree


def context(
    tmp_path: Path, handlers, files=None, *, top: str = "", extra: str = "", options=None
) -> ScanContext:
    root = write_tree(
        tmp_path / "target",
        files
        or {
            "Dockerfile": "FROM python:3.12\nUSER root\n",
            "main.tf": 'resource "aws_s3_bucket" "b" {}\n',
            ".github/workflows/ci.yml": "on: push\njobs: {}\n",
        },
    )
    (tmp_path / "htw.yaml").write_text(
        scope_yaml([{"id": "app", "path": "target", "extra": extra}], top=top),
        encoding="utf-8",
    )
    config = load_config(tmp_path / "htw.yaml")
    return ScanContext(
        asset=config.assets[0],
        root=root,
        profile=detect_stack(root),
        runner=FakeRunner(handlers),
        settings=AgentSettings(options=options or {}),
        config_dir=tmp_path,
        artifacts_dir=tmp_path / "artifacts",
    )


def test_hadolint_reads_dockerfiles_and_ignores_other_files(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def handler(argv, cwd):
        calls.append(argv)
        return 1, json.dumps(
            [
                {
                    "file": "Dockerfile",
                    "line": 2,
                    "level": "error",
                    "code": "DL3002",
                    "message": "root",
                }
            ]
        )

    findings = Hadolint().scan(context(tmp_path, {"hadolint": handler}))

    assert calls[0][:3] == ["hadolint", "--format", "json"]
    assert "Dockerfile" in calls[0]
    assert "main.tf" not in calls[0]
    assert findings[0].rule_id == "DL3002"
    assert findings[0].category == "container"
    assert findings[0].severity is Severity.HIGH


def test_trivy_config_keeps_only_the_agent_file_types(tmp_path: Path) -> None:
    payload = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "Title": "root",
                        "Severity": "HIGH",
                        "CauseMetadata": {"StartLine": 2},
                    }
                ],
            },
            {
                "Target": "main.tf",
                "Type": "terraform",
                "Misconfigurations": [
                    {"ID": "AVD-AWS-0086", "Title": "bucket", "Severity": "MEDIUM"}
                ],
            },
        ]
    }

    def handler(argv, cwd):
        return 0, json.dumps(payload)

    ctx = context(tmp_path, {"trivy": handler})
    container = TrivyConfig("container").scan(ctx)
    iac = TrivyConfig("iac").scan(ctx)

    assert [item.rule_id for item in container] == ["DS002"]
    assert [item.rule_id for item in iac] == ["AVD-AWS-0086"]
    assert "--skip-db-update" in ctx.runner.calls[0]
    assert "image" not in ctx.runner.calls[0]


def test_checkov_stays_inside_the_asset(tmp_path: Path) -> None:
    payload = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_1",
                    "check_name": "bucket logging",
                    "file_path": "/main.tf",
                    "file_line_range": [1, 1],
                    "severity": "HIGH",
                },
                {"check_id": "CKV_OUT", "check_name": "nope", "file_path": "/../../etc/passwd"},
            ]
        }
    }
    ctx = context(tmp_path, {"checkov": lambda argv, cwd: (1, json.dumps(payload))})

    (finding,) = Checkov("iac").scan(ctx)

    assert finding.location.path == "main.tf"
    assert finding.category == "iac"
    assert "--download-external-modules" in ctx.runner.calls[0]
    assert (
        ctx.runner.calls[0][ctx.runner.calls[0].index("--download-external-modules") + 1] == "false"
    )


def test_zizmor_is_offline(tmp_path: Path) -> None:
    payload = {
        "findings": [
            {
                "ident": "artipacked",
                "desc": "artifacts persist credentials",
                "url": "https://docs.zizmor.sh/audits/#artipacked",
                "determinations": {"severity": "high", "confidence": "high"},
                "locations": [
                    {"symbolic": {"path": ".github/workflows/ci.yml", "annotation": "line 1"}}
                ],
            }
        ]
    }
    ctx = context(tmp_path, {"zizmor": lambda argv, cwd: (0, json.dumps(payload))})

    (finding,) = Zizmor().scan(ctx)

    assert ctx.runner.calls[0][:4] == ["zizmor", "--offline", "--format", "json"]
    assert finding.rule_id == "artipacked"
    assert finding.location.path == ".github/workflows/ci.yml"
    assert finding.category == "pipeline"
    assert finding.confidence == "high"


def test_zap_refuses_any_target_that_is_not_the_approved_url(tmp_path: Path) -> None:
    called = []

    def handler(argv, cwd):
        called.append(argv)
        return 0, json.dumps({"site": []})

    ctx = context(tmp_path, {"zap-baseline.py": handler})
    with pytest.raises(ScopeViolation, match="current human approval"):
        Zap().scan(ctx)
    assert called == []


def test_zap_contacts_only_the_approved_url(tmp_path: Path) -> None:
    url = "https://staging.example.invalid"
    extra = f"""\
runtime:
  staging_url: {url}
approvals:
  - control: dast
    level: L2
    authorized_by: Jane Doe
    authorized_on: 2026-01-01
    expires_on: 2027-01-01
    target: {url}
"""
    ctx = context(
        tmp_path,
        {"zap-baseline.py": lambda argv, cwd: (0, json.dumps({"site": [{"alerts": []}]}))},
        extra=extra,
        options={"staging_url": url},
    )
    # The asset must carry the approval, which load_config puts on it.
    assert ctx.asset.staging_url == url

    assert Zap().scan(ctx) == []
    argv = ctx.runner.calls[0]
    assert argv[argv.index("-t") + 1] == url
    assert "169.254.169.254" not in argv


def test_staging_url_cannot_be_metadata_or_carry_credentials(tmp_path: Path) -> None:
    for url in (
        "http://169.254.169.254/",
        "https://metadata.google.internal/computeMetadata/",
        "https://user:secret@staging.example.invalid/",
        "file:///etc/passwd",
    ):
        path = tmp_path / "htw.yaml"
        path.write_text(
            scope_yaml([{"id": "a", "path": "."}]).replace(
                "    owner: platform-team\n",
                f"    owner: platform-team\n    runtime:\n      staging_url: {json.dumps(url)}\n",
            ),
            encoding="utf-8",
        )
        with pytest.raises(ConfigError, match=r"staging_url|scannable|credentials|http"):
            load_config(path)


def test_dockle_does_not_pull(tmp_path: Path) -> None:
    from htw.scanners.dockle import Dockle

    ctx = context(tmp_path, {"dockle": lambda argv, cwd: (0, "{}")})
    with pytest.raises(ToolError, match="does not pull"):
        Dockle().scan(ctx)
    assert ctx.runner.calls == []
