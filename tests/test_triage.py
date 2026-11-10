"""Deterministic triage, and the proof that a model is not called unless configured."""

from __future__ import annotations

import json

import pytest

from htw.agents.triage import triage_findings
from htw.core.config import TriageSettings, load_config
from htw.core.finding import Severity
from htw.core.llm import HttpLlm, client_for
from htw.errors import ConfigError

from .conftest import scope_yaml
from .helpers import dependency_finding, sast_finding, secret_finding


def test_vendor_sast_and_doc_placeholders_are_filtered() -> None:
    vendor = sast_finding(path="vendor/lib/util.py")
    real = sast_finding()
    placeholder = secret_finding(path="docs/examples/settings.md", context="API_KEY = placeholder")
    real_secret = secret_finding()
    for finding in (vendor, real, placeholder, real_secret):
        finding.fingerprint = finding.location.path or ""

    kept, notes = triage_findings(
        [vendor, real, placeholder, real_secret], environment="production"
    )

    assert kept == [real, real_secret]
    assert {note.action for note in notes} == {"false_positive"}


def test_the_same_issue_from_two_tools_collapses_to_one() -> None:
    semgrep = sast_finding(tool="semgrep", severity=Severity.HIGH, identifiers=("CWE-95",))
    bandit = sast_finding(tool="bandit", severity=Severity.MEDIUM, identifiers=("CWE-95",))
    other = sast_finding(line=20, rule="python.sql", identifiers=("CWE-89",))
    for finding in (semgrep, bandit, other):
        finding.fingerprint = f"{finding.tool}:{finding.rule_id}:{finding.location.start_line}"

    kept, notes = triage_findings([semgrep, bandit, other], environment="production")

    assert kept == [semgrep, other]
    assert notes[0].action == "duplicate"
    assert "semgrep" in notes[0].reason


def test_two_advisories_for_one_package_are_not_collapsed() -> None:
    first = dependency_finding("CVE-2024-0001")
    second = dependency_finding("CVE-2024-0002", tool="trivy")
    first.identifiers = ("CVE-2024-0001",)
    second.identifiers = ("CVE-2024-0002",)
    first.fingerprint, second.fingerprint = "a", "b"

    kept, notes = triage_findings([first, second], environment="production")

    assert kept == [first, second] and notes == []


def test_low_confidence_lowers_priority_except_for_secrets() -> None:
    code = sast_finding()
    code.priority = "P1"
    code.confidence = "low"
    secret = secret_finding()
    secret.priority = "P1"
    secret.confidence = "low"

    triage_findings([code, secret], environment="production")

    assert code.priority == "P2"
    assert secret.priority == "P1"


def test_default_triage_does_not_call_a_provider() -> None:
    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        raise AssertionError(url)

    assert client_for(TriageSettings()) is None
    client = client_for(TriageSettings(llm=False, provider=None), transport)
    assert client is None
    kept, notes = triage_findings([sast_finding()], environment="development", llm=None)
    assert len(kept) == 1 and notes == []


def test_llm_is_off_unless_a_provider_and_key_name_are_configured(tmp_path) -> None:
    path = tmp_path / "htw.yaml"
    path.write_text(
        scope_yaml([{"id": "a", "path": "."}], top="triage:\n  llm: true\n"),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="provider"):
        load_config(path)

    path.write_text(
        scope_yaml(
            [{"id": "a", "path": "."}],
            top="triage:\n  llm: true\n  provider: openai\n  api_key_env: OPENAI_API_KEY\n",
        ),
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.triage.llm and config.triage.provider == "openai"


def test_configured_llm_reads_the_named_variable_and_no_other_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        seen["url"] = url
        seen["authorization"] = headers.get("Authorization")
        seen["body"] = body.decode()
        return json.dumps(
            {"choices": [{"message": {"content": json.dumps({"findings": []})}}]}
        ).encode()

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-from-the-environment")
    monkeypatch.delenv("ANOTHER_SECRET", raising=False)
    client = HttpLlm(
        TriageSettings(llm=True, provider="openai", api_key_env="OPENAI_API_KEY"),
        transport,
    )
    finding = sast_finding()
    finding.fingerprint = "htw1:abc"
    finding.context = "super-secret-line"
    finding.line_fix = None

    kept, notes = triage_findings([finding], environment="production", llm=client)

    assert kept == [finding] and notes == []
    assert seen["url"] == "https://api.openai.com/v1/chat/completions"
    assert seen["authorization"] == "Bearer sk-test-from-the-environment"
    body = str(seen["body"])
    assert "super-secret-line" not in body
    assert "htw1:abc" in body


def test_missing_api_key_does_not_call_the_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        raise AssertionError(url)

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    client = HttpLlm(
        TriageSettings(llm=True, provider="openai", api_key_env="OPENAI_API_KEY"),
        transport,
    )
    finding = sast_finding()
    finding.fingerprint = "htw1:abc"

    _kept, notes = triage_findings([finding], environment="production", llm=client)

    assert notes[0].action == "error"
    assert "does not invent credentials" in notes[0].reason
