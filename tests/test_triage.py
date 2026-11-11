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


def test_the_same_ghsa_from_two_tools_collapses_without_changing_fingerprints() -> None:
    grype = dependency_finding("GHSA-aaaa-bbbb-cccc", tool="grype", severity=Severity.HIGH)
    trivy = dependency_finding("GHSA-aaaa-bbbb-cccc", tool="trivy", severity=Severity.MEDIUM)
    other = dependency_finding("GHSA-cccc-dddd-eeee", tool="osv-scanner")
    other_package = dependency_finding("GHSA-aaaa-bbbb-cccc", name="requests", tool="trivy")
    grype.fingerprint = "fp-grype"
    trivy.fingerprint = "fp-trivy"
    other.fingerprint = "fp-other"
    other_package.fingerprint = "fp-requests"

    kept, notes = triage_findings([trivy, grype, other, other_package], environment="development")

    assert kept == [grype, other, other_package]
    assert [item.fingerprint for item in kept] == ["fp-grype", "fp-other", "fp-requests"]
    assert notes[0].action == "duplicate"
    assert notes[0].fingerprint == "fp-trivy"
    assert "fp-grype" in notes[0].reason


def test_the_same_cve_from_two_tools_still_collapses() -> None:
    grype = dependency_finding("CVE-2024-0001", tool="grype", severity=Severity.HIGH)
    trivy = dependency_finding("CVE-2024-0001", tool="trivy", severity=Severity.LOW)
    grype.identifiers = ("CVE-2024-0001",)
    trivy.identifiers = ("CVE-2024-0001", "CWE-79")
    grype.fingerprint, trivy.fingerprint = "fp-grype", "fp-trivy"

    kept, notes = triage_findings([trivy, grype], environment="production")

    assert kept == [grype]
    assert grype.fingerprint == "fp-grype"
    assert notes[0].fingerprint == "fp-trivy"


def test_environment_does_not_change_priority() -> None:
    production = sast_finding()
    development = sast_finding()
    production.priority = "P1"
    development.priority = "P1"

    triage_findings([production], environment="production")
    triage_findings([development], environment="development")

    assert production.priority == development.priority == "P1"


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
    body = json.loads(str(seen["body"]))
    assert body["model"] == "gpt-4.1-mini"
    assert body["max_tokens"] == 384
    encoded = json.dumps(body)
    assert "super-secret-line" not in encoded
    assert "htw1:abc" in encoded


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


def _reply(findings: list[dict[str, object]]) -> bytes:
    return json.dumps(
        {"choices": [{"message": {"content": json.dumps({"findings": findings})}}]}
    ).encode()


def test_model_sees_only_findings_local_triage_left_unsettled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, str] = {}

    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        del url, headers
        seen["body"] = body.decode()
        return _reply([])

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    client = HttpLlm(
        TriageSettings(llm=True, provider="openai", api_key_env="OPENAI_API_KEY"),
        transport,
    )
    high = sast_finding(path="app/high.py")
    high.confidence = "high"
    high.fingerprint = "htw1:high"
    medium = sast_finding(path="app/medium.py")
    medium.confidence = "medium"
    medium.fingerprint = "htw1:medium"
    medium.message = "M" * 400
    vendor = sast_finding(path="vendor/lib.py")
    vendor.fingerprint = "htw1:vendor"

    kept, notes = triage_findings([high, medium, vendor], environment="production", llm=client)

    assert high in kept and medium in kept
    assert vendor not in kept
    assert notes[0].fingerprint == "htw1:vendor" and notes[0].action == "false_positive"
    assert seen["body"].count("htw1:medium") == 1
    assert "htw1:high" not in seen["body"]
    assert "htw1:vendor" not in seen["body"]
    assert "M" * 160 in seen["body"]
    assert "M" * 161 not in seen["body"]


def test_a_classified_fingerprint_is_not_sent_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    calls = {"n": 0}

    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        del url, headers, body
        calls["n"] += 1
        return _reply(
            [
                {
                    "fingerprint": "htw1:once",
                    "false_positive": True,
                    "confidence": "high",
                    "reason": "test fixture, not a real issue",
                }
            ]
        )

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    client = HttpLlm(
        TriageSettings(llm=True, provider="openai", api_key_env="OPENAI_API_KEY"),
        transport,
    )

    def finding() -> object:
        item = sast_finding()
        item.confidence = "medium"
        item.fingerprint = "htw1:once"
        return item

    first, notes = triage_findings(
        [finding()], environment="production", llm=client, state_dir=tmp_path
    )
    second, again = triage_findings(
        [finding()], environment="production", llm=client, state_dir=tmp_path
    )

    assert first == [] and second == []
    assert calls["n"] == 1
    assert notes[0].reason == again[0].reason
    assert "test fixture" in notes[0].reason


def test_confirming_low_confidence_does_not_lower_priority_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        del url, headers, body
        return _reply(
            [
                {
                    "fingerprint": "htw1:low",
                    "false_positive": False,
                    "confidence": "low",
                    "reason": "",
                }
            ]
        )

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    client = HttpLlm(
        TriageSettings(llm=True, provider="openai", api_key_env="OPENAI_API_KEY"),
        transport,
    )
    code = sast_finding()
    code.priority = "P1"
    code.confidence = "low"
    code.fingerprint = "htw1:low"

    triage_findings([code], environment="production", llm=client)

    assert code.priority == "P2"
    assert code.confidence == "low"


def test_anthropic_asks_for_a_short_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        del url, headers
        seen["body"] = json.loads(body)
        return json.dumps({"content": [{"text": json.dumps({"findings": []})}]}).encode()

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    client = HttpLlm(
        TriageSettings(llm=True, provider="anthropic", api_key_env="ANTHROPIC_API_KEY"),
        transport,
    )
    one = sast_finding()
    one.fingerprint = "htw1:one"
    triage_findings([one], environment="development", llm=client)
    assert seen["body"]["max_tokens"] == 384
    assert seen["body"]["model"] == "claude-sonnet-4-5"

    two = [sast_finding(path="app/a.py"), sast_finding(path="app/b.py")]
    two[0].fingerprint = "htw1:a"
    two[1].fingerprint = "htw1:b"
    triage_findings(two, environment="development", llm=client)
    assert seen["body"]["max_tokens"] == 640


def test_a_truncated_reply_is_not_applied(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        del url, headers, body
        return json.dumps(
            {
                "choices": [
                    {
                        "finish_reason": "length",
                        "message": {
                            "content": json.dumps(
                                {
                                    "findings": [
                                        {
                                            "fingerprint": "htw1:cut",
                                            "false_positive": True,
                                            "confidence": "high",
                                            "reason": "incomplete",
                                        }
                                    ]
                                }
                            )
                        },
                    }
                ]
            }
        ).encode()

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    client = HttpLlm(
        TriageSettings(llm=True, provider="openai", api_key_env="OPENAI_API_KEY"),
        transport,
    )
    finding = sast_finding()
    finding.fingerprint = "htw1:cut"
    finding.confidence = "medium"

    kept, notes = triage_findings(
        [finding], environment="production", llm=client, state_dir=tmp_path
    )

    assert kept == [finding]
    assert notes[0].action == "error"
    assert "truncated" in notes[0].reason
    assert not (tmp_path / "cache" / "llm-triage.json").exists()


def _triage_scope(tmp_path, top: str):
    path = tmp_path / "htw.yaml"
    path.write_text(scope_yaml([{"id": "a", "path": "."}], top=top), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "base_url",
    [
        "http://169.254.169.254/v1",
        "https://metadata.google.internal/computeMetadata/v1",
        "http://metadata.internal/v1",
        "http://169.254.1.1/v1",
        "http://[fe80::1]/v1",
        "http://[fe80::1%25eth0]/v1",
        "http://[::ffff:169.254.169.254]/v1",
    ],
)
def test_local_base_url_refuses_metadata_and_link_local(tmp_path, base_url: str) -> None:
    path = _triage_scope(
        tmp_path,
        "triage:\n"
        "  llm: true\n"
        "  provider: local\n"
        f"  base_url: {json.dumps(base_url)}\n"
        "  model: your-model-name\n",
    )
    with pytest.raises(ConfigError, match="link-local or cloud metadata"):
        load_config(path)


def test_local_base_url_refuses_credentials_and_a_non_http_scheme(tmp_path) -> None:
    for base_url in ("http://user:secret@127.0.0.1:8000/v1", "file:///tmp/model"):
        path = _triage_scope(
            tmp_path,
            "triage:\n"
            "  llm: true\n"
            "  provider: local\n"
            f"  base_url: {json.dumps(base_url)}\n"
            "  model: your-model-name\n",
        )
        with pytest.raises(ConfigError, match="base_url"):
            load_config(path)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1:8000/v1",
        "http://localhost:8080/v1",
        "http://[::1]:8080/v1",
        "http://ollama.localhost:11434/v1",
        "https://models.example.com/v1",
    ],
)
def test_local_provider_accepts_loopback_and_an_ordinary_host(tmp_path, base_url: str) -> None:
    path = _triage_scope(
        tmp_path,
        "triage:\n"
        "  llm: true\n"
        "  provider: local\n"
        f"  base_url: {json.dumps(base_url)}\n"
        "  model: your-model-name\n",
    )
    config = load_config(path)
    assert config.triage.llm is True
    assert config.triage.provider == "local"
    assert config.triage.base_url == base_url
    assert config.triage.model == "your-model-name"
    assert config.triage.api_key_env is None


def test_local_provider_treats_a_blank_api_key_name_as_unset(tmp_path) -> None:
    path = _triage_scope(
        tmp_path,
        "triage:\n"
        "  llm: true\n"
        "  provider: local\n"
        "  base_url: http://127.0.0.1:8000/v1\n"
        "  model: your-model-name\n"
        '  api_key_env: ""\n',
    )
    config = load_config(path)
    assert config.triage.api_key_env is None


def test_local_provider_requires_a_base_url_and_a_model_name(tmp_path) -> None:
    missing_model = _triage_scope(
        tmp_path,
        "triage:\n  llm: true\n  provider: local\n  base_url: http://127.0.0.1:8000/v1\n",
    )
    with pytest.raises(ConfigError, match="does not pick a default model"):
        load_config(missing_model)

    missing_url = _triage_scope(
        tmp_path,
        "triage:\n  llm: true\n  provider: local\n  model: your-model-name\n",
    )
    with pytest.raises(ConfigError, match="base_url"):
        load_config(missing_url)

    cloud = _triage_scope(
        tmp_path,
        "triage:\n"
        "  llm: true\n"
        "  provider: openai\n"
        "  api_key_env: OPENAI_API_KEY\n"
        "  base_url: http://127.0.0.1:8000/v1\n",
    )
    with pytest.raises(ConfigError, match="only used when `provider` is local"):
        load_config(cloud)


def test_local_fields_stay_off_unless_llm_is_enabled(tmp_path) -> None:
    path = _triage_scope(
        tmp_path,
        "triage:\n  llm: false\n  provider: local\n  base_url: http://127.0.0.1:8000/v1\n",
    )
    with pytest.raises(ConfigError, match="require `llm: true`"):
        load_config(path)


def test_local_client_refuses_a_metadata_url_before_any_request() -> None:
    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        raise AssertionError(url)

    with pytest.raises(ConfigError, match="link-local or cloud metadata"):
        HttpLlm(
            TriageSettings(
                llm=True,
                provider="local",
                model="your-model-name",
                base_url="http://169.254.169.254/v1",
            ),
            transport,
        )


def test_local_provider_applies_a_mocked_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        seen["url"] = url
        seen["headers"] = dict(headers)
        seen["body"] = json.loads(body)
        return _reply(
            [
                {
                    "fingerprint": "htw1:local",
                    "false_positive": True,
                    "confidence": "high",
                    "reason": "test fixture, not a real issue",
                }
            ]
        )

    monkeypatch.delenv("LOCAL_LLM_API_KEY", raising=False)
    client = HttpLlm(
        TriageSettings(
            llm=True,
            provider="local",
            model="your-model-name",
            base_url="http://127.0.0.1:8000/v1/",
        ),
        transport,
    )
    finding = sast_finding()
    finding.fingerprint = "htw1:local"
    finding.confidence = "medium"
    finding.context = "super-secret-line"
    finding.line_fix = "patched source"

    kept, notes = triage_findings([finding], environment="production", llm=client)

    assert kept == []
    assert notes[0].action == "false_positive"
    assert seen["url"] == "http://127.0.0.1:8000/v1/chat/completions"
    headers = seen["headers"]
    assert isinstance(headers, dict)
    assert "Authorization" not in headers
    body = seen["body"]
    assert isinstance(body, dict)
    assert body["model"] == "your-model-name"
    assert body["max_tokens"] == 384
    content = str(body["messages"][0]["content"])
    item = json.loads(content.split("\n", 1)[1])[0]
    assert item == {
        "fingerprint": "htw1:local",
        "rule": "python.lang.security.eval",
        "path": "app/server.py",
        "line": "10",
        "category": "sast",
        "severity": "high",
        "message": "eval() on request data",
    }
    encoded = json.dumps(body)
    assert "super-secret-line" not in encoded
    assert "patched source" not in encoded


def test_local_provider_calls_when_the_named_variable_is_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        del url, body
        seen["headers"] = dict(headers)
        return _reply([])

    monkeypatch.setenv("LOCAL_LLM_API_KEY", "")
    client = HttpLlm(
        TriageSettings(
            llm=True,
            provider="local",
            model="your-model-name",
            base_url="http://127.0.0.1:8000/v1",
            api_key_env="LOCAL_LLM_API_KEY",
        ),
        transport,
    )
    finding = sast_finding()
    finding.fingerprint = "htw1:empty"
    triage_findings([finding], environment="development", llm=client)
    headers = seen["headers"]
    assert isinstance(headers, dict)
    assert "Authorization" not in headers


def test_local_provider_sends_a_bearer_token_when_one_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, str] = {}

    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        del url, body
        seen["authorization"] = headers.get("Authorization", "")
        return _reply([])

    monkeypatch.setenv("LOCAL_LLM_API_KEY", "local-test-token")
    client = HttpLlm(
        TriageSettings(
            llm=True,
            provider="local",
            model="your-model-name",
            base_url="http://10.1.2.3:8000/v1",
            api_key_env="LOCAL_LLM_API_KEY",
        ),
        transport,
    )
    finding = sast_finding()
    finding.fingerprint = "htw1:token"
    triage_findings([finding], environment="development", llm=client)
    assert seen["authorization"] == "Bearer local-test-token"


def test_a_truncated_local_reply_is_not_applied(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    def transport(url: str, headers: dict[str, str], body: bytes) -> bytes:
        del url, headers, body
        return json.dumps(
            {
                "choices": [
                    {
                        "finish_reason": "length",
                        "message": {
                            "content": json.dumps(
                                {
                                    "findings": [
                                        {
                                            "fingerprint": "htw1:cut",
                                            "false_positive": True,
                                            "confidence": "high",
                                            "reason": "incomplete",
                                        }
                                    ]
                                }
                            )
                        },
                    }
                ]
            }
        ).encode()

    monkeypatch.delenv("LOCAL_LLM_API_KEY", raising=False)
    client = HttpLlm(
        TriageSettings(
            llm=True,
            provider="local",
            model="your-model-name",
            base_url="http://127.0.0.1:8000/v1",
        ),
        transport,
    )
    finding = sast_finding()
    finding.fingerprint = "htw1:cut"
    finding.confidence = "medium"

    kept, notes = triage_findings(
        [finding], environment="production", llm=client, state_dir=tmp_path
    )

    assert kept == [finding]
    assert finding.confidence == "medium"
    assert notes[0].action == "error"
    assert "truncated" in notes[0].reason
    assert not (tmp_path / "cache" / "llm-triage.json").exists()


def test_local_transport_does_not_follow_a_redirect() -> None:
    from htw.core.llm import _RefuseRedirect

    with pytest.raises(ConfigError, match="will not follow"):
        _RefuseRedirect().redirect_request(None, None, 302, "Found", {}, "http://169.254.169.254/")
