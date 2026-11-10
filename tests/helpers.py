from __future__ import annotations

from htw.core.finding import DEPENDENCY, SAST, SECRET, Finding, Location, Package, Severity

# Synthetic credential-shaped strings are assembled at import time so that no literal
# in this repository matches a provider token format.
FAKE_AWS_KEY_ID = "AKIA" + "Q7Z2" * 4
FAKE_GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5" * 4
FAKE_OPAQUE_TOKEN = "".join(f"{c}{i % 10}" for i, c in enumerate("QwErTyUiOpAsDfGhJkLz"))
_PEM_LABEL = "RSA " + "PRIVATE " + "KEY"
FAKE_PRIVATE_KEY = f"-----BEGIN {_PEM_LABEL}-----\nNOT+A+KEY+0000\n-----END {_PEM_LABEL}-----"
FAKE_DATABASE_URL = (
    "postgres://" + "fixture_user:" + "fixture-pass-0000" + "@db.fixture.invalid:5432/app"
)


def sast_finding(
    path: str = "app/server.py",
    line: int = 10,
    rule: str = "python.lang.security.eval",
    tool: str = "semgrep",
    severity: Severity = Severity.HIGH,
    asset: str = "app",
    **extra: object,
) -> Finding:
    return Finding(
        asset_id=asset,
        agent="sast",
        tool=tool,
        category=SAST,
        rule_id=rule,
        title="Use of eval",
        message="eval() on request data",
        severity=severity,
        location=Location(path, line, line),
        **extra,  # type: ignore[arg-type]
    )


def dependency_finding(
    advisory: str = "GHSA-aaaa-bbbb-cccc",
    name: str = "jinja2",
    version: str = "2.10",
    fixed: tuple[str, ...] = ("2.11.3",),
    ecosystem: str = "PyPI",
    path: str = "requirements.txt",
    tool: str = "grype",
    severity: Severity = Severity.HIGH,
    asset: str = "app",
) -> Finding:
    return Finding(
        asset_id=asset,
        agent="deps_sbom",
        tool=tool,
        category=DEPENDENCY,
        rule_id=advisory,
        title=f"{name} {version} is affected by {advisory}",
        message="Sandbox escape",
        severity=severity,
        location=Location(path),
        package=Package(ecosystem, name, version, fixed),
        identifiers=(advisory,),
    )


def secret_finding(
    path: str = "app/settings.py",
    line: int = 3,
    rule: str = "generic-api-key",
    context: str | None = "API_KEY = REDACTED",
    asset: str = "app",
) -> Finding:
    return Finding(
        asset_id=asset,
        agent="secrets",
        tool="gitleaks",
        category=SECRET,
        rule_id=rule,
        title="Generic API key",
        message="Detected a generic API key",
        severity=Severity.HIGH,
        location=Location(path, line, line),
        context=context,
    )
