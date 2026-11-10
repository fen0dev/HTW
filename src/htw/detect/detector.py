"""Stack detection: work out what an asset is made of, from the files alone.

Detection is static and read-only. It never follows symlinks, never executes anything
from the asset, and reads only a bounded prefix of the files it has to look inside.
The resulting profile decides which scanners apply, so every component carries the
paths that prove it.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from htw.core.paths import is_excluded
from htw.detect import signatures as sig
from htw.detect.model import (
    CI_CD,
    CLOUD,
    CONTAINER,
    IAC,
    LANGUAGE,
    PACKAGE_MANAGER,
    VCS,
    StackProfile,
)

DEFAULT_MAX_FILES = 200_000
SNIFF_BYTES = 64 * 1024
MAX_CONTENT_SNIFFS = 20_000

_API_VERSION_RE = re.compile(r"^apiVersion:\s*['\"]?([\w./-]+)", re.MULTILINE)
_KIND_RE = re.compile(r"^kind:\s*['\"]?(\w+)", re.MULTILINE)
_CFN_RESOURCE_RE = re.compile(r"""['"]?Type['"]?\s*:\s*['"]?AWS::\w+""")
_CFN_RESOURCES_RE = re.compile(r"""^\s*['"]?Resources['"]?\s*:""", re.MULTILINE)
_SAM_RE = re.compile(r"""['"]?Transform['"]?\s*:\s*[\[\s'"-]*AWS::Serverless""")
_ANSIBLE_PLAY_RE = re.compile(r"^-\s+(?:name:.*\n\s+)?hosts:\s*\S", re.MULTILINE)
_COMPOSE_SERVICES_RE = re.compile(r"^services:\s*$", re.MULTILINE)
_COMPOSE_SERVICE_BODY_RE = re.compile(r"^\s+(image|build):", re.MULTILINE)
_AZURE_PIPELINE_RE = re.compile(r"^(pool|trigger|pr):", re.MULTILINE)
_AZURE_PIPELINE_BODY_RE = re.compile(r"^(steps|stages|jobs):", re.MULTILINE)
_GAE_RUNTIME_RE = re.compile(r"^runtime:\s*\S", re.MULTILINE)
_TF_PROVIDER_RE = re.compile(r'^\s*provider\s+"([\w-]+)"', re.MULTILINE)
_TF_RESOURCE_RE = re.compile(r'^\s*(?:resource|data)\s+"([a-z0-9]+)_', re.MULTILINE)
_TF_SOURCE_RE = re.compile(r'source\s*=\s*"(?:registry\.terraform\.io/)?hashicorp/([\w-]+)"')
_SERVERLESS_PROVIDER_RE = re.compile(
    r"^provider:\s*\n(?:\s+.*\n)*?\s+name:\s*['\"]?(\w+)", re.MULTILINE
)
_POETRY_RE = re.compile(r"^\[tool\.poetry[\].]", re.MULTILINE)
_PDM_RE = re.compile(r"^\[tool\.pdm[\].]", re.MULTILINE)


def detect_stack(
    root: Path,
    exclude: Sequence[str] = (),
    max_files: int = DEFAULT_MAX_FILES,
) -> StackProfile:
    """Walk `root` and return the detected stack profile."""
    profile = StackProfile()
    root = Path(root)

    if (root / ".git").exists():
        profile.record(VCS, "Git", ".git")
    if (root / ".hg").is_dir():
        profile.record(VCS, "Mercurial", ".hg")
    if (root / ".gitmodules").is_file():
        profile.notes.append(
            "Git submodules are declared (.gitmodules). Submodule contents may be third-party "
            "code that your authorization does not cover; exclude them if so."
        )

    sniffs = 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = sorted(
            name
            for name in dirnames
            if not _prune(name, rel_dir, filenames, exclude, Path(dirpath))
        )
        for name in sorted(filenames):
            rel_path = f"{rel_dir}/{name}" if rel_dir else name
            if is_excluded(rel_path, exclude):
                continue
            full_path = os.path.join(dirpath, name)
            if os.path.islink(full_path):
                continue
            profile.files_seen += 1
            if profile.files_seen > max_files:
                profile.truncated = True
                profile.notes.append(
                    f"Detection stopped after {max_files} files; the profile may be incomplete."
                )
                _finalize(profile)
                return profile
            sniffs += _classify(profile, rel_path, name, full_path, sniffs < MAX_CONTENT_SNIFFS)

    if sniffs >= MAX_CONTENT_SNIFFS:
        profile.notes.append(
            "Content inspection budget reached; some YAML/JSON files were classified by name only."
        )
    _finalize(profile)
    return profile


def _prune(
    name: str, rel_dir: str, sibling_files: Iterable[str], exclude: Sequence[str], parent: Path
) -> bool:
    if name in sig.PRUNED_DIRECTORIES:
        return True
    if os.path.islink(parent / name):
        return True
    markers = sig.CONDITIONALLY_PRUNED.get(name)
    if markers and any(marker in sibling_files for marker in markers):
        return True
    rel_path = f"{rel_dir}/{name}" if rel_dir else name
    return is_excluded(rel_path, exclude)


def _classify(
    profile: StackProfile, rel_path: str, name: str, full_path: str, may_sniff: bool
) -> int:
    """Record everything `rel_path` is evidence of. Returns 1 if file content was read."""
    lower = name.lower()
    seen: set[tuple[str, str]] = set()

    def record(signature: sig.Signature) -> None:
        key = (signature.category, signature.name)
        if key in seen:
            return
        seen.add(key)
        component = profile.record(
            signature.category, signature.name, rel_path, signature.confidence
        )
        if signature.category == PACKAGE_MANAGER:
            component.attributes["ecosystem"] = signature.attributes["ecosystem"]
            kind = signature.attributes["kind"] + "s"
            component.attributes[kind] = int(component.attributes.get(kind, 0)) + 1
        for category, implied in signature.implies:
            if (category, implied) not in seen:
                seen.add((category, implied))
                profile.record(category, implied, rel_path, "medium")

    for signature in sig.FILENAME_SIGNATURES.get(lower, ()):
        record(signature)
    for suffix, signature in sig.SUFFIX_SIGNATURES:
        if lower.endswith(suffix) and len(lower) > len(suffix):
            record(signature)
            break
    for pattern, signature in sig.PATH_SIGNATURES:
        if pattern.search(rel_path):
            record(signature)

    extension = os.path.splitext(name)[1]
    language = sig.LANGUAGE_EXTENSIONS.get(extension) or sig.LANGUAGE_EXTENSIONS.get(
        extension.lower()
    )
    if language and not lower.endswith((".d.ts", ".min.js")):
        profile.record(LANGUAGE, language[0], rel_path, language[1])

    if lower == "pyproject.toml":
        text = _read_prefix(full_path)
        if _POETRY_RE.search(text):
            record(sig.package_manager("Poetry", "PyPI", "manifest"))
        elif _PDM_RE.search(text):
            record(sig.package_manager("PDM", "PyPI", "manifest"))
        else:
            record(sig.package_manager("pip", "PyPI", "manifest"))
        return 1
    if not may_sniff:
        return 0
    if lower.endswith((".yml", ".yaml")):
        _sniff_yaml(profile, rel_path, lower, _read_prefix(full_path), seen)
        return 1
    if lower.endswith((".json", ".template")):
        _sniff_json(profile, rel_path, _read_prefix(full_path), seen)
        return 1
    if lower.endswith((".tf", ".tofu")):
        _sniff_terraform(profile, rel_path, _read_prefix(full_path))
        return 1
    if not extension and not seen and not language:
        return _sniff_shebang(profile, rel_path, full_path)
    return 0


def _read_prefix(full_path: str) -> str:
    try:
        with open(full_path, "rb") as handle:
            data = handle.read(SNIFF_BYTES)
    except OSError:
        return ""
    if b"\x00" in data:
        return ""
    return data.decode("utf-8", errors="replace")


def _sniff_shebang(profile: StackProfile, rel_path: str, full_path: str) -> int:
    try:
        with open(full_path, "rb") as handle:
            first = handle.read(128).split(b"\n", 1)[0]
    except OSError:
        return 1
    if first.startswith(b"#!"):
        for pattern, language in sig.SHEBANG_LANGUAGES:
            if pattern.match(first):
                profile.record(LANGUAGE, language, rel_path, "medium")
                break
    return 1


def _sniff_yaml(
    profile: StackProfile, rel_path: str, lower: str, text: str, seen: set[tuple[str, str]]
) -> None:
    if not text:
        return

    def record(category: str, name: str, confidence: str = "high") -> None:
        if (category, name) not in seen:
            seen.add((category, name))
            profile.record(category, name, rel_path, confidence)

    api_versions = _API_VERSION_RE.findall(text)
    kinds = _KIND_RE.findall(text)
    if api_versions and kinds:
        for api_version, kind in zip(api_versions, kinds, strict=False):
            _classify_api_document(api_version, kind, record)

    if "AWSTemplateFormatVersion" in text or (
        _CFN_RESOURCES_RE.search(text) and _CFN_RESOURCE_RE.search(text)
    ):
        record(IAC, "AWS SAM" if _SAM_RE.search(text) else "CloudFormation")
        record(CLOUD, "AWS", "medium")

    if lower in ("serverless.yml", "serverless.yaml"):
        match = _SERVERLESS_PROVIDER_RE.search(text)
        provider = {"aws": "AWS", "azure": "Azure", "google": "Google Cloud"}.get(
            match.group(1).lower() if match else ""
        )
        if provider:
            record(CLOUD, provider, "medium")
        return

    if (CI_CD, "GitHub Actions") in seen or (IAC, "Helm") in seen:
        return
    if lower in ("app.yaml", "app.yml") and _GAE_RUNTIME_RE.search(text) and not api_versions:
        record(CLOUD, "Google Cloud", "medium")
    if _ANSIBLE_PLAY_RE.search(text):
        record(IAC, "Ansible", "medium")
    if (
        (CONTAINER, "Docker Compose") not in seen
        and _COMPOSE_SERVICES_RE.search(text)
        and _COMPOSE_SERVICE_BODY_RE.search(text)
    ):
        record(CONTAINER, "Docker Compose", "medium")
    if (
        not any(category == CI_CD for category, _ in seen)
        and not api_versions
        and _AZURE_PIPELINE_RE.search(text)
        and _AZURE_PIPELINE_BODY_RE.search(text)
    ):
        record(CI_CD, "Azure Pipelines", "medium")


def _classify_api_document(api_version: str, kind: str, record: Callable[..., None]) -> None:
    group = api_version.split("/", 1)[0] if "/" in api_version else ""
    if group in sig.NON_KUBERNETES_API_GROUPS or group.startswith("skaffold"):
        return
    if group == "tekton.dev":
        record(CI_CD, "Tekton")
    elif group == "argoproj.io":
        record(CI_CD, sig.ARGO_KINDS.get(kind, "Argo"))
    elif group.endswith(".toolkit.fluxcd.io"):
        record(CI_CD, "Flux")
    elif group == "kustomize.config.k8s.io":
        record(IAC, "Kustomize")
        return
    elif group.endswith("crossplane.io"):
        record(IAC, "Crossplane")
    elif not group and (api_version != "v1" or kind not in sig.KUBERNETES_CORE_KINDS):
        return
    record(
        IAC,
        "Kubernetes",
        "high" if not group or group in sig.KUBERNETES_API_GROUPS else "medium",
    )


def _sniff_json(
    profile: StackProfile, rel_path: str, text: str, seen: set[tuple[str, str]]
) -> None:
    if not text:
        return
    if '"AWSTemplateFormatVersion"' in text or (
        '"Resources"' in text and _CFN_RESOURCE_RE.search(text)
    ):
        profile.record(IAC, "AWS SAM" if _SAM_RE.search(text) else "CloudFormation", rel_path)
        if (CLOUD, "AWS") not in seen:
            profile.record(CLOUD, "AWS", rel_path, "medium")
    elif "deploymentTemplate.json" in text and '"$schema"' in text:
        profile.record(IAC, "ARM templates", rel_path)
        profile.record(CLOUD, "Azure", rel_path, "medium")


def _sniff_terraform(profile: StackProfile, rel_path: str, text: str) -> None:
    providers = set(_TF_PROVIDER_RE.findall(text)) | set(_TF_SOURCE_RE.findall(text))
    providers |= set(_TF_RESOURCE_RE.findall(text))
    recorded = set()
    for provider in sorted(providers):
        cloud = sig.TERRAFORM_PROVIDERS.get(provider)
        if cloud and cloud not in recorded:
            recorded.add(cloud)
            profile.record(CLOUD, cloud, rel_path, "high")


def _finalize(profile: StackProfile) -> None:
    """Add cross-file observations once the whole tree has been seen."""
    by_ecosystem: dict[str, dict[str, int]] = {}
    for component in profile.of(PACKAGE_MANAGER):
        ecosystem = str(component.attributes.get("ecosystem", ""))
        totals = by_ecosystem.setdefault(ecosystem, {"manifests": 0, "lockfiles": 0})
        totals["manifests"] += int(component.attributes.get("manifests", 0))
        totals["lockfiles"] += int(component.attributes.get("lockfiles", 0))
    for ecosystem, totals in sorted(by_ecosystem.items()):
        if totals["manifests"] and not totals["lockfiles"]:
            profile.notes.append(
                f"{ecosystem}: manifest without a lockfile. Dependency scanners only see the "
                "versions the manifest pins, so transitive dependencies may be missed."
            )
