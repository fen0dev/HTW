"""Stack detection against varied fixtures and edge cases.

The fixture expectations are exact: a component that appears or disappears
unexpectedly is a regression, because the profile decides which scanners run.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from htw.detect import detect_stack
from htw.detect.model import (
    CATEGORIES,
    CI_CD,
    CLOUD,
    CONTAINER,
    DEPENDENCY_AUTOMATION,
    IAC,
    LANGUAGE,
    PACKAGE_MANAGER,
    VCS,
)

from .conftest import STACKS, VULNERABLE_APP, write_tree

EXPECTED = {
    "python-service": {
        LANGUAGE: {"Python", "Shell"},
        PACKAGE_MANAGER: {"pip"},
        CONTAINER: {"Dockerfile", "Docker Compose"},
        CI_CD: {"GitHub Actions"},
        DEPENDENCY_AUTOMATION: {"Dependabot"},
    },
    "node-monorepo": {
        LANGUAGE: {"TypeScript", "JavaScript"},
        PACKAGE_MANAGER: {"npm", "pnpm"},
        CONTAINER: {"Docker Compose"},
        CLOUD: {"Vercel"},
        CI_CD: {"GitLab CI"},
        DEPENDENCY_AUTOMATION: {"Renovate"},
    },
    "go-kubernetes": {
        LANGUAGE: {"Go"},
        PACKAGE_MANAGER: {"Go modules"},
        CONTAINER: {"Dockerfile"},
        IAC: {"Kubernetes", "Kustomize", "Helm"},
        CI_CD: {"Jenkins", "GoReleaser", "Argo CD", "Tekton"},
    },
    "java-terraform-aws": {
        LANGUAGE: {"Java", "Kotlin"},
        PACKAGE_MANAGER: {"Maven"},
        IAC: {"Terraform", "CloudFormation"},
        CLOUD: {"AWS", "Google Cloud"},
        CI_CD: {"AWS CodeBuild", "Azure Pipelines", "Bitbucket Pipelines"},
    },
    "polyglot": {
        LANGUAGE: {
            "Rust", "Ruby", "PHP", "C#", "Elixir", "Dart", "Swift", "C", "C++",
            "Perl", "PowerShell", "SQL",
        },
        PACKAGE_MANAGER: {
            "Cargo", "Bundler", "Composer", "NuGet", "Mix", "Pub",
            "Swift Package Manager", "Conan",
        },
        IAC: {"Bicep", "ARM templates", "Ansible", "Pulumi", "Serverless Framework"},
        CLOUD: {"Azure", "AWS", "Fly.io"},
        CI_CD: {"CircleCI", "Travis CI", "Drone"},
    },
    "docs-only": {},
    "lookalikes": {},
}  # fmt: skip


def names_by_category(profile) -> dict[str, set[str]]:
    return {c: profile.names(c) for c in CATEGORIES if profile.names(c)}


@pytest.mark.parametrize("stack", sorted(EXPECTED))
def test_fixture_stack_is_detected_exactly(stack: str) -> None:
    profile = detect_stack(STACKS / stack)

    assert names_by_category(profile) == EXPECTED[stack]
    assert not profile.truncated


def test_every_fixture_stack_has_an_expectation() -> None:
    assert sorted(p.name for p in STACKS.iterdir() if p.is_dir()) == sorted(EXPECTED)


def test_vulnerable_app_fixture() -> None:
    profile = detect_stack(VULNERABLE_APP)

    assert profile.languages == {"Python", "JavaScript", "Go"}
    assert profile.names(PACKAGE_MANAGER) == {"pip", "npm", "Go modules"}
    assert profile.ecosystems == {"PyPI", "npm", "Go"}


def test_evidence_points_at_the_files_that_prove_a_component() -> None:
    profile = detect_stack(STACKS / "go-kubernetes")

    kubernetes = profile.components[(IAC, "Kubernetes")]
    assert "deploy/k8s/deployment.yaml" in kubernetes.evidence
    assert kubernetes.confidence == "high"
    assert profile.components[(CI_CD, "Jenkins")].evidence == ["Jenkinsfile"]
    # A multi-document manifest is one file, not two.
    assert kubernetes.count == 4


def test_dependency_directories_do_not_pollute_the_profile() -> None:
    node = detect_stack(STACKS / "node-monorepo")
    go = detect_stack(STACKS / "go-kubernetes")

    # node_modules holds .js and .py files; vendor/ holds .go and .rb files.
    assert node.components[(LANGUAGE, "JavaScript")].evidence == ["packages/web/src/legacy.js"]
    assert "Python" not in node.languages
    assert go.components[(LANGUAGE, "Go")].count == 2
    assert "Ruby" not in go.languages


def test_lockfiles_and_manifests_are_told_apart() -> None:
    node = detect_stack(STACKS / "node-monorepo")
    python = detect_stack(STACKS / "python-service")

    assert node.components[(PACKAGE_MANAGER, "pnpm")].attributes["lockfiles"] == 1
    assert node.components[(PACKAGE_MANAGER, "npm")].attributes == {
        "ecosystem": "npm",
        "manifests": 3,
    }
    assert not any("npm" in note for note in node.notes)
    assert any(note.startswith("PyPI: manifest without a lockfile") for note in python.notes)


def test_terraform_providers_reveal_the_cloud(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "main.tf": """
                provider "azurerm" {
                  features {}
                }
                resource "digitalocean_droplet" "web" {}
            """,
            "k8s.tf": 'provider "kubernetes" {}\n',
        },
    )

    profile = detect_stack(tmp_path)

    assert profile.names(IAC) == {"Terraform"}
    assert profile.names(CLOUD) == {"Azure", "DigitalOcean"}


def test_yaml_is_classified_by_content_not_by_name(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "stack.yml": """
                services:
                  db:
                    image: postgres:16
            """,
            "ops/release.yml": """
                trigger:
                  - main
                pool:
                  vmImage: ubuntu-latest
                stages:
                  - stage: Build
            """,
            "provision.yml": """
                - hosts: all
                  tasks:
                    - name: ping
                      ansible.builtin.ping:
            """,
            "sam/template.yaml": """
                Transform: AWS::Serverless-2016-10-31
                Resources:
                  Fn:
                    Type: AWS::Serverless::Function
            """,
            "cfn/stack.json": '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {}}',
            "gitops/release.yaml": """
                apiVersion: helm.toolkit.fluxcd.io/v2
                kind: HelmRelease
                metadata:
                  name: app
            """,
            "crd/monitor.yaml": """
                apiVersion: example.invalid/v1
                kind: Widget
            """,
        },
    )

    profile = detect_stack(tmp_path)

    assert profile.names(CONTAINER) == {"Docker Compose"}
    assert profile.components[(CONTAINER, "Docker Compose")].confidence == "medium"
    assert profile.names(CI_CD) == {"Azure Pipelines", "Flux"}
    assert profile.names(IAC) == {"Ansible", "AWS SAM", "CloudFormation", "Kubernetes"}
    # An unknown API group still looks like a Kubernetes resource, but less certainly.
    assert "crd/monitor.yaml" in profile.components[(IAC, "Kubernetes")].evidence
    assert profile.names(CLOUD) == {"AWS"}


def test_pyproject_backends(tmp_path: Path) -> None:
    write_tree(tmp_path / "a", {"pyproject.toml": "[tool.poetry]\nname = 'x'\n", "poetry.lock": ""})
    write_tree(tmp_path / "b", {"pyproject.toml": "[project]\nname = 'x'\n", "uv.lock": ""})

    assert detect_stack(tmp_path / "a").names(PACKAGE_MANAGER) == {"Poetry"}
    assert detect_stack(tmp_path / "b").names(PACKAGE_MANAGER) == {"pip", "uv"}
    assert not detect_stack(tmp_path / "b").notes


def test_scripts_without_extension_are_recognized_by_shebang(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "bin/run": "#!/usr/bin/env python3\nprint('x')\n",
            "bin/start": "#!/bin/sh\necho x\n",
            "bin/serve": "#!/usr/bin/env node\nconsole.log(1)\n",
            "bin/notes": "just text\n",
        },
    )

    profile = detect_stack(tmp_path)

    assert profile.languages == {"Python", "Shell", "JavaScript"}
    assert profile.components[(LANGUAGE, "Python")].confidence == "medium"


def test_symlinks_are_never_followed(tmp_path: Path) -> None:
    outside = write_tree(tmp_path / "outside", {"secret.py": "x = 1\n", "infra/main.tf": ""})
    root = tmp_path / "asset"
    root.mkdir()
    os.symlink(outside, root / "linked-dir")
    os.symlink(outside / "secret.py", root / "linked.py")

    profile = detect_stack(root)

    assert profile.components == {}
    assert profile.files_seen == 0


def test_excludes_apply_to_directories_globs_and_file_names(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "src/app.py": "",
            "third_party/lib/main.go": "",
            "third_party/lib/go.mod": "",
            "docs/examples/demo.rb": "",
            "generated/api_pb2.py": "",
            "web/app.generated.ts": "",
        },
    )

    profile = detect_stack(tmp_path, exclude=["third_party", "docs/examples/**", "*.generated.ts"])

    assert profile.languages == {"Python"}
    assert not profile.has(PACKAGE_MANAGER)
    assert profile.components[(LANGUAGE, "Python")].count == 2


def test_build_output_is_pruned_only_next_to_its_build_file(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "rust/Cargo.toml": "",
            "rust/src/main.rs": "",
            "rust/target/debug/build/gen.rs": "",
            "rust/target/debug/helper.py": "",
            "ops/target/deploy.sh": "",
            "php/composer.json": "{}",
            "php/vendor/lib/x.js": "",
            "plain/vendor/tool.rb": "",
        },
    )

    profile = detect_stack(tmp_path)

    assert profile.components[(LANGUAGE, "Rust")].count == 1
    assert "Python" not in profile.languages and "JavaScript" not in profile.languages
    # `target` and `vendor` are ordinary directory names elsewhere.
    assert {"Shell", "Ruby"} <= profile.languages


def test_binary_and_unreadable_content_does_not_break_detection(tmp_path: Path) -> None:
    (tmp_path / "blob.yaml").write_bytes(b"\x00\x01\x02apiVersion: apps/v1\nkind: Deployment\n")
    (tmp_path / "latin.yml").write_bytes(b"name: caf\xe9\nservices:\n  web:\n    image: x\n")
    (tmp_path / "empty.json").write_bytes(b"")

    profile = detect_stack(tmp_path)

    assert not profile.has(IAC)
    assert profile.names(CONTAINER) == {"Docker Compose"}


def test_large_trees_are_truncated_with_a_note(tmp_path: Path) -> None:
    write_tree(tmp_path, {f"src/m{i}.py": "" for i in range(30)})

    profile = detect_stack(tmp_path, max_files=10)

    assert profile.truncated
    assert any("may be incomplete" in note for note in profile.notes)
    assert profile.components[(LANGUAGE, "Python")].count == 10


def test_git_checkout_and_submodules_are_noted(tmp_path: Path) -> None:
    write_tree(tmp_path, {".git/config": "", ".git/hooks/pre-commit.py": "", ".gitmodules": ""})

    profile = detect_stack(tmp_path)

    assert profile.names(VCS) == {"Git"}
    assert profile.is_git_repository
    assert not profile.languages
    assert any("submodules" in note for note in profile.notes)


def test_profile_serializes_deterministically() -> None:
    first = detect_stack(STACKS / "polyglot").to_dict()
    second = detect_stack(STACKS / "polyglot").to_dict()

    assert first == second
    assert list(first["components"]) == [c for c in CATEGORIES if c in first["components"]]
