"""Detection signatures: the file names, paths and content markers that identify a stack.

This module is data. Adding support for a new technology should normally mean adding
a line here and a fixture under tests/fixtures/stacks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from htw.detect.model import (
    CI_CD,
    CLOUD,
    CONTAINER,
    DEPENDENCY_AUTOMATION,
    IAC,
    PACKAGE_MANAGER,
)


@dataclass(frozen=True)
class Signature:
    category: str
    name: str
    confidence: str = "high"
    attributes: dict[str, str] = field(default_factory=dict)
    implies: tuple[tuple[str, str], ...] = ()


def package_manager(name: str, ecosystem: str, kind: str) -> Signature:
    return Signature(PACKAGE_MANAGER, name, attributes={"ecosystem": ecosystem, "kind": kind})


# Directories that only ever hold dependencies, caches or tool state.
PRUNED_DIRECTORIES = frozenset(
    {
        ".git", ".hg", ".svn", ".htw",
        "node_modules", "bower_components", "jspm_packages",
        ".venv", "venv", "site-packages", "__pycache__", ".eggs",
        ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
        ".terraform", ".terragrunt-cache", ".gradle", ".m2", ".bundle",
        ".dart_tool", "Pods", "Carthage", ".next", ".nuxt", ".svelte-kit",
        ".idea", ".vscode", ".cache",
    }
)  # fmt: skip

# Pruned only when a sibling file shows that the directory is build or vendor output.
CONDITIONALLY_PRUNED = {
    "target": ("Cargo.toml", "pom.xml", "build.sbt"),
    "vendor": ("go.mod", "composer.json", "Gemfile"),
}

# Extensions are matched case-sensitively first (so .R and .C keep their meaning) and
# lowercased second.
LANGUAGE_EXTENSIONS: dict[str, tuple[str, str]] = {
    ".py": ("Python", "high"), ".pyi": ("Python", "high"), ".pyx": ("Python", "medium"),
    ".js": ("JavaScript", "high"), ".mjs": ("JavaScript", "high"),
    ".cjs": ("JavaScript", "high"), ".jsx": ("JavaScript", "high"),
    ".ts": ("TypeScript", "high"), ".tsx": ("TypeScript", "high"),
    ".mts": ("TypeScript", "high"), ".cts": ("TypeScript", "high"),
    ".vue": ("JavaScript", "medium"), ".svelte": ("JavaScript", "medium"),
    ".go": ("Go", "high"),
    ".java": ("Java", "high"),
    ".kt": ("Kotlin", "high"), ".kts": ("Kotlin", "medium"),
    ".scala": ("Scala", "high"), ".sc": ("Scala", "medium"),
    ".groovy": ("Groovy", "high"),
    ".rb": ("Ruby", "high"), ".rake": ("Ruby", "high"),
    ".php": ("PHP", "high"),
    ".cs": ("C#", "high"), ".fs": ("F#", "high"), ".vb": ("Visual Basic", "high"),
    ".c": ("C", "high"), ".h": ("C", "medium"),
    ".cc": ("C++", "high"), ".cpp": ("C++", "high"), ".cxx": ("C++", "high"),
    ".hpp": ("C++", "high"), ".hh": ("C++", "high"), ".hxx": ("C++", "high"),
    ".rs": ("Rust", "high"),
    ".swift": ("Swift", "high"),
    ".m": ("Objective-C", "medium"), ".mm": ("Objective-C", "high"),
    ".dart": ("Dart", "high"),
    ".ex": ("Elixir", "high"), ".exs": ("Elixir", "high"),
    ".erl": ("Erlang", "high"),
    ".hs": ("Haskell", "high"),
    ".lua": ("Lua", "high"),
    ".pl": ("Perl", "medium"), ".pm": ("Perl", "medium"),
    ".r": ("R", "medium"), ".R": ("R", "high"),
    ".jl": ("Julia", "high"),
    ".clj": ("Clojure", "high"), ".cljs": ("Clojure", "high"), ".cljc": ("Clojure", "high"),
    ".sol": ("Solidity", "high"),
    ".sh": ("Shell", "high"), ".bash": ("Shell", "high"), ".zsh": ("Shell", "high"),
    ".ps1": ("PowerShell", "high"), ".psm1": ("PowerShell", "high"),
    ".sql": ("SQL", "high"),
}  # fmt: skip

SHEBANG_LANGUAGES = (
    (re.compile(rb"^#!.*\bpython[0-9.]*\b"), "Python"),
    (re.compile(rb"^#!.*\b(ba|z|k|da)?sh\b"), "Shell"),
    (re.compile(rb"^#!.*\b(node|deno|bun)\b"), "JavaScript"),
    (re.compile(rb"^#!.*\bruby\b"), "Ruby"),
    (re.compile(rb"^#!.*\bperl\b"), "Perl"),
    (re.compile(rb"^#!.*\bphp\b"), "PHP"),
)

_AWS = ((CLOUD, "AWS"),)
_AZURE = ((CLOUD, "Azure"),)
_GCP = ((CLOUD, "Google Cloud"),)

# Exact file names, compared case-insensitively.
FILENAME_SIGNATURES: dict[str, tuple[Signature, ...]] = {
    # JavaScript / TypeScript
    "package.json": (package_manager("npm", "npm", "manifest"),),
    "package-lock.json": (package_manager("npm", "npm", "lockfile"),),
    "npm-shrinkwrap.json": (package_manager("npm", "npm", "lockfile"),),
    "yarn.lock": (package_manager("Yarn", "npm", "lockfile"),),
    "pnpm-lock.yaml": (package_manager("pnpm", "npm", "lockfile"),),
    "pnpm-workspace.yaml": (package_manager("pnpm", "npm", "manifest"),),
    "bun.lockb": (package_manager("Bun", "npm", "lockfile"),),
    "bun.lock": (package_manager("Bun", "npm", "lockfile"),),
    "deno.json": (package_manager("Deno", "npm", "manifest"),),
    "deno.jsonc": (package_manager("Deno", "npm", "manifest"),),
    "deno.lock": (package_manager("Deno", "npm", "lockfile"),),
    # Python
    "pipfile": (package_manager("Pipenv", "PyPI", "manifest"),),
    "pipfile.lock": (package_manager("Pipenv", "PyPI", "lockfile"),),
    "poetry.lock": (package_manager("Poetry", "PyPI", "lockfile"),),
    "uv.lock": (package_manager("uv", "PyPI", "lockfile"),),
    "pdm.lock": (package_manager("PDM", "PyPI", "lockfile"),),
    "setup.py": (package_manager("pip", "PyPI", "manifest"),),
    "setup.cfg": (package_manager("pip", "PyPI", "manifest"),),
    "environment.yml": (package_manager("Conda", "Conda", "manifest"),),
    "environment.yaml": (package_manager("Conda", "Conda", "manifest"),),
    "conda-lock.yml": (package_manager("Conda", "Conda", "lockfile"),),
    # Go
    "go.mod": (package_manager("Go modules", "Go", "manifest"),),
    "go.sum": (package_manager("Go modules", "Go", "lockfile"),),
    "go.work": (package_manager("Go modules", "Go", "manifest"),),
    # Rust
    "cargo.toml": (package_manager("Cargo", "crates.io", "manifest"),),
    "cargo.lock": (package_manager("Cargo", "crates.io", "lockfile"),),
    # JVM
    "pom.xml": (package_manager("Maven", "Maven", "manifest"),),
    "build.gradle": (package_manager("Gradle", "Maven", "manifest"),),
    "build.gradle.kts": (package_manager("Gradle", "Maven", "manifest"),),
    "settings.gradle": (package_manager("Gradle", "Maven", "manifest"),),
    "settings.gradle.kts": (package_manager("Gradle", "Maven", "manifest"),),
    "gradle.lockfile": (package_manager("Gradle", "Maven", "lockfile"),),
    "build.sbt": (package_manager("sbt", "Maven", "manifest"),),
    "deps.edn": (package_manager("Clojure CLI", "Maven", "manifest"),),
    "project.clj": (package_manager("Leiningen", "Maven", "manifest"),),
    # Ruby
    "gemfile": (package_manager("Bundler", "RubyGems", "manifest"),),
    "gemfile.lock": (package_manager("Bundler", "RubyGems", "lockfile"),),
    # PHP
    "composer.json": (package_manager("Composer", "Packagist", "manifest"),),
    "composer.lock": (package_manager("Composer", "Packagist", "lockfile"),),
    # .NET
    "packages.config": (package_manager("NuGet", "NuGet", "manifest"),),
    "packages.lock.json": (package_manager("NuGet", "NuGet", "lockfile"),),
    "directory.packages.props": (package_manager("NuGet", "NuGet", "manifest"),),
    "paket.dependencies": (package_manager("Paket", "NuGet", "manifest"),),
    "paket.lock": (package_manager("Paket", "NuGet", "lockfile"),),
    # Elixir / Erlang
    "mix.exs": (package_manager("Mix", "Hex", "manifest"),),
    "mix.lock": (package_manager("Mix", "Hex", "lockfile"),),
    "rebar.config": (package_manager("Rebar", "Hex", "manifest"),),
    "rebar.lock": (package_manager("Rebar", "Hex", "lockfile"),),
    # Dart / Flutter
    "pubspec.yaml": (package_manager("Pub", "Pub", "manifest"),),
    "pubspec.lock": (package_manager("Pub", "Pub", "lockfile"),),
    # Swift / Objective-C
    "package.swift": (package_manager("Swift Package Manager", "SwiftURL", "manifest"),),
    "package.resolved": (package_manager("Swift Package Manager", "SwiftURL", "lockfile"),),
    "podfile": (package_manager("CocoaPods", "CocoaPods", "manifest"),),
    "podfile.lock": (package_manager("CocoaPods", "CocoaPods", "lockfile"),),
    "cartfile": (package_manager("Carthage", "Carthage", "manifest"),),
    "cartfile.resolved": (package_manager("Carthage", "Carthage", "lockfile"),),
    # C / C++
    "conanfile.txt": (package_manager("Conan", "ConanCenter", "manifest"),),
    "conanfile.py": (package_manager("Conan", "ConanCenter", "manifest"),),
    "conan.lock": (package_manager("Conan", "ConanCenter", "lockfile"),),
    "vcpkg.json": (package_manager("vcpkg", "vcpkg", "manifest"),),
    # Haskell, Perl, R
    "stack.yaml": (package_manager("Stack", "Hackage", "manifest"),),
    "stack.yaml.lock": (package_manager("Stack", "Hackage", "lockfile"),),
    "cabal.project": (package_manager("Cabal", "Hackage", "manifest"),),
    "cabal.project.freeze": (package_manager("Cabal", "Hackage", "lockfile"),),
    "cpanfile": (package_manager("CPAN", "CPAN", "manifest"),),
    "cpanfile.snapshot": (package_manager("CPAN", "CPAN", "lockfile"),),
    "renv.lock": (package_manager("renv", "CRAN", "lockfile"),),
    # Infrastructure as code
    ".terraform.lock.hcl": (Signature(IAC, "Terraform"),),
    "terragrunt.hcl": (Signature(IAC, "Terragrunt"),),
    "chart.yaml": (Signature(IAC, "Helm"),),
    "kustomization.yaml": (Signature(IAC, "Kustomize"),),
    "kustomization.yml": (Signature(IAC, "Kustomize"),),
    "kustomization": (Signature(IAC, "Kustomize"),),
    "pulumi.yaml": (Signature(IAC, "Pulumi"),),
    "serverless.yml": (Signature(IAC, "Serverless Framework"),),
    "serverless.yaml": (Signature(IAC, "Serverless Framework"),),
    "serverless.ts": (Signature(IAC, "Serverless Framework"),),
    "cdk.json": (Signature(IAC, "AWS CDK", implies=_AWS),),
    "cdktf.json": (Signature(IAC, "CDK for Terraform"),),
    "samconfig.toml": (Signature(IAC, "AWS SAM", implies=_AWS),),
    "ansible.cfg": (Signature(IAC, "Ansible"),),
    "vagrantfile": (Signature(IAC, "Vagrant"),),
    "azure.yaml": (Signature(IAC, "Azure Developer CLI", implies=_AZURE),),
    # Platforms
    "vercel.json": (Signature(CLOUD, "Vercel"),),
    "netlify.toml": (Signature(CLOUD, "Netlify"),),
    "fly.toml": (Signature(CLOUD, "Fly.io"),),
    "render.yaml": (Signature(CLOUD, "Render"),),
    "wrangler.toml": (Signature(CLOUD, "Cloudflare"),),
    "wrangler.json": (Signature(CLOUD, "Cloudflare"),),
    "wrangler.jsonc": (Signature(CLOUD, "Cloudflare"),),
    "firebase.json": (Signature(CLOUD, "Firebase", implies=_GCP),),
    "procfile": (Signature(CLOUD, "Heroku-style Procfile", confidence="medium"),),
    "dockerrun.aws.json": (Signature(CLOUD, "AWS"),),
    "staticwebapp.config.json": (Signature(CLOUD, "Azure"),),
    # CI/CD
    ".gitlab-ci.yml": (Signature(CI_CD, "GitLab CI"),),
    ".gitlab-ci.yaml": (Signature(CI_CD, "GitLab CI"),),
    "jenkinsfile": (Signature(CI_CD, "Jenkins"),),
    "bitbucket-pipelines.yml": (Signature(CI_CD, "Bitbucket Pipelines"),),
    ".travis.yml": (Signature(CI_CD, "Travis CI"),),
    ".drone.yml": (Signature(CI_CD, "Drone"),),
    ".drone.yaml": (Signature(CI_CD, "Drone"),),
    ".drone.jsonnet": (Signature(CI_CD, "Drone"),),
    ".woodpecker.yml": (Signature(CI_CD, "Woodpecker"),),
    ".woodpecker.yaml": (Signature(CI_CD, "Woodpecker"),),
    "appveyor.yml": (Signature(CI_CD, "AppVeyor"),),
    ".appveyor.yml": (Signature(CI_CD, "AppVeyor"),),
    "cloudbuild.yaml": (Signature(CI_CD, "Google Cloud Build", implies=_GCP),),
    "cloudbuild.yml": (Signature(CI_CD, "Google Cloud Build", implies=_GCP),),
    "cloudbuild.json": (Signature(CI_CD, "Google Cloud Build", implies=_GCP),),
    "buildspec.yml": (Signature(CI_CD, "AWS CodeBuild", implies=_AWS),),
    "buildspec.yaml": (Signature(CI_CD, "AWS CodeBuild", implies=_AWS),),
    "appspec.yml": (Signature(CI_CD, "AWS CodeDeploy", implies=_AWS),),
    "appspec.yaml": (Signature(CI_CD, "AWS CodeDeploy", implies=_AWS),),
    "codefresh.yml": (Signature(CI_CD, "Codefresh"),),
    "skaffold.yaml": (Signature(CI_CD, "Skaffold"),),
    "skaffold.yml": (Signature(CI_CD, "Skaffold"),),
    ".goreleaser.yaml": (Signature(CI_CD, "GoReleaser"),),
    ".goreleaser.yml": (Signature(CI_CD, "GoReleaser"),),
    "dagger.json": (Signature(CI_CD, "Dagger"),),
    "earthfile": (Signature(CI_CD, "Earthly"),),
    # Dependency automation
    "renovate.json": (Signature(DEPENDENCY_AUTOMATION, "Renovate"),),
    "renovate.json5": (Signature(DEPENDENCY_AUTOMATION, "Renovate"),),
    ".renovaterc": (Signature(DEPENDENCY_AUTOMATION, "Renovate"),),
    ".renovaterc.json": (Signature(DEPENDENCY_AUTOMATION, "Renovate"),),
}  # fmt: skip

# File name suffixes, compared case-insensitively. Longest suffix wins.
SUFFIX_SIGNATURES: tuple[tuple[str, Signature], ...] = (
    (".tf.json", Signature(IAC, "Terraform")),
    (".tf", Signature(IAC, "Terraform")),
    (".tfvars", Signature(IAC, "Terraform")),
    (".tofu", Signature(IAC, "Terraform")),
    (".pkr.hcl", Signature(IAC, "Packer")),
    (".nomad.hcl", Signature(IAC, "Nomad")),
    (".nomad", Signature(IAC, "Nomad")),
    (".bicep", Signature(IAC, "Bicep", implies=_AZURE)),
    (".csproj", package_manager("NuGet", "NuGet", "manifest")),
    (".fsproj", package_manager("NuGet", "NuGet", "manifest")),
    (".vbproj", package_manager("NuGet", "NuGet", "manifest")),
    (".gemspec", package_manager("Bundler", "RubyGems", "manifest")),
    (".cabal", package_manager("Cabal", "Hackage", "manifest")),
    (".dockerfile", Signature(CONTAINER, "Dockerfile")),
    (".containerfile", Signature(CONTAINER, "Dockerfile")),
    (".jenkinsfile", Signature(CI_CD, "Jenkins")),
)

# Regular expressions over the POSIX path relative to the asset root.
PATH_SIGNATURES: tuple[tuple[re.Pattern[str], Signature], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), signature)
    for pattern, signature in (
        (r"(^|/)(dockerfile|containerfile)(\.[\w.-]+)?$", Signature(CONTAINER, "Dockerfile")),
        (
            r"(^|/)(docker-)?compose([.-][\w.-]+)?\.ya?ml$",
            Signature(CONTAINER, "Docker Compose"),
        ),
        (
            r"(^|/)requirements([-_.][\w.-]*)?\.(txt|in)$",
            package_manager("pip", "PyPI", "manifest"),
        ),
        (r"(^|/)requirements/[\w.-]+\.(txt|in)$", package_manager("pip", "PyPI", "manifest")),
        (r"(^|/)constraints([-_.][\w.-]*)?\.txt$", package_manager("pip", "PyPI", "manifest")),
        (r"(^|/)pulumi\.[\w-]+\.ya?ml$", Signature(IAC, "Pulumi")),
        (r"(^|/)jenkinsfile([.-][\w.-]+)?$", Signature(CI_CD, "Jenkins")),
        (r"^\.github/workflows/[^/]+\.ya?ml$", Signature(CI_CD, "GitHub Actions")),
        (r"^\.github/actions/.+/action\.ya?ml$", Signature(CI_CD, "GitHub Actions")),
        (r"^\.github/dependabot\.ya?ml$", Signature(DEPENDENCY_AUTOMATION, "Dependabot")),
        (r"^\.github/renovate\.json5?$", Signature(DEPENDENCY_AUTOMATION, "Renovate")),
        (r"^\.gitlab/renovate\.json5?$", Signature(DEPENDENCY_AUTOMATION, "Renovate")),
        (r"^\.gitlab/ci/.+\.ya?ml$", Signature(CI_CD, "GitLab CI")),
        (r"^\.gitea/workflows/[^/]+\.ya?ml$", Signature(CI_CD, "Gitea Actions")),
        (r"^\.forgejo/workflows/[^/]+\.ya?ml$", Signature(CI_CD, "Forgejo Actions")),
        (r"^\.circleci/config\.ya?ml$", Signature(CI_CD, "CircleCI")),
        (r"(^|/)azure-pipelines([.-][\w.-]+)?\.ya?ml$", Signature(CI_CD, "Azure Pipelines")),
        (r"^\.azure-pipelines/.+\.ya?ml$", Signature(CI_CD, "Azure Pipelines")),
        (r"^\.azuredevops/.+\.ya?ml$", Signature(CI_CD, "Azure Pipelines")),
        (r"^\.buildkite/.+\.(ya?ml|json)$", Signature(CI_CD, "Buildkite")),
        (r"^\.woodpecker/.+\.ya?ml$", Signature(CI_CD, "Woodpecker")),
        (r"^\.semaphore/.+\.ya?ml$", Signature(CI_CD, "Semaphore")),
        (r"^\.teamcity/.+\.(kts|xml)$", Signature(CI_CD, "TeamCity")),
        (r"^\.harness/.+\.ya?ml$", Signature(CI_CD, "Harness")),
        (r"^\.tekton/.+\.ya?ml$", Signature(CI_CD, "Tekton")),
        (
            r"(^|/)roles/[^/]+/(tasks|handlers|defaults|vars|meta)/main\.ya?ml$",
            Signature(IAC, "Ansible"),
        ),
        (r"(^|/)\.ebextensions/.+\.config$", Signature(CLOUD, "AWS")),
    )
)

# Terraform provider and resource prefixes mapped to the platform they manage.
TERRAFORM_PROVIDERS = {
    "aws": "AWS", "awscc": "AWS",
    "azurerm": "Azure", "azuread": "Azure", "azapi": "Azure",
    "google": "Google Cloud", "google-beta": "Google Cloud",
    "digitalocean": "DigitalOcean",
    "oci": "Oracle Cloud",
    "alicloud": "Alibaba Cloud",
    "hcloud": "Hetzner Cloud",
    "linode": "Linode",
    "scaleway": "Scaleway",
    "openstack": "OpenStack",
    "vsphere": "VMware vSphere",
    "cloudflare": "Cloudflare",
    "ibm": "IBM Cloud",
}  # fmt: skip

# Kubernetes API groups. A manifest in one of these is reported with high confidence.
KUBERNETES_API_GROUPS = frozenset(
    {
        "apps", "batch", "autoscaling", "policy", "extensions",
        "networking.k8s.io", "rbac.authorization.k8s.io", "storage.k8s.io",
        "apiextensions.k8s.io", "admissionregistration.k8s.io", "certificates.k8s.io",
        "coordination.k8s.io", "scheduling.k8s.io", "node.k8s.io", "discovery.k8s.io",
        "gateway.networking.k8s.io", "apiregistration.k8s.io", "flowcontrol.apiserver.k8s.io",
        "cert-manager.io", "monitoring.coreos.com", "networking.istio.io",
        "security.istio.io", "keda.sh", "external-secrets.io", "route.openshift.io",
        "apps.openshift.io", "kyverno.io", "traefik.io", "traefik.containo.us",
    }
)  # fmt: skip
KUBERNETES_CORE_KINDS = frozenset(
    {
        "Pod", "Service", "ConfigMap", "Secret", "Namespace", "ServiceAccount",
        "PersistentVolume", "PersistentVolumeClaim", "Endpoints", "LimitRange",
        "ResourceQuota", "ReplicationController", "List", "Node",
    }
)  # fmt: skip
# apiVersion/kind documents that are not Kubernetes workloads.
NON_KUBERNETES_API_GROUPS = frozenset(
    {
        "backstage.io",
        "kind.x-k8s.io",
        "kubeadm.k8s.io",
        "kubelet.config.k8s.io",
        "chainsaw.kyverno.io",
    }
)
ARGO_KINDS = {
    "Workflow": "Argo Workflows",
    "CronWorkflow": "Argo Workflows",
    "WorkflowTemplate": "Argo Workflows",
    "ClusterWorkflowTemplate": "Argo Workflows",
    "Application": "Argo CD",
    "ApplicationSet": "Argo CD",
    "AppProject": "Argo CD",
    "Rollout": "Argo Rollouts",
}
