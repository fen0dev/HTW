# HTW - Hack The Web

Security scanning agents that an engineering team runs on its **own** systems. HTW
detects what a codebase is made of, runs the established open-source scanners that
apply to it, and on every recurring scan reports only what changed: what is new, what
came back, what was resolved. It can also propose fixes for a person to review. It
never applies them.

> **Authorized use only.** Only scan systems you own or are explicitly authorized to
> test. HTW refuses to scan anything that is not declared, with a named authorizer and
> an expiry date, in its scope file. That check protects you from mistakes; it does
> not make an unauthorized scan legitimate. Scanning systems without permission may be
> illegal where you are.

**Status: phase 1 (alpha).** This release covers static analysis of source
repositories and directories: dependencies and SBOM, secrets, static code
analysis, container files, infrastructure as code, and CI/CD workflow files.
Runtime tests stay off unless a person has approved one staging URL. It is
report-only by default. See [Limitations](#limitations) for what it
does not do yet.

## What phase 1 does

- **Scope and authorization first.** A scope file is the allowlist. Every asset needs
  an owner and an authorization record that expires. For git checkouts, HTW verifies
  before every scan that the checkout points to the remote you declared.
- **Automatic stack detection.** Languages, package managers, containers,
  infrastructure as code, cloud providers and CI/CD systems are detected from the
  files, and the detected stack decides which scanners run.
- **Scanner agents**, each a thin wrapper around tools you may already use. Nothing
  here builds an image, applies infrastructure, or contacts a cloud account:

  | Agent | What it finds | Tools, in order of preference |
  |---|---|---|
  | Dependencies and SBOM | Known vulnerabilities in dependencies; a CycloneDX SBOM | Syft, then Grype, OSV-Scanner or Trivy |
  | Secrets | Credentials in files and in git history | Gitleaks or TruffleHog |
  | Static analysis (SAST) | Unsafe code patterns | Semgrep; Bandit (Python) and gosec (Go) as fallbacks |
  | Containers | Dockerfile and Compose misconfiguration, from the files only | Hadolint, then Trivy config or Checkov. Dockle is opt-in and only reads a local `.tar` |
  | Infrastructure as code | Terraform, CloudFormation, Kubernetes, Ansible and the other formats the detector already names | Checkov, then Trivy config, KICS or kube-linter |
  | CI/CD | Workflow misconfiguration for the CI systems the detector recognizes | zizmor (GitHub Actions, offline) or Checkov. OpenSSF Scorecard and cosign are opt-in |
  | Runtime (DAST) | Passive checks against one approved staging URL | ZAP baseline. Nuclei is opt-in. Refused unless a current L2 approval names that exact URL |

- **Only what changed.** Findings get a stable fingerprint that survives code moving
  around, so a nightly scan tells you what is new, reappeared or resolved instead of
  repeating the whole list.
- **Normalized output.** One Markdown report and one SARIF 2.1.0 file per run,
  whatever mix of scanners produced the findings.
- **Fix proposals for human review** (off by default): the target version for a
  vulnerable dependency, a patch when the scanner supplies a small safe edit, and,
  only when you turn it on, a draft pull request. Never applied, never merged.
- **Guardrails throughout**: kill switch, scan windows and rate limits, secrets
  redacted at the source, scanners run with a scrubbed environment and timeouts, a
  tamper-evident audit log, suppressions that must be justified and expire.

**What "agents" means here.** The agents are deterministic: an orchestrator and one
scanner agent per kind of check, behind a common interface. Triage (deduplicate,
rank, drop obvious false positives) is on by default and does not call a model.
An optional model can mark a finding as a likely false positive, and it stays off
until the scope file names a provider and an environment variable that already
holds the key. HTW never stores that key and never sends a secret value or a
source snippet. Deep code review and generated fixes beyond a scanner-supplied
patch are not in this release.

## Install

HTW needs Python 3.11 or later, on Linux or macOS.

```bash
pipx install git+https://github.com/fen0dev/HTW.git
```

or, from a clone, with dependencies pinned by hash:

```bash
git clone https://github.com/fen0dev/HTW.git && cd HTW
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.txt
pip install --no-deps .
```

Check it:

```bash
htw --version
htw doctor      # shows which scanners are installed
```

### Install the scanners

HTW wraps external scanners and bundles none of them. Install the ones you want.
Where several tools can do the same job, HTW prefers Grype, then OSV-Scanner, then
Trivy; Gitleaks, then TruffleHog; Semgrep, then Bandit and gosec; Hadolint, then
Trivy config or Checkov; Checkov, then Trivy config, KICS or kube-linter; and
zizmor, then Checkov, for GitHub Actions. Opt-in tools (Dockle, Scorecard, cosign,
Nuclei) are listed by `htw doctor` and run only when `tools:` names them.

| Tool | Agent | Install | Tested with |
|---|---|---|---|
| [Syft](https://github.com/anchore/syft) | Dependencies and SBOM | `brew install syft`, or a [release binary](https://github.com/anchore/syft/releases) | 1.57.1 |
| [Grype](https://github.com/anchore/grype) | Dependencies and SBOM | `brew install grype`, or a [release binary](https://github.com/anchore/grype/releases) | 0.121.3 |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Dependencies and SBOM | `brew install osv-scanner`, or a [release binary](https://github.com/google/osv-scanner/releases) | 2.7.1 |
| [Trivy](https://github.com/aquasecurity/trivy) | Dependencies and SBOM | `brew install trivy`, or a [release binary](https://github.com/aquasecurity/trivy/releases) | 0.76.2 |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secrets | `brew install gitleaks`, or a [release binary](https://github.com/gitleaks/gitleaks/releases) | 8.30.1 |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Secrets | `brew install trufflehog`, or a [release binary](https://github.com/trufflesecurity/trufflehog/releases) | 3.99.8 |
| [Semgrep](https://github.com/semgrep/semgrep) | Static analysis | `pipx install semgrep` or `brew install semgrep` | 1.185.0 |
| [Bandit](https://github.com/PyCQA/bandit) | Static analysis (Python) | `pipx install bandit` | 1.9.4 |
| [gosec](https://github.com/securego/gosec) | Static analysis (Go) | `go install github.com/securego/gosec/v2/cmd/gosec@latest` (also needs the Go toolchain at scan time) | 2.30.0 |
| [Hadolint](https://github.com/hadolint/hadolint) | Containers | `brew install hadolint`, or a [release binary](https://github.com/hadolint/hadolint/releases) | — |
| [Trivy](https://github.com/aquasecurity/trivy) `config` | Containers, infrastructure | same binary as above; HTW passes `--skip-db-update` and never `trivy image` | 0.76.2 |
| [Checkov](https://github.com/bridgecrewio/checkov) | Containers, infrastructure, CI/CD | `pipx install checkov` | — |
| [KICS](https://github.com/Checkmarx/kics) | Infrastructure | `brew install kics`, or a [release binary](https://github.com/Checkmarx/kics/releases) | — |
| [kube-linter](https://github.com/stackrox/kube-linter) | Kubernetes manifests | `brew install kube-linter`, or a [release binary](https://github.com/stackrox/kube-linter/releases) | — |
| [zizmor](https://github.com/zizmorcore/zizmor) | GitHub Actions | `brew install zizmor`, or a [release binary](https://github.com/zizmorcore/zizmor/releases) | 1.32.0 |

A reasonable minimum is **Syft, Grype, Gitleaks and Semgrep**, plus **zizmor** when
the repository uses GitHub Actions. Install scanners from their official releases
and verify the published checksums: HTW runs whatever your `PATH` resolves.

**If a scanner is missing, HTW does not fail.** It prints a warning with the install
command, tries the next tool that can do the same job, runs everything else, and
lists in the report exactly what was not covered:

```
[my-service] complete: 2 new, 0 reappeared, 0 resolved, 0 still open
  ...
  warning: semgrep is not installed (no `semgrep` on PATH). Install: `pipx install semgrep` or `brew install semgrep`
  not covered: static analysis of JavaScript code
```

Use `htw scan --strict` if a coverage gap should fail the run instead.

## Quick start

```bash
cd /path/to/your/repository
htw init        # writes htw.yaml for this directory
```

`htw init` leaves the owner and the authorization record empty on purpose. Open
`htw.yaml` and fill them in: nothing can be scanned on the strength of a generated
file.

```yaml
    owner: payments-team
    authorization:
      authorized_by: Jane Doe (Head of Engineering)
      authorized_on: 2026-01-15
      expires_on: 2026-07-15
```

Add `.htw/` to your `.gitignore`, then:

```bash
htw validate    # is the scope file valid, and would each asset be scanned?
htw detect      # what stack was detected, and which scanners will run?
htw scan        # scan, and write the report
```

The report is at `.htw/reports/<asset>/<run>/report.md`. Run `htw scan` again and it
reports nothing new.

## The scope file

`htw.yaml` is the allowlist. A commented example with every option is in
[config/htw.example.yaml](config/htw.example.yaml). The essentials:

```yaml
version: 1

fixes:
  propose: false                  # report-only (the default)

assets:
  - id: payments-api
    type: repository              # a git checkout; or `directory`
    path: ../payments-api
    owner: payments-team
    criticality: critical         # low | medium | high | critical
    ownership:
      git_remote: github.com/acme/payments-api   # verified before every scan
    authorization:
      authorized_by: Jane Doe (Head of Engineering)
      authorized_on: 2026-01-15
      expires_on: 2026-07-15      # scans are refused after this date
    exclude:
      - vendor
```

- Anything not listed is out of scope. `htw scan` accepts asset ids from this file
  and nothing else; there is no way to point it at an arbitrary path or URL.
- The file is validated strictly: an unknown key is an error.
- Keep it in version control and review every change to it. A change to this file is
  a change to what may be scanned.

## Commands

| Command | What it does |
|---|---|
| `htw init` | Write a starter scope file for the current directory. |
| `htw validate` | Check the scope file and say whether each asset would be scanned or refused, and why. |
| `htw doctor` | List the scanners, whether each is installed, and what each sends over the network. |
| `htw detect [--asset ID] [--json]` | Show the detected stack and the scan plan. Runs no scanner, writes nothing. |
| `htw scan [--asset ID] [--fail-on SEVERITY] [--strict]` | Scan and report. |
| `htw audit-verify` | Verify the hash chain of the audit log. |

All commands take `-c PATH` to use a scope file other than `./htw.yaml`.

Exit codes of `htw scan`:

| Code | Meaning |
|---|---|
| 0 | Completed. Nothing at or above `--fail-on` (if given) is new or reappeared. |
| 1 | A new or reappeared finding is at or above `--fail-on`. |
| 2 | Refused: invalid scope file, undeclared asset, expired authorization, failed ownership check, outside a scan window, or the kill switch is engaged. |
| 3 | Incomplete: a scanner failed. With `--strict`, also when part of the stack was not covered. |

`--fail-on` only looks at what is new or reappeared, so an existing backlog does not
keep a pipeline red; it shows in the report as "still open".

## What a scan writes

Under `.htw/` (configurable with `state_dir`):

```
.htw/
  state.db                         findings and their history
  audit.jsonl                      who ran what, when, on which asset
  reports/<asset>/<run>/
    report.md                      what changed, what is open, what was not covered
    findings.sarif                 SARIF 2.1.0, all findings on record
    summary.json                   machine-readable summary
    sbom.cdx.json                  CycloneDX SBOM (when Syft is installed)
    proposals/                     fix proposals (when enabled)
```

**Treat this directory as confidential.** Reports describe weaknesses that may not be
fixed yet. Do not commit it, and do not paste reports into public issues, pull
requests or chats.

In the SARIF file, each finding's stable id is in `partialFingerprints["htw/v1"]` and
its status relative to the previous scan is in `baselineState`.

## Recurring scans

The findings state in `.htw/state.db` is what makes repeated scans quiet, so it has
to persist between runs.

On a machine you control, a cron entry is enough:

```cron
17 3 * * *  cd /srv/scans/payments-api && git pull -q && htw scan --fail-on high
```

For GitHub Actions, see [docs/examples/scheduled-scan.yml](docs/examples/scheduled-scan.yml),
and read the note at the top of it about public repositories.

Use `limits.windows` and `limits.min_interval_minutes` in the scope file to bound
when and how often an asset may be scanned.

## Working with findings

Each finding has an id such as `htw1:5f0c…`, shown in the report. It stays the same
when code moves or is reformatted, and for a dependency it stays the same until the
advisory no longer applies.

If a finding is wrong or is a risk you accept, suppress it in `suppressions.yaml`
next to the scope file ([example](config/suppressions.example.yaml)):

```yaml
suppressions:
  - fingerprint: "htw1:0123456789abcdef0123456789abcdef"
    kind: false_positive          # or accepted_risk
    reason: Sample value in a documentation snippet, not a real credential.
    author: jane.doe@example.com
    expires: 2026-12-31
```

A reason, an author and an expiry date are required. There are no permanent
suppressions: when one expires the finding is reported again. Keep the file in
version control so that suppressions are reviewed like code.

If a scan finds a real credential: revoke and rotate it first. Removing it from the
latest commit is not enough, because it stays in the git history.

## Fix proposals

With `fixes.propose: true`, each run also writes proposals to
`reports/<asset>/<run>/proposals/`: one Markdown file per proposal and a `.patch`
file where a patch could be derived.

Proposals cover two cases:

- **Vulnerable dependencies.** HTW works out the lowest version that fixes every
  advisory against a package. It writes a patch only when the edit is unambiguous
  (an exact `==` pin without hashes in a requirements file); otherwise it states the
  target version and leaves the upgrade to your package manager so that lockfiles
  stay consistent. If Dependabot or Renovate is configured, the proposal says so
  and defers to it.
- **A scanner-supplied fix.** When Semgrep returns a small replacement for the
  flagged lines, and that text still matches the file in exactly one place, HTW
  writes a unified diff. The tree being scanned is not modified. A replacement that
  looks like a credential is dropped.

HTW does not apply a proposal. With `fixes.pull_requests: true` it can open the
proposal as a **draft** pull request on GitHub, using the `git` and `gh` binaries
and the login `gh` already has. HTW does not create a token. The branch is pushed
from a temporary clone, never from the checkout that was scanned. If the pull
request is not a draft, HTW closes it and records the failure. Nothing is merged.

A patch that describes an unfixed weakness (every scanner-supplied code fix) is
refused unless `fixes.private_destination: true`. A dependency bump for a published
advisory may go to a public repository. The rules live in
[`PullRequestPublisher`](src/htw/integrations/pull_requests.py).

## Guardrails

The full list, with where each is implemented and its current limits, is in
[docs/guardrails.md](docs/guardrails.md). In short:

- **Deny by default.** Only assets in the scope file, only while authorized.
- **Ownership check** against the declared git remote before every scan.
- **Static analysis (L0) unless a person approves more.** Container, infrastructure
  and CI checks read files only. Runtime tests (L2) run only against one staging
  URL named in a current approval, and they refuse without it. Read-only checks of
  live cloud accounts (L1) are not in this release. Intrusive testing (L3) can
  never be configured.
- **Report-only by default; fixes are never auto-applied.**
- **Secrets are redacted at the source.** Reports, SARIF, the state database and the
  audit log hold the location and kind of a secret, never its value.
- **Scanners are contained**: no shell, a scrubbed environment (your tokens do not
  reach them), timeouts and output limits. When `bwrap` works, each scanner also
  runs in a process sandbox: the asset is read-only, the home directory is not
  mounted, and tools that do not use the network lose it. `git` and `gh` are not
  wrapped, so a draft pull request can still use the login you already have.
- **Kill switch**: `touch .htw/STOP` or `HTW_KILL_SWITCH=1` stops everything.
- **Audit log** with a hash chain; `htw audit-verify` detects edits.
- **Scanned content is treated as hostile**: no symlinks followed, nothing read
  outside the asset, scanner text escaped in reports.

Two limits to know about now: the process sandbox is bubblewrap, not a
digest-pinned container, and it is skipped (with a note in the report) where
`bwrap` cannot start. HTW does not verify the scanner binaries. Run HTW as an
unprivileged user on a machine that holds no credentials it does not need.

## What leaves your machine

HTW itself makes no network connections. Some of the scanners it runs do, to fetch
rules or vulnerability data. `htw doctor` prints this for the scanners you have.

| Tool | Network use |
|---|---|
| Syft, Gitleaks, Bandit | None. |
| TruffleHog | None. HTW always disables verification of found credentials, which would contact the service a credential belongs to. |
| Grype, Trivy | Download their vulnerability database. Package data stays local. |
| OSV-Scanner | Sends package names and versions to osv.dev (and deps.dev, to resolve transitive dependencies). No source code. |
| Semgrep | Downloads rulesets from semgrep.dev unless `semgrep_rules` points to local rule files. HTW disables its metrics and version check. No code is uploaded. |
| gosec | The Go toolchain may download modules the scanned code depends on. |
| Hadolint, KICS, kube-linter, zizmor, cosign, Dockle | None. zizmor is passed `--offline`. Dockle is only given a local image archive. cosign verifies a blob with a key file inside the asset. |
| Checkov | None with the flags HTW passes: external modules are not downloaded and results are not uploaded. |
| Trivy `config` | `--skip-db-update`. A missing local vulnerability cache may still be fetched once; the files stay local. |
| OpenSSF Scorecard | Opt-in. Local mode can still contact GitHub. HTW adds no token. |
| ZAP, Nuclei | Only the staging URL in the current approval. Refused otherwise. No other host is passed on the command line, and a Nuclei match for any other origin is dropped. |

To keep everything on the machine, set `tools:` explicitly in the scope file (for
example Syft, Gitleaks and Bandit) and point `semgrep_rules` at local rules.

## Limitations

What this release does not do. Each item is planned unless noted.

- **Assets:** repositories and directories only. Container images, cloud accounts,
  clusters and running applications are rejected by the scope file with a message
  saying so.
- **No live cloud, cluster or image-registry scanning.** Container and
  infrastructure checks read the files in the checkout. Dockle refuses to pull an
  image. Prowler, kube-bench and similar read-only checks of running systems are
  not in this release.
- **Runtime tests need a decision you record yourself.** DAST runs only with
  `max_level: L2`, `runtime.staging_url`, and an `approvals` entry for control
  `dast` whose target is that exact URL and whose dates include today. Loopback,
  link-local and cloud metadata addresses are rejected. Without that record the
  agent does not run and does not open a network connection.
- **Triage is deterministic.** It drops SAST, container, infrastructure and
  pipeline findings under vendored and virtualenv trees, drops secret findings in
  documentation only when the context looks like a placeholder, and collapses two
  tools' reports of the same CWE at the same line or the same advisory on the same
  package. A model is optional (`triage.llm`) and off by default; with no provider
  configured, HTW makes no network call. The model may only mark a false positive
  or lower confidence. It does not receive secret context or a proposed patch.
- **CI systems with no wrapped scanner stay unscanned.** Jenkins, Tekton, Travis,
  Drone, CodeBuild and the other systems the detector names but Checkov and zizmor
  do not read are reported as `no wrapped scanner`. Installing another copy of
  Checkov does not close that gap, and HTW does not add a scanner for them.
- **The process sandbox is not a network allowlist.** Bubblewrap, when it starts,
  hides the home directory and keeps the asset read-only. It does not pin scanner
  images by digest and does not restrict egress to a list of addresses. Where
  `bwrap` is missing, scanners run as this user and the report says so. See
  [docs/guardrails.md](docs/guardrails.md#current-limits).
- **Reports go to files.** No issue tracker or chat integration. Draft pull
  requests are GitHub only, and only when `fixes.pull_requests` is true.
- **Priority is simple:** scanner severity adjusted by asset criticality, then
  lowered one step when triage marks confidence as low (secret findings keep
  their priority). No exploitability (EPSS, CISA KEV) or reachability data.
- **Deduplication is conservative.** Two different advisories on one package stay
  separate. Two findings from the same tool stay separate. Code findings collapse
  across tools only when they share a CWE, a path and a line.
- **Secrets, history mode:** for a git checkout the secrets scanner reads committed
  content, so files that are not committed yet are not scanned. Set `history: false`
  to scan the files in the working tree instead.
- **Whole-tree scans only.** There is no mode that scans just the diff of a pull
  request.
- **Platforms:** Linux and macOS. Windows is untested.

## Development

```bash
pip install --require-hashes -r requirements-dev.txt
pip install --no-deps --no-build-isolation -e .
ruff check . && ruff format --check . && mypy && pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [docs/architecture.md](docs/architecture.md)
and the decision records in [docs/adr/](docs/adr/). The implementation language is
Python; the reasoning is in
[ADR 0001](docs/adr/0001-implementation-language.md).

`tests/fixtures/` holds intentionally vulnerable test data with synthetic
credentials. It is excluded from HTW's scan of itself.

## Security

To report a vulnerability in HTW, see [SECURITY.md](SECURITY.md). Please do not open
a public issue.

## License

[Apache-2.0](LICENSE).
