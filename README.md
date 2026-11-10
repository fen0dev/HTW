# HTW

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
repositories and directories: dependencies and SBOM, secrets, and static code
analysis. It is report-only by default. See [Limitations](#limitations) for what it
does not do yet.

## What phase 1 does

- **Scope and authorization first.** A scope file is the allowlist. Every asset needs
  an owner and an authorization record that expires. For git checkouts, HTW verifies
  before every scan that the checkout points to the remote you declared.
- **Automatic stack detection.** Languages, package managers, containers,
  infrastructure as code, cloud providers and CI/CD systems are detected from the
  files, and the detected stack decides which scanners run.
- **Three scanner agents**, each a thin wrapper around tools you may already use:

  | Agent | What it finds | Tools, in order of preference |
  |---|---|---|
  | Dependencies and SBOM | Known vulnerabilities in dependencies; a CycloneDX SBOM | Syft, then Grype, OSV-Scanner or Trivy |
  | Secrets | Credentials in files and in git history | Gitleaks or TruffleHog |
  | Static analysis (SAST) | Unsafe code patterns | Semgrep; Bandit (Python) and gosec (Go) as fallbacks |

- **Only what changed.** Findings get a stable fingerprint that survives code moving
  around, so a nightly scan tells you what is new, reappeared or resolved instead of
  repeating the whole list.
- **Normalized output.** One Markdown report and one SARIF 2.1.0 file per run,
  whatever mix of scanners produced the findings.
- **Fix proposals for human review** (off by default): the target version for a
  vulnerable dependency and, where the edit is unambiguous, a patch file. Never
  applied, never merged.
- **Guardrails throughout**: kill switch, scan windows and rate limits, secrets
  redacted at the source, scanners run with a scrubbed environment and timeouts, a
  tamper-evident audit log, suppressions that must be justified and expire.

**What "agents" means here.** In this phase the agents are deterministic: an
orchestrator and three scanner agents with a common interface. Phase 1 makes no calls
to any language model and sends your code to no AI service. The agents that reason
with a model (triage of findings, deeper code review, fix generation) are planned for
later phases and plug into the same pipeline.

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
Trivy; Gitleaks, then TruffleHog; and Semgrep, then Bandit and gosec.

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

A reasonable minimum is **Syft, Grype, Gitleaks and Semgrep**. Install scanners from
their official releases and verify the published checksums: HTW runs whatever your
`PATH` resolves.

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

In this release proposals cover vulnerable dependencies. HTW works out the lowest
version that fixes every advisory against a package. It writes a patch only when the
edit is unambiguous (an exact `==` pin without hashes in a requirements file);
otherwise it states the target version and leaves the upgrade to your package manager
so that lockfiles stay consistent. If Dependabot or Renovate is configured, the
proposal says so and defers to it.

HTW does not apply a proposal, does not push a branch and does not open a pull
request. A person reviews the proposal and applies it. The interface for opening
proposals as draft pull requests exists
([`PullRequestPublisher`](src/htw/integrations/pull_requests.py)) and enforces the
rules in one place: enabled explicitly, asset in scope, draft only, never merge, and
nothing that would disclose an unfixed weakness to a public destination. No
implementation for a specific forge ships yet.

## Guardrails

The full list, with where each is implemented and its current limits, is in
[docs/guardrails.md](docs/guardrails.md). In short:

- **Deny by default.** Only assets in the scope file, only while authorized.
- **Ownership check** against the declared git remote before every scan.
- **Static analysis only (L0).** Nothing is executed on, or sent to, the systems you
  scan. Higher levels are refused; intrusive testing (L3) can never be configured.
- **Report-only by default; fixes are never auto-applied.**
- **Secrets are redacted at the source.** Reports, SARIF, the state database and the
  audit log hold the location and kind of a secret, never its value.
- **Scanners are contained**: no shell, a scrubbed environment (your tokens do not
  reach them), timeouts and output limits.
- **Kill switch**: `touch .htw/STOP` or `HTW_KILL_SWITCH=1` stops everything.
- **Audit log** with a hash chain; `htw audit-verify` detects edits.
- **Scanned content is treated as hostile**: no symlinks followed, nothing read
  outside the asset, scanner text escaped in reports.

Two limits to know about now: scanners run as ordinary local processes, without a
filesystem or network sandbox, and HTW does not verify the scanner binaries. Run HTW
as an unprivileged user on a machine that holds no credentials it does not need.

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

To keep everything on the machine, set `tools:` explicitly in the scope file (for
example Syft, Gitleaks and Bandit) and point `semgrep_rules` at local rules.

## Limitations

What this release does not do. Each item is planned unless noted.

- **Assets:** repositories and directories only. Container images, cloud accounts,
  clusters and running applications are rejected by the scope file with a message
  saying so.
- **Scanners:** when containers, infrastructure as code or CI/CD pipelines are
  detected, the report says they were not scanned. There are no agents for them yet.
- **No LLM-based agents:** no automated triage, deep code review or generated code
  fixes. Expect false positives from the scanners; the first scans of a codebase need
  a pass of manual suppressions.
- **No sandbox** around scanners, and no network egress control. See
  [docs/guardrails.md](docs/guardrails.md#current-limits).
- **No approval flow**, so nothing above L0 can run.
- **Reports go to files.** No issue tracker or chat integration, and no pull request
  publisher for a specific forge.
- **Priority is simple:** scanner severity adjusted by asset criticality. No
  exploitability (EPSS, CISA KEV) or reachability data.
- **No cross-tool deduplication for code findings.** If you run two SAST tools they
  may report the same problem twice. Dependency findings are stable across tools only
  when the tools use the same advisory id.
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
