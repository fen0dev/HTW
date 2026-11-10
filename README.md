# HTW

HTW scans source repositories and directories that you own, or that someone has
authorized you to test. It looks at the files, picks the open-source scanners that
fit that stack, and writes a local report of what changed since the last run. It
can also leave fix proposals for a person to review. It does not apply them, and it
does not open a ticket, a chat message, or a dashboard. Follow one invented team's
scan, from install through the digest, in [docs/example-recon.md](docs/example-recon.md).

> **Authorized use only.** Only scan systems you own or are explicitly authorized to
> test. HTW refuses anything that is not declared, with a named authorizer and an
> expiry date, in `htw.yaml`. That check stops accidents. It does not make an
> unauthorized scan legitimate.

This is an alpha. It runs on Linux and macOS with Python 3.11 or later. Windows is
untested.

## What a scan does

You list the assets in `htw.yaml`. That file is the allowlist: a path that is not
listed is out of scope, and `htw scan` will not accept an arbitrary path or URL on
the command line. Each asset needs an owner and an authorization record with a
start date and an expiry date. For a git checkout (`type: repository`), HTW also
checks, before every scan, that the checkout's remote matches `ownership.git_remote`.
A plain directory has no remote to check, so the authorization record is the only
basis for scanning it.

HTW then detects the stack from the files: languages, package managers, Dockerfiles,
infrastructure-as-code, and CI configuration. The detected stack decides which
agents run. Each agent is a wrapper around tools you install yourself. HTW bundles
none of them. When several tools can do one job, it tries them in order and uses
the first that is installed and still adds coverage.

Dependencies and SBOMs use Syft, then Grype, OSV-Scanner, or Trivy. Secrets use
Gitleaks, then TruffleHog. Static analysis uses Semgrep, then Bandit for Python and
gosec for Go. Container files use Hadolint, then Trivy `config` or Checkov. Those
tools read the Dockerfile and Compose file in the checkout. They do not pull or run
an image. Dockle runs only when `scanners.container.tools` lists `dockle`. An
explicit `tools` list replaces the automatic choice for that agent, and Dockle is
only given a local `.tar`. Infrastructure as code uses Checkov, then Trivy `config`,
KICS, or kube-linter, again on the files only. Nothing in this release logs into a
cloud account or a cluster.

CI coverage is narrower than detection. zizmor reads GitHub Actions workflows and
is always passed `--offline`. Checkov reads GitHub Actions, GitLab CI, Azure
Pipelines, Bitbucket Pipelines, and CircleCI. Other systems the detector
recognizes, including Jenkins, Tekton, Travis CI, Drone, Buildkite, AWS CodeBuild,
and Argo CD, are reported as a gap: `no wrapped scanner`. Installing another copy
of Checkov does not close that gap, and HTW does not add a scanner for them.
`--strict` makes any such gap fail the run.

A missing scanner does not fail a normal run. HTW prints the install command, tries
the next tool, finishes the rest of the scan, and lists what was not covered.

Every finding gets a stable id (`htw1:…`) that survives reformatting and, for a
dependency, stays the same until the advisory no longer applies. The next scan
compares those ids with `.htw/state.db` and reports what is new, what came back,
and what was resolved. The same findings are written as SARIF 2.1.0. The id is in
`partialFingerprints["htw/v1"]` and the comparison with the previous scan is in
`baselineState`.

Priority starts from the scanner severity and the asset's `criticality`. When a
finding already carries a CVE id, and `exploitability.enabled` is true (the
default), the run downloads the public CISA Known Exploited Vulnerabilities catalog
and the public FIRST EPSS scores for those ids only. There is no API key. The
response is cached under the state directory for 24 hours. A CVE in the KEV catalog
raises priority one step. An EPSS score of at least 0.10 raises it one more step.
The two steps stop at P0. If a feed cannot be fetched and the cache is missing or
older than 24 hours, priority is left where severity and criticality put it. A low
score does not lower it. Reachability is not scored.

Local triage then runs. It drops static findings under vendored and virtualenv
trees, drops a secret finding in documentation when the context looks like a
placeholder, and collapses two tools' reports of the same CWE at the same line, or
the same advisory on the same package. It does not call a model unless you turn
that on, as described below.

When `bwrap` is available and `runner.sandbox` is `auto` (the default), each
scanner process is wrapped with bubblewrap. The asset is mounted read-only, the
home directory is not mounted, and a tool that declares no network use loses the
network. `git` and `gh` are not wrapped, so a draft pull request can still use a
login you already have. If bubblewrap is missing or cannot start, the scan
continues and the report says the scanners ran as the current user. This is not a
digest-pinned container and not an address allowlist. Set `runner.sandbox: "off"`
to skip the wrap. Quote `off`: a bare `off` is a boolean in YAML 1.1, and both
spellings are accepted.

## Install

```bash
pipx install git+https://github.com/fen0dev/HTW.git
```

Or, from a clone, with the runtime dependency pinned by hash:

```bash
git clone https://github.com/fen0dev/HTW.git && cd HTW
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements.txt
pip install --no-deps .
```

Check the install:

```bash
htw --version
htw doctor
```

`htw doctor` lists every wrapped scanner, whether it is on `PATH`, and what it
sends over the network. It also prints whether bubblewrap will wrap scanner
processes on this machine.

Install the scanners you want from their own releases and check the published
checksums. HTW runs whatever `PATH` resolves and does not verify those binaries.
A practical minimum is Syft, Grype, Gitleaks, and Semgrep, plus zizmor when the
repository uses GitHub Actions.

| Tool | Install | Tested with |
|---|---|---|
| [Syft](https://github.com/anchore/syft) | `brew install syft`, or a [release binary](https://github.com/anchore/syft/releases) | 1.57.1 |
| [Grype](https://github.com/anchore/grype) | `brew install grype`, or a [release binary](https://github.com/anchore/grype/releases) | 0.121.3 |
| [OSV-Scanner](https://github.com/google/osv-scanner) | `brew install osv-scanner`, or a [release binary](https://github.com/google/osv-scanner/releases) | 2.7.1 |
| [Trivy](https://github.com/aquasecurity/trivy) | `brew install trivy`, or a [release binary](https://github.com/aquasecurity/trivy/releases) | 0.76.2 |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | `brew install gitleaks`, or a [release binary](https://github.com/gitleaks/gitleaks/releases) | 8.30.1 |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | `brew install trufflehog`, or a [release binary](https://github.com/trufflesecurity/trufflehog/releases) | 3.99.8 |
| [Semgrep](https://github.com/semgrep/semgrep) | `pipx install semgrep` or `brew install semgrep` | 1.185.0 |
| [Bandit](https://github.com/PyCQA/bandit) | `pipx install bandit` | 1.9.4 |
| [gosec](https://github.com/securego/gosec) | `go install github.com/securego/gosec/v2/cmd/gosec@latest` (the Go toolchain is also needed at scan time) | 2.30.0 |
| [Hadolint](https://github.com/hadolint/hadolint) | `brew install hadolint`, or a [release binary](https://github.com/hadolint/hadolint/releases) | — |
| [Checkov](https://github.com/bridgecrewio/checkov) | `pipx install checkov` | — |
| [KICS](https://github.com/Checkmarx/kics) | `brew install kics`, or a [release binary](https://github.com/Checkmarx/kics/releases) | — |
| [kube-linter](https://github.com/stackrox/kube-linter) | `brew install kube-linter`, or a [release binary](https://github.com/stackrox/kube-linter/releases) | — |
| [zizmor](https://github.com/zizmorcore/zizmor) | `brew install zizmor`, or a [release binary](https://github.com/zizmorcore/zizmor/releases) | 1.32.0 |

Trivy is one binary. The dependency agent may run `trivy fs`. The container and
infrastructure agents run `trivy config` with `--skip-db-update`, never
`trivy image`.

## Configure `htw.yaml` and run a scan

From the repository you want to scan:

```bash
cd /path/to/your/repository
htw init
```

`htw init` writes `htw.yaml` for the current directory and leaves `owner` and the
authorization dates empty. A generated file cannot be scanned until a person fills
those in. Open it and set them:

```yaml
    owner: payments-team
    authorization:
      authorized_by: Jane Doe (Head of Engineering)
      authorized_on: 2026-01-15
      expires_on: 2026-07-15
```

If the directory is a git checkout, `htw init` also sets `type: repository` and
`ownership.git_remote` from the remote it found. Check that remote. It must be
`host/owner/repo`, for example `github.com/acme/payments-api`. Add `.htw/` to
`.gitignore`. Reports describe weaknesses that may not be fixed yet, so that
directory stays out of version control.

Then:

```bash
htw validate
htw detect
htw scan
```

`htw validate` checks the file and says whether each asset would be scanned or
refused. `htw detect` prints the stack and the scan plan without running a scanner
and without writing a report. `htw scan` runs the plan. The full report is
`.htw/reports/<asset>/<run>/report.md`. Run `htw scan` again and it reports nothing
new, as long as `.htw/state.db` is still there.

Read the short digest of that finished scan:

```bash
htw digest
```

This does not scan again. It reads the latest `summary.json` and `findings.sarif`
already written for each declared asset and writes `.htw/digest.md`. Open that file
in an editor. It counts what changed, what is still open by priority and by asset,
and what was not covered. The last line of the command output is the path. HTW
does not upload the digest and does not start a server. The digest does not compute
time to resolution or a false-positive rate, because the reports do not contain
them.

A scope file you write by hand has the same shape. `version: 1` is required.
`state_dir` defaults to `.htw` when you omit it. Unknown keys are rejected.

```yaml
version: 1

state_dir: .htw

fixes:
  propose: false

assets:
  - id: payments-api
    type: repository
    path: .
    owner: payments-team
    environment: development
    criticality: medium       # low | medium | high | critical
    max_level: L0             # static files only; see DAST below
    ownership:
      git_remote: github.com/acme/payments-api
    authorization:
      authorized_by: Jane Doe (Head of Engineering)
      authorized_on: 2026-01-15
      expires_on: 2026-07-15
    exclude:
      - vendor
```

Every option is commented in [config/htw.example.yaml](config/htw.example.yaml).
`limits.windows` and `limits.min_interval_minutes` restrict when and how often an
asset may be scanned. `scanners.secrets.history` defaults to true, so a git
checkout's secrets scan reads committed history and skips uncommitted files; set
it to false to scan the working tree instead. `scanners.sast.semgrep_rules`
defaults to `p/default`. Point it at local rule files if Semgrep should not
download rules.

To scan one asset from a file that lists several, pass `--asset` with the id from
the file. Repeat the flag for more than one. `-c PATH` selects a scope file other
than `./htw.yaml` for every command except `htw doctor`.

If a finding is wrong or is a risk you accept, suppress it in `suppressions.yaml`
next to the scope file. A reason, an author, and an expiry date are required.
There is no permanent suppression. The example is
[config/suppressions.example.yaml](config/suppressions.example.yaml). If a scan
finds a real credential, revoke and rotate it first. Deleting it from the latest
commit leaves it in git history.

`touch .htw/STOP` or `HTW_KILL_SWITCH=1` stops a run. `htw audit-verify` checks
the hash chain in `.htw/audit.jsonl`.

For a repeated scan on a machine you control, keep `.htw/state.db` between runs:

```cron
17 3 * * *  cd /srv/scans/payments-api && git pull -q && htw scan --fail-on high
```

[docs/examples/scheduled-scan.yml](docs/examples/scheduled-scan.yml) is a GitHub
Actions schedule. Read the note at the top before you use it. On a public
repository, workflow artifacts can be downloaded by anyone, so do not upload the
report that way.

## What stays off, and how to turn it on

Three things stay off until the scope file says otherwise. Turning them on does
not create a GitHub token, a cloud credential, or a scanner license. The only new
credential is the model provider key described below, and only if you enable the
model. EPSS and CISA KEV need no key. Draft pull requests use the `gh` login the
operator already has.

### A model for triage

With the default `triage.llm: false`, triage is the local rules above and HTW does
not call a model. To ask a model to review the findings after those rules:

```yaml
triage:
  enabled: true
  llm: true
  provider: openai          # openai or anthropic
  api_key_env: OPENAI_API_KEY
```

`api_key_env` is the name of an environment variable, not the key. HTW reads that
variable when the scan runs. It does not accept a key in the file, it does not
store one, and it does not call the provider when the variable is unset. In that
case the scan is marked incomplete and the report records the error. The model may
only mark a false positive or set confidence to low, which lowers priority one
step (a secret finding keeps its priority). The prompt carries the fingerprint,
rule, path, line, category, severity, and a short message. It does not carry
secret context or a proposed patch. `model` is optional. When you omit it, OpenAI
uses `gpt-4.1-mini` and Anthropic uses `claude-sonnet-4-5`.

### DAST against one staging URL

The default `max_level` is `L0`, so dynamic testing does not run and does not open
a connection. To run it, the asset needs all of the following. `max_level` must be
`L2`. `runtime.staging_url` must be an `http` or `https` URL for a staging host
the operator owns, with no user or password in the URL. An `approvals` entry for
control `dast` must be in force today, and its `target` must be exactly that same
URL. The config is rejected if the two strings differ.

```yaml
    max_level: L2
    runtime:
      staging_url: https://staging.example.com
    approvals:
      - control: dast
        level: L2
        authorized_by: Jane Doe (Head of Engineering)
        authorized_on: 2026-01-15
        expires_on: 2026-07-15
        target: https://staging.example.com
```

Loopback, link-local, unspecified, multicast, and reserved addresses are refused,
including `localhost` and cloud metadata names such as `metadata.google.internal`.
`L3` cannot be set. Live checks of a cloud account or a cluster are not a level
you can turn on. The tool that runs is ZAP's `zap-baseline.py`, and only against
that URL. Nuclei stays unselected unless `scanners.dast.tools` lists `nuclei`. A
Nuclei match for any other origin is dropped.

### Fix proposals and draft pull requests

`fixes.propose` defaults to false, so a scan writes findings and no patches. Set
it to true and each run also writes
`.htw/reports/<asset>/<run>/proposals/`: one Markdown file per proposal, and a
`.patch` when a patch is unambiguous. HTW does not edit the tree it scanned.

Two kinds of patch are produced. A dependency bump is written only for an exact
`==` pin, without hashes, in a requirements file, and only for the lowest version
that clears the advisories HTW saw. Anything else is a note of the target version,
left to your package manager. If Dependabot or Renovate is already configured, the
proposal says so and defers to it. A code edit is written only when Semgrep
supplies a small replacement, the original text occurs exactly once, and redaction
does not change the text. A replacement that looks like a credential is dropped.

`fixes.pull_requests: true` also needs `fixes.propose: true`. HTW then opens each
proposal that has a patch as a GitHub draft. It uses the `git` and `gh` binaries
on `PATH` and the login `gh` already has. It does not create a token. The patch is
committed in a temporary clone, not in the checkout that was scanned, and the
asset must have exactly one `github.com/owner/repo` remote. If the pull request is
not a draft, HTW closes it and records the failure. It never merges and it never
approves.

A dependency bump for a published advisory may be opened on a public repository.
A patch that describes an unfixed weakness, which is every scanner-supplied code
fix, is refused unless `fixes.private_destination: true`.

## What is not built

HTW does not file tickets and does not post to chat. `htw digest` is a file on the
machine that ran the scan. There is no dashboard, no time-to-resolution view, and
no measured false-positive rate.

It does not read live cloud accounts, clusters, or image registries. Container
images, cloud accounts, clusters, and running applications are rejected as asset
types. Dockle will not pull an image. Prowler, kube-bench, and fuzzing are not
in this release.

Patches stop at the two safe cases above. There is no general code fix, no
generated rewrite, and no patch that HTW applies by itself.

Also absent, so the report does not imply them: reachability of a vulnerable
function, a scan of only the pull-request diff, and any check at `L3`.

## Commands and results

| Command | What it does |
|---|---|
| `htw init` | Write a starter scope file for the current directory. |
| `htw validate` | Check the scope file and say whether each asset would be scanned or refused. |
| `htw doctor` | List scanners, whether each is installed, what each sends on the network, and the sandbox status. |
| `htw detect [--asset ID] [--json]` | Show the detected stack and the scan plan. Runs no scanner and writes nothing. |
| `htw scan [--asset ID] [--fail-on SEVERITY] [--strict]` | Scan and write the report. |
| `htw digest [--asset ID]` | Write `.htw/digest.md` from the latest finished scan. |
| `htw audit-verify` | Verify the hash chain of the audit log. |

`--fail-on` takes `critical`, `high`, `medium`, `low`, or `info`. It looks only at
findings that are new or back, so an existing backlog does not keep a pipeline red.

| Exit code of `htw scan` | Meaning |
|---|---|
| 0 | Completed. Nothing at or above `--fail-on`, if you passed one, is new or back. |
| 1 | A new or reappeared finding is at or above `--fail-on`. |
| 2 | Refused: invalid scope file, unknown asset, expired authorization, failed ownership check, outside a scan window, or the kill switch. |
| 3 | Incomplete: a scanner failed, or the model was enabled and could not be called. With `--strict`, also when part of the stack was not covered. |

`htw digest` exits 2 when there is no finished report to read.

A scan writes this under `state_dir` (`.htw` unless you change it). `digest.md`
appears when you run `htw digest`, not during the scan.

```
.htw/
  digest.md
  state.db
  audit.jsonl
  reports/<asset>/<run>/
    report.md
    findings.sarif
    summary.json
    sbom.cdx.json          # when Syft ran
    proposals/             # when fixes.propose is true
```

What else leaves the machine, besides the EPSS and KEV downloads above: Grype and
Trivy download a vulnerability database; OSV-Scanner sends package names and
versions to osv.dev and deps.dev; Semgrep downloads rulesets unless
`semgrep_rules` points at local files, and HTW passes `--metrics=off` and
`--disable-version-check`; gosec's Go toolchain may download modules. OpenSSF
Scorecard runs only when `scanners.pipeline.tools` names `scorecard`, and cosign
only when that list names `cosign`. The list is the whole selection for the
pipeline agent, so keep `zizmor` and `checkov` on it if you still want them.
Scorecard's local mode can still contact GitHub, and HTW adds no token. cosign is
run as `cosign verify-blob --offline` with a `cosign.pub` file inside the asset. ZAP and Nuclei contact only the approved
staging URL. Syft, Gitleaks, Bandit, and TruffleHog (`--no-verification`
`--no-update`) do not use the network, and neither do Hadolint, KICS,
kube-linter, zizmor (`--offline`), cosign, or Dockle under the flags HTW passes.
Checkov is passed `--download-external-modules false` and `--skip-results-upload`.
Trivy `config` is passed `--skip-db-update`; a missing local cache may still be
fetched once. `htw digest` reads local files only.

The guardrails, and the limits of the bubblewrap sandbox, are written out in
[docs/guardrails.md](docs/guardrails.md).

## Development

```bash
pip install --require-hashes -r requirements-dev.txt
pip install --no-deps --no-build-isolation -e .
ruff check . && ruff format --check . && mypy && pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [docs/architecture.md](docs/architecture.md),
and [ADR 0001](docs/adr/0001-implementation-language.md). The language is Python.

`tests/fixtures/` holds intentionally vulnerable test data with synthetic
credentials. It is excluded from HTW's scan of itself.

## Security

To report a vulnerability in HTW, see [SECURITY.md](SECURITY.md). Please do not
open a public issue.

## License

[Apache-2.0](LICENSE).
