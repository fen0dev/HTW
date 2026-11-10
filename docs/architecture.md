# Architecture

This describes what phase 1 implements. The guardrails have their own page:
[guardrails.md](guardrails.md).

## One scan, step by step

```
htw scan
   |
   v
 scope file (allowlist) ----> refused: authorization, ownership, window, rate limit
   |
   v
 stack detection ----------> languages, package managers, containers, IaC, CI/CD
   |
   v
 scanner agents choose tools for the detected stack; missing tools are skipped
   |
   +--> Dependencies and SBOM   Syft -> Grype | OSV-Scanner | Trivy
   +--> Secrets                 Gitleaks | TruffleHog
   +--> Static analysis         Semgrep | Bandit | gosec
   +--> Containers              Hadolint, Trivy config | Checkov   (files only)
   +--> Infrastructure          Checkov | Trivy config | KICS | kube-linter
   +--> CI/CD                   zizmor | Checkov                    (workflow files)
   +--> Runtime (L2)            ZAP baseline, only with a current approval
   |
   v
 normalize -> fingerprint -> triage -> prioritize -> compare with the previous run
   |
   v
 report.md, findings.sarif, summary.json, SBOM, optional fix proposals
   |
   v
 optional: draft pull request (never merged)
```

The orchestrator follows these steps. Triage is deterministic and on by default. A
language model is optional, off unless the scope file names a provider, and never
called when that provider's key is absent. "Agent" here means a component that owns
one kind of check behind a common interface. Deep review and generated fixes beyond
a scanner-supplied patch are not in this release.

Every step that matters (scope decision, run start, each tool executed, run end) is
written to the audit log.

## Code layout

```
src/htw/
  cli.py                 command line
  core/
    config.py            scope file: parsing and strict validation
    scope.py             scope guard, ownership check, kill switch
    levels.py            control levels L0-L3
    runner.py            scanner processes: scrubbed environment, timeout, output cap
    finding.py           the normalized finding record
    fingerprint.py       stable finding identity
    store.py             SQLite state: new / unchanged / resolved / reappeared
    suppressions.py      reviewed, expiring suppressions
    scoring.py           priority P0-P3
    redact.py            masking of credential-like text
    markdown.py          escaping of scanner-supplied text in reports
    sarif.py             SARIF 2.1.0 output
    audit.py             hash-chained append-only log
  detect/                stack detection (signatures are data, in signatures.py)
  scanners/              one adapter per external tool
  agents/
    base.py              the agent interface and tool selection
    deps_sbom.py, secrets.py, sast.py, container.py, iac.py, pipeline.py, dast.py
    triage.py            deduplicate, rank, optional model
    orchestrator.py      the pipeline
    reporting.py         report.md, SARIF, summary.json
    fixer.py             fix proposals
  integrations/
    pull_requests.py     proposal files and the draft pull request rules
    github.py            opens a draft pull request with git and gh
  core/llm.py            optional triage client; no call unless configured
```

This follows the layout in the architecture plan, as one installable package. Parts of
the plan that this release does not need (`evals/`, tracker and chat integrations,
live cloud hardening, fuzzing) are not stubbed out. The model client is one module
and stays unused until `triage.llm` is set.

## Stack detection

Detection decides which scanners apply, so it has to be predictable:

- **Static and read-only.** It walks the tree and looks at file names, extensions and
  a bounded prefix (64 KiB) of files whose name alone is ambiguous: a `.yaml` file is
  classified by its content, not by where it sits. Nothing is executed.
- **Symlinks are never followed**, so a repository cannot point detection outside the
  declared asset.
- **Dependency and build directories are skipped** (`node_modules`, `.venv`,
  `vendor` next to a `go.mod` or `composer.json`, `target` next to a `Cargo.toml` or
  `pom.xml`, and so on). Vendored code would otherwise make a Go service look like it
  is also written in Ruby.
- **Evidence and confidence.** Every detected component lists the files that prove it
  and a confidence level. A language inferred from a shebang is `medium`; a Kubernetes
  manifest with an unknown API group is `medium`.
- **Data-driven.** The signatures live in `detect/signatures.py`. Adding a package
  manager or a CI system is a table entry.

Categories: languages, package managers (with the ecosystem and whether a lockfile is
present), containers, infrastructure as code, cloud providers, CI/CD, dependency
automation, version control.

`htw detect` prints the profile and the resulting scan plan without running a scanner.

A CI system the detector recognizes and no wrapped tool covers is reported as
`no wrapped scanner: <name>`. That line means HTW has no scanner for it. It is not
an invitation to install Checkov: Checkov already covers only the systems named in
`scanners/targets.py` (GitHub Actions, GitLab CI, Azure Pipelines, Bitbucket
Pipelines, CircleCI). Cloud providers detected from files are not contacted:
without infrastructure files, the infrastructure agent says so and stops.

## Scanner agents and tool adapters

A **tool adapter** (`scanners/`) wraps one external binary. It builds the command
line, runs it through the runner, parses the tool's native JSON defensively, and
returns normalized findings. Adapters read the native format rather than each tool's
SARIF export because that is where package names, installed versions and fixed
versions are still structured.

A **scanner agent** (`agents/`) owns one kind of check and lists its adapters in
order of preference. Selection is by coverage:

1. The agent asks the stack profile what needs covering, for example
   `sast:Python`, `sast:Go`, `sbom`, `vulns`.
2. Adapters are tried in order. One is selected only if it covers something no earlier
   adapter covers.
3. If its binary is not installed, that is recorded and the next adapter gets its
   chance.
4. Whatever is left uncovered is reported as a coverage gap.

So with Semgrep installed, Bandit and gosec are not run; without it they cover Python
and Go, and the report says JavaScript was not analysed. An explicit `tools:` list in
the scope file replaces this with "run exactly these".

### Adding a scanner

1. Write an adapter in `src/htw/scanners/`: subclass `ToolAdapter`, set `name`,
   `binary`, `homepage`, `install_hint` and `network`, and implement `coverage()` and
   `scan()`.
2. Add it to the adapter list of the agent it belongs to.
3. Add a parser test with canned output to `tests/test_scanners.py` and, if the tool
   is easy to install, an integration test.

The core does not change. Rules for adapters: never read a field that carries a
secret value or a source snippet; pass every path through `ctx.relative()`, which
drops anything outside the asset; pass free text through `clean_text()`.

## Findings, fingerprints and the delta

Every scanner result becomes a `Finding` with an asset, a tool, a category, a rule, a
severity, a location and, for dependencies, the package with its fixed versions.

The **fingerprint** (`htw1:` plus 32 hex digits) identifies the same problem across
scans:

- Code findings: tool, rule, file path and a hash of the flagged lines with whitespace
  normalized. Line numbers are left out, so code that moves keeps its identity. If the
  same rule flags identical lines several times in a file, an occurrence index keeps
  them apart.
- Secret findings: the same, but the hashed text is the scanner's already-redacted
  match. A line that holds a secret is never read or hashed by HTW.
- Dependency findings: advisory id, ecosystem, normalized package name and manifest
  path. The installed version and the reporting tool are left out, so an upgrade to a
  version that is still vulnerable remains the same finding, and switching from Grype
  to OSV-Scanner does not report everything again.

The **store** compares each run with the state the previous one left:

| State | Meaning | Reported as a change |
|---|---|---|
| new | never seen before | yes |
| reappeared | was resolved, is back | yes |
| resolved | was open, the scanner that found it ran and no longer reports it | yes |
| unchanged | still open | no |
| unverified | still open, but its scanner did not complete in this run | no |

A finding is only resolved when the tool that reported it ran to completion. A missing
or failed scanner never makes findings disappear.

**Priority** (P0 to P3) is the scanner's severity adjusted by the asset's criticality.
It is deliberately simple; exploitability and reachability data are planned.

## Output

Under `<state_dir>/reports/<asset>/<run>/`:

- `report.md`: what changed, what is open, what was and was not covered.
- `findings.sarif`: SARIF 2.1.0, one run per underlying tool, the HTW fingerprint in
  `partialFingerprints["htw/v1"]`, the comparison with the previous run in
  `baselineState`, suppressions in `suppressions`.
- `summary.json`: counts, scanner status, coverage gaps and the detected stack, for
  scripts.
- `sbom.cdx.json`: CycloneDX SBOM, when Syft is installed.
- `proposals/`: fix proposals, when enabled.

## Fix proposals

`fixes.propose: true` adds proposals to the run. A proposal states the remedy and
carries a patch in two cases: an exact `==` pin without hashes in a requirements
file, and a Semgrep replacement that is small, survives redaction, and matches the
reported lines in exactly one place. The scanned tree is not edited. Everything else
gets a proposal without a patch.

Proposals are written as files. `fixes.pull_requests: true` asks
`GitHubCliPublisher` to open each one as a draft. The publisher subclasses
`PullRequestPublisher`, so the rules (enabled explicitly, asset in scope, draft
only, never merge, nothing that discloses an unfixed weakness to a public
destination) cannot be skipped. The work happens in a temporary clone. `gh` uses
the login it already has; HTW creates no token. A pull request that is not a draft
is closed and the failure is recorded. Code patches stay `public_safe: false`.

## Differences from the plan

- Scanners run as local binaries, not as containers pinned by digest. When
  bubblewrap is usable they see the asset read-only, a private home directory, and
  no other path except a cache named in `env_passthrough` and the report directory.
  Tools whose network note is "none" also lose the network. There is no egress
  allowlist of addresses. See [guardrails.md](guardrails.md).
- Results go to files (Markdown, SARIF, JSON). Posting to an issue tracker or chat is
  not implemented.
- Stack detection is a component of its own, which the plan did not single out.
