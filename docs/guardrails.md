# Guardrails

HTW is meant to be run unattended on systems that matter. These are the rules it
enforces on itself, where each one lives in the code, and where the current limits
are.

## Authorized use

Only scan systems you own or are explicitly authorized to test. HTW refuses to scan
anything that is not declared, with an authorization record, in its scope file. That
refusal protects operators from mistakes. It does not make an unauthorized scan
legitimate: whoever writes the scope file is responsible for what it declares.

## What is enforced

### Deny by default

The scope file is an allowlist. `htw scan` and `htw detect` take asset ids from that
file and nothing else: there is no way to pass a path or a URL on the command line.
An asset that is not declared is out of scope.

The file is validated strictly. Unknown keys are errors, so a typo cannot silently
turn a restriction off.

Code: `core/config.py`.

### Authorization records that expire

Every asset needs `authorized_by` (a named person), `authorized_on` and `expires_on`.
A scan before the start date or after the expiry date is refused: an expired
authorization is no authorization. HTW warns when expiry is 14 days away or less.
`htw init` writes a scope file with these fields empty, so a generated file cannot be
used until a person has filled them in.

Code: `core/scope.py` (`ScopeGuard`).

### Ownership check before every run

For `repository` assets the scope file names the git remote the checkout must point
to (`ownership.git_remote`). Before every scan HTW reads the checkout's remotes and
refuses if none matches. The host and the owner must be written out in the pattern;
wildcards are only allowed after them.

The git configuration is parsed directly. No git command is run, so nothing in the
repository's configuration can execute. Credentials embedded in remote URLs are
stripped before the URL is compared or logged.

For `directory` assets there is nothing to check against, and the report says so. Use
`repository` wherever the path is a git checkout.

### Control levels

| Level | Meaning | This release |
|---|---|---|
| L0 | Static analysis of files. Nothing is executed, nothing is contacted on the target. | Implemented. Dependencies, secrets, SAST, containers, infrastructure and CI/CD are L0. |
| L1 | Read-only checks against running systems. | Refused: no L1 check exists yet. Cloud accounts are not contacted. |
| L2 | Active tests that need a time-bound human approval. | DAST only. Refused unless the asset's `max_level` is at least L2 and `approvals` contains a current entry for control `dast` whose `target` is exactly `runtime.staging_url`. |
| L3 | Intrusive or potentially destructive tests. | Never run by agents. `max_level: L3` is rejected by the scope file. |

An asset's `max_level` caps what may run against it. The guard checks the level of
every agent and tool before it runs.

Code: `core/levels.py`, `core/scope.py`.

### Report-only by default, and never auto-applied

HTW does not modify the systems it scans. With the default configuration it writes
reports and nothing else. With `fixes.propose: true` it also writes fix proposals as
files next to the report.

The interface for opening proposals as pull requests enforces, in its base class:
proposals must be enabled explicitly; the asset must be in scope; only draft pull
requests on a new `htw/` branch; no merge, no approval, no auto-merge; and a proposal
that could reveal an unfixed weakness may only go to a destination declared private.
`GitHubCliPublisher` is that implementation for GitHub. It clones into a temporary
directory, pushes with `gh auth git-credential`, and closes the pull request if
`gh` did not open it as a draft. It does not create credentials. If `git` or `gh`
is missing, the proposal file remains and the run records why no pull request was
opened.

Code: `agents/fixer.py`, `integrations/pull_requests.py`, `integrations/github.py`.

### Triage does not phone home unless you say so

Deduplication, ranking and the obvious false-positive filters run locally. Findings
under vendored trees are dropped for code, container, infrastructure and pipeline
checks, not for dependency or secret findings. A secret finding in documentation is
dropped only when its context matches a placeholder pattern.

`triage.llm: true` also requires `provider` (`openai` or `anthropic`) and
`api_key_env`, the name of an environment variable. The key is read at call time
and is not written into the scope file, the report or the prompt. The model is
asked only about findings the local rules did not settle, and a fingerprint it
already classified is read back from the state directory instead of being sent
again. That file stores the classification, not the finding text. The prompt
carries the fingerprint, rule, path, line, category, severity and a short message.
It does not carry the secret context or the proposed patch. If the variable is
unset and a call is still needed, no request is made and the run is marked
incomplete. The model may only mark a false positive, with a reason, or set
confidence to low. Confidence that is already low is not lowered a second time.

Code: `agents/triage.py`, `core/llm.py`.

### Secrets are redacted at the source

A secret finding keeps the location, the kind of credential and a fingerprint. The
value is never stored:

- Gitleaks runs with `--redact`, and its match is masked again in case it was not.
- TruffleHog's raw and partially redacted fields are never read. Verification of
  found credentials (which would contact the service they belong to) is always off.
- Source snippets that scanners return are not copied into findings.
- Free text from scanners passes through a redaction filter for credential-shaped
  strings before it is stored or printed.
- The fingerprint of a secret finding is computed from the scanner's redacted match.
  HTW never reads or hashes the line that holds the secret.

Code: `scanners/gitleaks.py`, `scanners/trufflehog.py`, `core/redact.py`,
`core/fingerprint.py`.

### Scanners are contained

Each scanner is a child process started without a shell, with:

- a scrubbed environment: only an allowlist of variables (`PATH`, `HOME`, locale,
  proxy and CA settings, cache locations) plus what `runner.env_passthrough` names.
  Tokens in the operator's shell or CI job do not reach the scanners;
- a timeout and an output size limit, after which the whole process group is killed;
- no standard input;
- when bubblewrap is usable, a private mount namespace: the asset read-only, a
  fresh home directory, and the network dropped for tools that do not use it.
  `git` and `gh` are started without that wrapper so they can use the login the
  operator already has. HTW does not create that login.

Code: `core/runner.py`. `htw doctor` prints whether the sandbox is active.

### Kill switch

Creating `<state_dir>/STOP` or setting `HTW_KILL_SWITCH=1` stops everything: no scan
starts, and a scanner that is running is sent a termination signal within a fraction
of a second (and killed if it does not exit). Results of an interrupted run are
discarded rather than half-recorded.

### Limits

Per asset: `limits.windows` (when scans may start, in UTC) and
`limits.min_interval_minutes` (how soon after the previous scan). Per tool: at most
5000 findings are kept, most severe first.

### Audit log

`<state_dir>/audit.jsonl` records every scope decision (including refusals and why),
who or what started each run, every tool executed with its version and level, and how
each run ended. Each record carries the hash of the one before it; `htw audit-verify`
detects edited, removed or reordered records.

Truncating the end of the file cannot be detected from the file alone. Ship the log to
storage that the scanned systems cannot write to.

Code: `core/audit.py`.

### Suppressions are reviewed and expire

A suppression needs a fingerprint, a kind (`false_positive` or `accepted_risk`), a
reason, an author and an expiry date. There are no permanent suppressions. The file is
meant to live in version control so that each one is reviewed. Expired suppressions
stop applying and are listed in the report.

Code: `core/suppressions.py`.

### Scanned content is treated as hostile

File names, package names and scanner messages come from the scanned content, which
may be attacker-influenced:

- stack detection and fingerprinting never follow symlinks and never read outside the
  asset root;
- findings whose path is outside the asset are dropped;
- control characters are stripped, so nothing can rewrite a terminal;
- text is escaped in Markdown reports, so nothing can inject links, images or HTML;
- only `http(s)` references are rendered as links;
- scanner output is parsed defensively: a field that is missing or has the wrong
  type is skipped, and a wrapper that still trips over its input costs that tool's
  results, not the run.

### Reports are confidential

Reports describe where a weakness is and how to remedy it, never how to exploit it.
They are written to the state directory, which HTW creates readable by its owner
only, and nothing is uploaded anywhere. Every report opens with a
notice not to paste it into public issues, pull requests or chats.
`htw digest` only reads those reports and writes `digest.md` in the same state
directory. It does not start a server and does not send the digest anywhere.

## Current limits

These are the gaps between the rules above and what phase 1 enforces. They are
listed here so that nobody has to discover them.

- **The process sandbox is bubblewrap, not the container the plan describes.**
  When `bwrap` can start, a scanner may read the asset and may write only the
  report directory (and a cache directory named in `runner.env_passthrough`). The
  asset is mounted read-only. The home directory is not mounted, so an existing
  `gh` or cloud login is not visible to the scanner. Tools that declare no network
  use lose the network. `runner.sandbox: off` disables this. The plan's
  digest-pinned images and an egress allowlist of addresses are not implemented.
  Where bubblewrap cannot start, the report says the scanners ran as this user.
  Run HTW as an unprivileged user, on a machine or CI runner that holds no
  credentials it does not need.
- **Scanner binaries are not verified.** HTW runs whatever `PATH` resolves. Install
  scanners from their official releases and verify the checksums.
- **Some scanners use the network** to fetch rules or advisory data. See
  [What leaves your machine](../README.md#what-leaves-your-machine).
- **Priority enrichment uses two public feeds.** CISA KEV and FIRST EPSS are
  downloaded only for CVE ids already present on a finding, cached for a day, and
  ignored when unavailable so priority is not raised. The request carries no
  credentials and no source text. Reachability is not scored.
- **The kill switch is local.** It stops HTW on the machine where it is set.
- **The audit log is tamper-evident, not tamper-proof**, and only as trustworthy as
  the storage it is kept on.
- **Redaction of free text is best effort.** The structural rule (never read the
  fields that carry values) is what the guarantee rests on; the text filter is a
  second line of defence.
- **Directory assets have no ownership check.**
- **Time windows are in UTC.**
