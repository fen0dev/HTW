# Example: Northwind scans its own service

This is an example, not a report of a real company. Northwind Payments, the host
`github.com/northwind-example/payments-api`, the person Mina Cho, and the findings
below are invented. Nothing here is a secret, and nothing here explains how to
attack a system. The commands and the `htw.yaml` keys are the ones HTW accepts.
Run them only on a checkout your team owns.

Northwind keeps one small service in git. The checkout has the application, a
Dockerfile, and a GitHub Actions workflow:

```
payments-api/
  app/server.py
  requirements.txt
  Dockerfile
  .github/workflows/ci.yml
```

Mina is on the team that owns that repository. She wants a local report of what
the files contain, not a scan of a running host. She works on her laptop, in a
clone she already has.

## Install

HTW needs Python 3.11 or later. The scanners are separate programs. For this
service she installs HTW, then zizmor, because the repository has a GitHub Actions
workflow. She also installs Syft, Grype, Gitleaks, Semgrep, and Hadolint so the
dependency list, secrets, Python, and Dockerfile are covered. HTW does not bundle
those tools. If one is missing, the later steps say so instead of failing.

```bash
pipx install git+https://github.com/fen0dev/HTW.git
htw --version
htw doctor
```

`htw --version` prints the HTW version. `htw doctor` lists every wrapped scanner,
whether that binary is on `PATH`, what it would send over the network, and whether
bubblewrap will wrap scanner processes on this machine. A line that says
`[missing]` means that scanner will be skipped until she installs it.

## `htw init`

She clones the repository her team owns and starts the scope file there. `htw init`
looks at the current directory. Because it is a git checkout, the file it writes
uses `type: repository` and copies the remote it found into `ownership.git_remote`.

```bash
cd ~/src/payments-api
htw init
```

The command prints:

```
Wrote htw.yaml.
Fill in `owner` and the `authorization` record, then run `htw validate`.
Only scan systems you own or are explicitly authorized to test. HTW scans nothing that is not declared, with an authorization record, in the scope file.
Add the state directory (.htw/) to your .gitignore.
```

`htw.yaml` is the allowlist. The generated file is not scannable yet: `owner` and
the authorization dates are empty on purpose. She adds `.htw/` to `.gitignore`
before the first scan. Reports stay on the machine.

## Allowlist and authorization

She opens `htw.yaml` and fills in the four fields the header asked for. She checks
that `ownership.git_remote` is the repository Northwind owns. She leaves
`max_level` at `L0`, so the scan reads files and does not contact a running
service. She leaves `fixes.propose` and `triage.llm` as `false`.

```yaml
version: 1

state_dir: .htw

fixes:
  propose: false
  pull_requests: false
  private_destination: false

triage:
  enabled: true
  llm: false

exploitability:
  enabled: true

assets:
  - id: payments-api
    type: repository
    path: .
    owner: payments-team
    environment: development
    criticality: medium
    max_level: L0
    ownership:
      git_remote: github.com/northwind-example/payments-api
    authorization:
      authorized_by: Mina Cho (Engineering)
      authorized_on: 2026-01-15
      expires_on: 2027-01-15
      reference: EXAMPLE-RECON-001
    exclude: []
```

`id` is the name she will pass to `--asset` later. `path: .` is this checkout,
relative to `htw.yaml`. `authorized_on` and `expires_on` are dates. After the
expiry date, `htw scan` refuses the asset. `reference` is optional; she uses it
as the ticket where the team recorded that this scan is allowed. `exclude: []`
means nothing in the checkout is skipped.

## `htw validate`

```bash
htw validate
```

Validate reads the scope file and does not run a scanner. For this file it prints:

```
htw.yaml: valid, 1 asset(s)
  payments-api: in scope (git remote github.com/northwind-example/payments-api matches github.com/northwind-example/payments-api)
```

`in scope` means the dates include today and the checkout's remote matches
`ownership.git_remote`. If the remote were different, the same command would print
`WOULD BE REFUSED` and the ownership error, and it would exit 2. An empty owner
or an empty date does the same.

## `htw detect`

```bash
htw detect
```

Detect still runs no scanner and writes no report. It prints the stack it
recognized and the plan for each agent. On this checkout the plan looks like this
when the extra scanners are not installed yet and zizmor is:

```
[payments-api] /home/mina/src/payments-api (5 files)
  Languages:
    Python (1): app/server.py
  Package managers:
    pip (1): requirements.txt
  Containers:
    Dockerfile (1): Dockerfile
  CI/CD pipelines:
    GitHub Actions (1): .github/workflows/ci.yml
  Version control:
    Git (1): .git
  note: PyPI: manifest without a lockfile. Dependency scanners only see the versions the manifest pins, so transitive dependencies may be missed.
  Scan plan:
    Dependencies and SBOM: no tool available
      missing: syft is not installed ...
      not covered: known vulnerabilities in dependencies (pip)
      not covered: software bill of materials (pip)
    Secrets: no tool available
      missing: gitleaks is not installed ...
      not covered: credentials in files and git history
    Static analysis (SAST): no tool available
      missing: semgrep is not installed ...
      not covered: static analysis of Python code
    Containers: no tool available
      missing: hadolint is not installed ...
      not covered: Dockerfile lint
      not covered: Dockerfile misconfiguration
    Infrastructure as code: not applicable (no infrastructure-as-code files detected)
    CI/CD and supply chain: zizmor
    Dynamic testing (DAST): not applicable (check level L2 exceeds the asset's max_level L0)
```

What she learns before spending a scan:

- The service, the Dockerfile, and the workflow were all seen. The counts are files,
  and the path after the colon is the evidence.
- There is no lockfile, so a later dependency scan can only see versions pinned in
  `requirements.txt`.
- Infrastructure-as-code is not applicable. There is no Terraform or Kubernetes
  file to scan.
- DAST is not applicable. `max_level` is `L0`, and dynamic testing is `L2`, so HTW
  will not open a connection.
- The workflow will be scanned by zizmor. The other checks are gaps until those
  binaries are on `PATH`. Installing them and running `htw detect` again replaces
  `no tool available` with the tool name. Syft covers the SBOM and Grype is the
  first tool HTW tries for known vulnerabilities. Hadolint covers Dockerfile
  lint. Dockerfile misconfiguration stays listed until Trivy or Checkov is
  installed.

## `htw scan`

```bash
htw scan
```

The scan writes under `.htw/` and does not modify the application files. With the
same tools as the detect step, the terminal ends like this:

```
[payments-api] complete: 3 new, 0 reappeared, 0 resolved, 0 still open
  P1 high     unpinned-uses (.github/workflows/ci.yml:6)
  P3 medium   artipacked (.github/workflows/ci.yml:6)
  P2 medium   excessive-permissions (.github/workflows/ci.yml:3)
  warning: syft is not installed ...
  not covered: known vulnerabilities in dependencies (pip)
  not covered: software bill of materials (pip)
  not covered: credentials in files and git history
  not covered: static analysis of Python code
  not covered: Dockerfile lint
  not covered: Dockerfile misconfiguration
  report: /home/mina/src/payments-api/.htw/reports/payments-api/<run-id>/report.md
```

`complete` means the scanners that did run finished. The three lines are example
findings from zizmor on the invented workflow: the rule name, the severity, the
priority, and the file and line. The warnings and `not covered` lines are the gaps
from detect. They are not findings. The last line is the report to open.

The run id in that path is new every scan. It looks like
`20261110T172520Z-b6ac2c`.

## Read the report

`report.md` is for the people who own the asset. The top of the example report:

```
# HTW scan report: payments-api

> **Confidential.** This report lists weaknesses that may not be fixed yet. Share it
> only with the people who own this asset, and do not paste it into public issues,
> pull requests or chats.

- Run: `20261110T172520Z-b6ac2c`, started 2026-11-10 17:25 UTC, HTW 0.1.0
- Status: **complete** with coverage gaps (see Coverage)
- Mode: report only; static checks only (L0), nothing was changed
- Asset: repository, owner payments-team, criticality medium
- Authorization: Mina Cho (Engineering), valid until 2027-01-15, reference EXAMPLE-RECON-001
- Ownership check: git remote github.com/northwind-example/payments-api matches github.com/northwind-example/payments-api
```

`What changed since the last scan` is a table. On a first run every finding is
new. In the example that table is 3 new (1 P1, 1 P2, 1 P3), and nothing
reappeared, resolved, or still open.

`New findings` repeats each one as a row and then a short block: the `htw1:` id,
priority, severity, confidence, the path, the rule, the tool, and a one-line
description written by the scanner. She reads that description in the report. This
walkthrough does not copy it. The three example rules are `unpinned-uses` (high,
P1), `excessive-permissions` (medium, P2), and `artipacked` (medium, reported at
P3 because the scanner's confidence is low).

`Coverage` lists the stack again, then a table of every scanner. zizmor's row says
`ran`. The tools that were not installed say `not installed`. Infrastructure as
code and DAST say `not applicable`, with the same reasons detect printed.
`Not covered` repeats the gaps in sentences.

Beside the Markdown file, the same directory holds `findings.sarif` and
`summary.json`. The SARIF file is the machine-readable copy. Each finding's id is
in `partialFingerprints["htw/v1"]`. She does not commit `.htw/`.

A second `htw scan`, with `.htw/state.db` left in place and no file changed,
prints:

```
[payments-api] complete: 0 new, 0 reappeared, 0 resolved, 3 still open
```

The three findings are no longer listed as new. They remain in the report under
`Still open`.

## `htw digest`

```bash
htw digest
```

Digest does not scan again. It reads the latest `summary.json` and
`findings.sarif` and writes `.htw/digest.md`. The command prints the digest and
then a line `digest: ` followed by that path. She opens the file in an editor.

The example digest:

```
# HTW digest

> **Confidential.** Built from the scan reports already stored on this machine.
> Nothing was uploaded. Do not paste it into public issues, pull requests or chats.

Read at 2026-11-10 17:25 UTC. One latest finished scan per declared asset.

- Declared assets: 1. Finished scans read: 1.
- Open findings: 3 (1 P1, 1 P2, 1 P3).
- In those scans: 3 new, 0 reappeared, 0 resolved.
- Time to resolution and a false-positive rate are not in these reports, so this digest does not show them.

## By asset

| Asset | Run | Status | New | Reappeared | Resolved | Still open | Open by priority |
|---|---|---|---|---|---|---|---|
| payments-api | `20261110T172520Z-b6ac2c` | complete | 3 | 0 | 0 | 0 | 1 P1, 1 P2, 1 P3 |

## payments-api

- Report: `/home/mina/src/payments-api/.htw/reports/payments-api/20261110T172520Z-b6ac2c/report.md`
- Started: `2026-11-10T17:25:20+00:00`
- 11 not installed.
- Not covered:
  - known vulnerabilities in dependencies (pip): no installed scanner covers this. See the Scanners table.
  - software bill of materials (pip): no installed scanner covers this. See the Scanners table.
  - credentials in files and git history: no installed scanner covers this. See the Scanners table.
  - static analysis of Python code: no installed scanner covers this. See the Scanners table.
  - Dockerfile lint: no installed scanner covers this. See the Scanners table.
  - Dockerfile misconfiguration: no installed scanner covers this. See the Scanners table.
```

The first lines are the whole checkout in one screen: one asset, three open
findings, three of them new. The path under `payments-api` is the full report.
The `Not covered` list is why the Dockerfile and the requirements file produced no
findings: those scanners were not installed, so HTW did not invent results for
them. Syft, Grype, Gitleaks, and Semgrep close the dependency, secret, and Python
gaps. Hadolint closes Dockerfile lint. Trivy or Checkov is still required for
Dockerfile misconfiguration. The next `htw digest` drops a gap only after a scan
that actually covered it.

Nothing was uploaded. The digest is not a dashboard and does not file a ticket.
