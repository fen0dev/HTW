# Security policy

## Reporting a vulnerability in HTW

Please report it privately. Do not open a public issue, pull request or discussion for
a suspected vulnerability, and do not include exploit details in public anywhere.

**How to report:** use GitHub's private vulnerability reporting for this repository:
open the [Security tab](https://github.com/fen0dev/HTW/security), choose
"Report a vulnerability", and fill in the form
([direct link](https://github.com/fen0dev/HTW/security/advisories/new)). The report is
visible only to you and the maintainers.

If that form is not available to you, open a public issue that says only "I would like
to report a security issue privately" with no technical details, and a maintainer will
arrange a private channel.

**What to include:**

- the HTW version (`htw --version`) or commit, and how you installed it;
- the versions of the scanners involved (`htw doctor`);
- what you observed and what you expected;
- the smallest configuration or input that reproduces it;
- your assessment of the impact.

Remove real secrets, internal hostnames and proprietary code from anything you send.
Synthetic reproductions are preferred.

**What to expect:** a maintainer will acknowledge the report, confirm whether it is
reproducible, and keep you informed while a fix is prepared. Fixes are developed in a
private advisory and published together with the advisory. You will be credited in the
advisory unless you ask not to be. Please give the maintainers reasonable time to
release a fix before disclosing anything publicly.

## What counts as a vulnerability in HTW

HTW runs on a team's own systems and processes content that may be hostile (a scanned
repository can be attacker-influenced). Reports in these areas are especially welcome:

- **Scope bypass:** any way to make HTW scan, read or modify something that is not
  declared and authorized in the scope file, including path traversal and symlink
  tricks.
- **Guardrail bypass:** running after an authorization has expired, ignoring the kill
  switch, exceeding the declared control level, or applying a change without review.
- **Secret exposure:** a secret value or source snippet reaching a report, the SARIF
  output, the state database, the audit log or the terminal.
- **Injection through scanned content:** file names, package names or scanner output
  that lead to command execution, or that inject links, markup or terminal escape
  sequences into reports.
- **Audit log integrity:** edits or deletions inside the log that `htw audit-verify`
  does not detect.
- **Credential leakage to scanners:** environment variables reaching a scanner process
  that are not on the documented allowlist.

Out of scope: vulnerabilities in the third-party scanners themselves (report those to
their maintainers), and findings about the intentionally vulnerable test data under
`tests/fixtures/`.

## Supported versions

HTW is pre-1.0. Security fixes are made on the latest release and on `main`.

## Using HTW responsibly

HTW is for systems you own or are explicitly authorized to test. It refuses to scan
anything that is not declared, with an authorization record, in its scope file. That
check is a safeguard for operators; it is not permission. Scanning systems without
authorization may be illegal where you are.

If HTW helps you find a vulnerability in someone else's software (for example in an
open-source dependency), report it privately to that project's maintainers through
their security policy. Do not publish details, and do not open a public issue or pull
request that describes how to exploit it.
