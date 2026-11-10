# ADR 0001: Implementation language

- Status: accepted
- Date: 2026-11-10

## Context

HTW is downloaded by engineering teams and run on their own systems. Its job is to
decide what may be scanned, detect the stack, run established scanners as child
processes, normalize what they report, and compare it with the previous run. Later
phases add LLM-based triage, deeper code review and fix generation.

The architecture plan recommends Python. This record confirms or changes that
recommendation before any code depends on it.

What the language has to be good at, in order of weight:

1. Orchestration and data handling: subprocesses, JSON and YAML, SQLite, text. The work
   is I/O-bound. The scanners do the expensive analysis in their own processes, so the
   orchestrator's raw speed is not a constraint.
2. The later phases: first-class LLM SDKs with structured output, evaluation tooling,
   and libraries for SARIF and advisory data.
3. Fit with the people who will run and extend it: security and platform engineers.
4. Distribution to machines HTW does not control, and the supply chain that comes
   with it.

## Decision

Python, version 3.11 or later, with a single runtime dependency (PyYAML).

## Reasons

- The orchestrator is glue. Python's standard library covers nearly all of it:
  `subprocess`, `sqlite3`, `json`, `hashlib`, `tomllib`, `argparse`. That is why the
  runtime dependency list has one entry, which matters more for a security tool than
  for most software.
- The LLM phases are where the project will grow. Provider SDKs, structured-output
  support and evaluation tooling arrive in Python first and are best maintained there.
  Choosing another language now would mean either a rewrite or a second runtime later.
- The audience already runs Python. Semgrep, Bandit and Checkov are Python packages;
  a team that installs them has the interpreter and the habits. Contributions such as
  a new scanner adapter are short Python modules, and the people most likely to write
  one are the people most likely to know the language.
- Scanners are invoked as processes, never linked as libraries, so the language they
  are written in (mostly Go) creates no pull towards Go.

## Alternatives considered

**Go.** The strongest alternative, for one reason: a single static binary is the best
way to hand a tool to someone else, and most of the scanners HTW wraps are distributed
that way. Against it: weaker LLM and evaluation ecosystem for the later phases, more
code for the same data handling, and a smaller pool of likely contributors among the
target audience. The distribution gap is real but narrow in practice: `pipx` or `uv`
installs HTW in isolation with one command, the dependency footprint is one package,
and the scanners have to be installed separately whatever HTW is written in.

**TypeScript.** Good LLM SDKs and a large community. Against it: a much larger
transitive dependency tree for the same functionality, which is the wrong trade for a
security tool, and no advantage over Python on any of the criteria above. The plan
lists it as an option for teams already invested in a graph-based agent framework;
phase 1 has a linear, deterministic flow and needs no such framework.

**Rust.** Single binary, memory safety, strong typing. Against it: the highest cost
per feature for I/O-bound glue code, the weakest LLM ecosystem of the four, and the
smallest contributor pool in the target audience. Its strengths would matter if HTW
did the analysis itself. It does not.

## Consequences

- Users need Python 3.11 or later. 3.11 is the floor because it is the oldest version
  with `tomllib`, `StrEnum` and `datetime.UTC` in the standard library, and it is
  still in security support.
- Type safety is enforced by tooling rather than the compiler: `mypy --strict` and
  `ruff` run in CI, and the code is fully annotated.
- Dependencies are pinned with hashes (`requirements.txt`, `requirements-dev.txt`).
  Adding a runtime dependency needs a reason that outweighs the supply-chain cost.
- No single-binary distribution in this phase. If demand for one appears, a zipapp or
  a container image is the first step; a rewrite is not.
- Revisit this decision if the orchestrator ever has to do CPU-bound analysis itself,
  or if installation friction turns out to be the main obstacle to adoption.
