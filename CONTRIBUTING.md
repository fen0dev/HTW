# Contributing

Thanks for helping. A few things to know before you start.

## Security issues

Do not open a public issue or pull request for a vulnerability in HTW. See
[SECURITY.md](SECURITY.md).

## Development setup

Python 3.11 or later.

```bash
git clone https://github.com/fen0dev/HTW.git
cd HTW
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements-dev.txt
pip install --no-deps --no-build-isolation -e .
```

## Checks

CI runs these, and a pull request needs all of them to pass:

```bash
ruff check .
ruff format --check .
mypy
pytest
```

`pytest` needs no scanner installed and no network. Tests marked `scanner` run the
real binaries against a temporary copy of `tests/fixtures/vulnerable-app` and are
skipped when the binary is missing:

```bash
pytest -m scanner -rs      # only the integration tests, listing what was skipped
pytest -m "not scanner"    # only the unit tests
```

One test validates HTW's SARIF output against the official SARIF 2.1.0 JSON schema.
The schema is not vendored. To run that test locally, download the schema and point
`HTW_SARIF_SCHEMA` at it (CI does this, see `.github/workflows/ci.yml` for the pinned
URL and checksum):

```bash
HTW_SARIF_SCHEMA=/path/to/sarif-schema-2.1.0.json pytest tests/test_sarif.py
```

## Ground rules

- **Never scan anything you do not own.** Tests and examples only ever touch the
  fixtures in this repository or temporary copies of them.
- **No real secrets, anywhere.** Fixture credentials must be obviously synthetic and
  must not match a real provider's token format. Where a test needs a
  credential-shaped string, assemble it at run time (see `tests/helpers.py`).
- **Guardrails are not optional.** A change that weakens one (scope, authorization,
  redaction, the kill switch, report-only by default) needs to say so in the pull
  request and needs a strong reason.
- **Keep the dependency list short.** HTW has one runtime dependency. Adding another
  needs a reason that outweighs the supply-chain cost.
- **Tests come with the change.** Scanner adapters are tested against canned output
  that keeps the shape of the tool's real JSON.

## Adding a scanner

See "Adding a scanner" in [docs/architecture.md](docs/architecture.md).

## Updating pinned dependencies

```bash
uv pip compile pyproject.toml --generate-hashes --universal -o requirements.txt
uv pip compile pyproject.toml --extra dev --generate-hashes --universal -o requirements-dev.txt
```

## Design decisions

Decisions that are expensive to reverse are recorded in `docs/adr/`. Add a record
when you make one.
