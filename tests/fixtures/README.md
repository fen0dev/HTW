# Test fixtures

Everything under this directory is test data for HTW.

- `vulnerable-app/` is **intentionally insecure**: outdated dependency pins, unsafe code
  and fake credentials. It exists so the scanner wrappers can be exercised end to end.
  Nothing in it is deployed or imported anywhere.
- `stacks/` holds small, inert project skeletons used to test stack detection.

All credentials in these files are synthetic. They were typed in for this repository,
have never been valid anywhere and grant access to nothing. Hosts use the reserved
`.invalid` top-level domain.

Dependency manifests here pin old versions on purpose. Do not "fix" them, and expect
dependency bots to complain about this directory.

The integration tests scan a temporary copy of `vulnerable-app/`, never the directory
in place: Semgrep's default ignore list skips directories named `tests`, and the tests
modify the copy. HTW's scan of its own repository excludes `tests/fixtures`.
