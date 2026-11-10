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
