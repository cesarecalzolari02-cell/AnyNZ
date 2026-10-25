# Changelog

## Unreleased

### Packaging and CI

- SPDX license metadata (`license = "MIT"`, `license-files`); builds need
  setuptools 77 or newer. The old table form stops building after 2027-02-18.
- The version is read from `nx_decode.__version__`.
- The sdist includes `tests/` (with the builders), `scripts/` and the docs, so the
  test suite runs from it.
- CI: Python 3.10, 3.12 and 3.14 on Ubuntu and Windows, current action versions,
  and a `package` job that builds the sdist and wheel, checks both for forbidden
  files, installs the wheel in a clean venv and runs the tests from the sdist.
- ruff is pinned to one minor version so a ruff release cannot break CI.

## 0.1.0

First version: `info`, `list`, `extract`, `nca-extract`, `verify` and `titles`
for XCI, NSP and NCA files, with common-ticket title keys, ExeFS/PFS0/RomFS
extraction, CNMT/NACP metadata, and title grouping (base, updates, DLC).
