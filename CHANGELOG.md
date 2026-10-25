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

### Repository

- `.gitattributes`: LF in the repository; the shell hook stays LF in Windows
  checkouts made with `core.autocrlf=true`.
- `check_forbidden.py` reads only the first 4 MiB of each file or staged blob, so
  an accidentally staged dump is not loaded whole. It also rejects archives
  (`.rar`, `.7z`, `.zip`), which often wrap dumps; `.gitignore` ignores them.
- An issue template that asks for the command and output, and says never to attach
  keys or game files.

### Fixes

- A keys file saved with a UTF-8 byte-order mark (Windows Notepad does this) was
  rejected as malformed on line 1; it now loads.
- Output that the console can't encode no longer crashes. On Windows, redirected
  output uses the legacy code page, so Japanese or Chinese title names were an
  "internal error"; they now print as `?`.
- `verify` on a rights-ID NCA given without its ticket reports the sections as
  skipped, not failed: an input is missing, the file isn't corrupt.
- A corrupt hash block size in an NCA FS header is a format error. Before, an IVFC
  block size computed as `1 << u32` could build a huge integer or try to allocate
  gigabytes.
- `verify` streams the hash tables and XCI HFS0 entry hashes instead of reading
  them whole (a hash level of a large game is tens of MiB), and bounds the XCI
  root header size.

### Tests

- `tests/test_robustness.py`: seeded corruption of synthetic NSP, XCI and NCA
  files (encrypted and plaintext), run through every command. Anything other than
  a clean error fails. Outside the suite, the same mutator ran through tens of
  thousands of command runs without a crash.

## 0.1.0

First version: `info`, `list`, `extract`, `nca-extract`, `verify` and `titles`
for XCI, NSP and NCA files, with common-ticket title keys, ExeFS/PFS0/RomFS
extraction, CNMT/NACP metadata, and title grouping (base, updates, DLC).
