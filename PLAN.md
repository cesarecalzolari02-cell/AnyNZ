# nx-decode plan

Local, read-only decryption/extraction of Nintendo Switch XCI/NSP/NCA files the
user owns, using the user's own `prod.keys`. Nothing downloads, distributes,
patches or signs anything.

## Phases

- [x] **Phase 1: keys + containers.** Scaffold (pyproject, MIT, .gitignore,
  pre-commit hook, CI, forbidden-file check), `keys`, `io`, `crypto`,
  `containers` (PFS0/HFS0/XCI/NSP, NSZ/XCZ detection), `list` / `extract`.
- [x] **Phase 2: NCA.** Header decryption (AES-128-XTS, big-endian sector
  tweak, NCA2 variant), key generation and key-area key, tickets / title keys
  (common only), section readers (none / CTR / XTS).
- [x] **Phase 3: extraction + info/verify.** ExeFS/PFS0 and RomFS (IVFC) extraction,
  CNMT/NACP, `info`, `nca-extract`, `verify`.
- [x] **Phase 4: polish.** README, `scripts/smoke.py`, CLI help, last checks,
  private GitHub repo.

Each phase ends with `ruff check`, `ruff format --check`, `pytest` and a commit.

## Spec sources

Layouts were taken from, and cross-checked between, the read-only reference
implementations hactool (ISC) and libnintendo-hac / libnintendo-es (MIT). No code
was copied. Module docstrings name these as `Reference:`.

Switchbrew (XCI, HFS0/PFS0, NCA, RomFS, Ticket, CNMT, NACP) is the intended spec,
but it could not be reached from the development environment, so the code has
not yet been cross-checked against it. Docstrings list those pages as
`Intended spec (not yet cross-checked)`.

Not confirmed by the two reference implementations (handled defensively):

1. Ticket signature-type byte order (both orders accepted).
2. Newer NCA FS-header fields (compression info, metadata hash info, SHA3 hash
   types, "skip layer hash" encryption types). These are detected and reported as
   unsupported, never decoded.
3. XCI dumps with a 0x1000-byte key-area prefix (`HEAD` probed at 0x100 and 0x1100).
