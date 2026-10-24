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
was copied.

They were then checked against Switchbrew (XCI, NCA incl. PartitionFS, Ticket,
CNMT, NCM services, NACP). Docstrings say `Spec:` for what the wiki confirmed and
`Reference:` for what relies on the implementations only. The wiki check found and
fixed: the CNMT content size (5 bytes on 15.0.0+), undetected metadata hash info
in NCA FS headers, and the missing HMAC ticket signature type.

Not documented on Switchbrew (reference implementations only): RomFS layout,
the AES-CTR counter, key derivation, the IVFC level count, NCA content ID, and the
base of the XCI HFS0 address.

The three formerly unconfirmed details:

1. Ticket signature-type byte order: still unconfirmed (both orders accepted).
2. Newer NCA FS-header fields (sparse, compression, metadata hash info, SHA3 hash
   types, skip-layer-hash encryption types): confirmed; detected and reported as
   unsupported, never decoded.
3. XCI dumps with a 0x1000-byte key-area prefix: confirmed (`HEAD` at 0x100 or
   0x1100).
