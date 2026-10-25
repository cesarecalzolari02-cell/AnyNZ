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
- [x] **Phase 5a: title grouping and DLC.** CNMT extended headers (ApplicationId,
  PatchId) and content meta records, `titles` command (base, highest update, DLC;
  warnings for missing bases, several update versions, duplicates), DLC through
  the common-ticket path, synthetic base/patch/DLC tests. Patch (BKTR) decryption
  and personalized tickets stay unsupported.
- [x] **Dev setup for working without a console.** `DEVELOPMENT.md`,
  `scripts/demo.py` (all commands on a synthetic library), CI on Windows too.
- [x] **GitHub readiness and hardening** (before real files):
  - [x] Packaging: SPDX `license` + `license-files` (setuptools 77+; the table
    form stops building after 2027-02-18), Python 3.10-3.14 classifiers.
  - [x] CI: Python 3.14, current action versions, a `package` job (build sdist and
    wheel, forbidden-file check on the sdist, install the wheel, run it).
  - [x] Repo hygiene: `.gitattributes` (the shell hook keeps LF on Windows
    checkouts with `core.autocrlf`), `check_forbidden.py` reads only the start of
    each file or staged blob, an issue template that says never to attach keys or
    game files.
  - [x] Hardening: sanity limits on hash-layout fields (a corrupt IVFC block size
    must not allocate gigabytes), stream XCI HFS0 entry hashes and verify's hash
    tables, non-ASCII output on Windows legacy code pages, a seeded corruption test
    that runs every command and accepts only clean errors.
  - [x] Docs: `CHANGELOG.md`, publishing steps (private repo) in `DEVELOPMENT.md`.
  - [x] Owner: private GitHub repository created; `main` pushed with CI passing.
    The old local bundle remote is now called `bundle`.

**Phase 5: updates and DLC** (the owner's full spec; 5a above covered items 1, 2
and 4):

- [x] 1. CNMT of every content set; Application, Patch, AddOnContent grouped by the
  CNMT's ApplicationId; Delta and SystemUpdate listed only. (5a)
- [x] 2. `titles PATH...`: base, latest update, DLC; warnings for DLC or updates
  without their base and for several update versions. (5a)
- [x] 3. BKTR: bucket trees (relocation + subsection tables), AES-CTR-EX with the
  subsection generations, indirect storage routing reads to base or patch, the
  patched RomFS read as usual. `nca-extract --base FILE` / `--update FILE`
  (highest version unless `--update-version`), and `--base` for `info`/`verify`.
- [x] 4. DLC through the common-ticket path, extracted like any RomFS, listed in
  `info`. (5a; personalized DLC tickets come with item 5)
- [x] 5. Personalized tickets via `eticket_rsa_keypair` (RSA-2048-OAEP), with a
  clear message when it is missing.
- [x] 6. Synthetic base + patch pair with real BKTR tables, personalized tickets,
  README / supported table / CHANGELOG, hygiene checks.

**Phase 5c: hardening that needs no real files** (while Phase 6 waits for dumps):

- [x] BKTR tables with a second offset level (Atmosphère's layout), entry sets read
  on demand; tested with small nodes and one real-size 1.67-million-entry table.
- [x] Windows extraction: a file whose path Windows can't create is skipped and
  reported, and the rest of the RomFS still extracts; long paths via `\\?\`.

Next (not started):

- [ ] **Phase 6: real-file validation.** Blocked until the owner has keys dumped
  from their own console and their own dumps. Work through the checklist in
  `DEVELOPMENT.md` ("Waiting for real files") with `scripts/smoke.py`; turn every
  surprise into a synthetic regression test before fixing it.

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
