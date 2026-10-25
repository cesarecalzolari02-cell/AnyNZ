# Developing nx-decode

Everything here works **without a modded console, real keys or game files**. The
test suite and `scripts/demo.py` build synthetic XCI/NSP/NCA files with randomly
generated keys at runtime. Real files are only needed for the checks listed under
[Waiting for real files](#waiting-for-real-files).

Read `CLAUDE.md` (standing rules) and `PLAN.md` (phases) first.

## Setup

Python 3.10 or newer.

```powershell
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip   # pip < 21.3 can't do editable installs here
.venv\Scripts\python -m pip install -e ".[dev]"
git config core.hooksPath .githooks                 # pre-commit safety check
```

```sh
# Linux / macOS
python3 -m venv .venv && . .venv/bin/activate
pip install --upgrade pip && pip install -e ".[dev]"
git config core.hooksPath .githooks
```

The hook runs `scripts/check_forbidden.py --staged` with `python3`. If `python3`
is not on your PATH (some Windows installs), activate the venv before committing.

## Day-to-day loop

```sh
ruff check . && ruff format --check . && pytest -q   # what CI runs (Ubuntu and Windows)
python scripts/demo.py                              # every command on a fake library
python scripts/demo.py --keep ../nx-demo            # same, but keep the files to poke at
```

`--keep` refuses folders inside the repository, so synthetic containers never end
up next to the code (the forbidden-file check would reject them anyway).

## Layout

| Module | What it does |
| --- | --- |
| `io.py` | `Storage`: streamed, nestable random-access reads (file, slice, decrypted section) |
| `crypto.py` | AES-ECB / XTS (Nintendo tweak) / CTR on top of `cryptography` |
| `keys.py` | parse a `prod.keys`, derive missing keys; never formats key values |
| `containers.py` | PFS0, HFS0, XCI, NSP; NSZ/XCZ/NCZ detection |
| `nca.py` | NCA header decryption, key selection, sections, hash layouts, "unsupported" reasons |
| `ticket.py` | common tickets (title key unwrapping input) |
| `romfs.py` | RomFS walk / extract |
| `meta.py` | CNMT (incl. extended headers) and NACP |
| `title.py` | `inspect()`: one container -> NCAs, tickets, CNMTs, NACPs |
| `library.py` | `scan()`: many files -> titles (base, updates, DLC) and warnings |
| `verify.py` | hash and content-ID checks |
| `cli.py` | the `nx-decode` commands |

`tests/builders.py` holds the synthetic builders. They implement the encryption
side independently of `nx_decode`, so tests check the decoder against a separate
implementation of the format.

## Conventions

- **Spec vs Reference.** A docstring says `Spec:` only for layouts checked against
  the Switchbrew wiki, and `Reference:` for what relies on hactool / libnintendo
  only. When you check something new against the wiki, move it from one to the
  other and update the README's "Specification sources".
- **Unsupported, not crashed.** Anything the tool can't decode (BKTR, personalized
  tickets, SHA3 layers, compressed files, unknown key generations) gets a clear
  reason via `Section.unsupported_reason()` or an `UnsupportedError`. Corrupt
  input raises a `FormatError`; `tests/test_robustness.py` runs corrupted
  synthetic files through every command and fails on anything that escapes as
  an "internal error". Size fields from a file are bounded before they are used
  to allocate (see `MAX_HASH_BLOCK` in `nca.py`).
- **Stream.** Never read a whole container into memory; go through `Storage`.
- **No key material in output.** Errors may name a key, never show its value.
  Tests assert this for the CLI.
- **Tests are synthetic.** Never add a real file, and never write a literal
  `name = <32/64 hex>` line (the forbidden-file check rejects it). Use
  `rand_key()` and the builders; add a builder option when you need a new field.
- **Small commits**, each with `ruff check`, `ruff format --check` and `pytest`
  passing.

## Publishing to GitHub

The repository stays **private**. Only the owner decides whether it ever becomes
public.

1. On GitHub, create an empty **private** repository (no README, license or
   `.gitignore`; the repository already has them).
2. Keep the old bundle remote under another name, add GitHub as `origin`, push:

   ```sh
   git remote rename origin bundle
   git remote add origin https://github.com/OWNER/nx-decode.git
   git push -u origin main
   ```

3. In the Actions tab, `forbidden-files`, `test` (Ubuntu and Windows) and
   `package` must pass. Optionally protect `main` and require them.

With the hook enabled (`git config core.hooksPath .githooks`), every commit has
already passed `check_forbidden.py`. CI runs it again on the whole tree and on the
built packages.

## Waiting for real files

These behave correctly on synthetic data, but the synthetic data was built from
the same understanding of the format, so only real files can confirm them. When
you have keys dumped from your own console, run `scripts/smoke.py` (it prints to
the terminal only) and check:

1. **Key derivation** from `master_key_XX` + `*_source` seeds (no Switchbrew page).
2. **AES-CTR section counter** (FS header 0x140, byte-reversed, then offset >> 4).
3. **RomFS layout** (no Switchbrew page): a full `nca-extract` of a real game.
4. **Ticket signature type byte order** (both orders are accepted today).
5. **XCI `PartitionFsHeaderAddress` base**, and dumps with/without the key area.
6. **CNMT file order** and the **content ID = first 16 bytes of the SHA-256** rule
   (`verify` reports both).
7. **DLC NCA content type** (the builders use Data; real DLC may use PublicData;
   the code does not depend on it).
8. **NACP languages 16/17** (Polish, Thai on 21.0.0+): where they live is unclear.
9. **`titles` speed** on a large XCI (it reads only headers, top-level hashes and
   the small CNMT/NACP files).
10. **Extraction on Windows:** RomFS paths longer than 260 characters (they need
    long paths enabled in Windows) and file names with characters Windows forbids
    (`<>:"|?*`). Today a path Windows can't create stops `nca-extract` with an OS
    error, and a `:` skips the whole section.

If one of these turns out wrong, reproduce it with a synthetic fixture first, then
fix the code, so the regression test exists without the real file.

Dump keys from your own console only, keep the keys file outside the repository
(`~/.switch/prod.keys` is the default location), and never paste key values into
issues, commits or chat.
