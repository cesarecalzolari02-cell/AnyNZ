# CLAUDE.md

Standing rules for working on nx-decode. These come from the project owner and
override convenience.

## Keys and game data
- Never open, read, cat, print or copy the owner's `prod.keys` (or any keys file).
  Only the tool's own code may read it, when the owner runs it.
- Never put real keys, titlekeys, tickets, certificates, firmware or game data
  (XCI/NSP/NCA/NSZ/XCZ, extracted files) in the repo, tests, fixtures, docs or
  commit messages. Do not store the owner's file paths or tool output in the repo.
- Tests use synthetic fixtures built at runtime with randomly generated keys
  (`tests/builders.py`). Never write a literal `name = <32/64 hex chars>` line.
- Errors may name a missing key, never show a key value.
- Decrypted title keys and the eticket keypair are key values too: never print,
  log or write them.

## Scope
- Local decrypt/extract only. Nothing in this project downloads anything (keys,
  firmware, games, title keys, updates), and nothing distributes keys, modifies or
  re-signs games, or bypasses online checks.
- Updates are applied locally: patch (BKTR) NCAs are decrypted and combined with a
  base game the owner supplies. Nothing is re-packed or written back.
- Personalized tickets are decrypted only with the `eticket_rsa_keypair` from the
  owner's own prod.keys. Without it, say so clearly.
- NSZ/XCZ, unknown key generations and unimplemented NCA features: report clearly
  as unsupported, don't crash.

## References
- Reading public specs (Switchbrew) and reference implementations (hactool,
  nxdumptool, ...) is fine, read-only. Keep fetched copies outside the repo and
  never run them. Never copy code.
- Docstrings say `Spec:` for what Switchbrew confirms and `Reference:` for what
  rests on implementations only; report anything no source confirms.

## Repo
- The GitHub repo stays private. Only the owner decides whether to make it public.
- Work only inside this project folder.
- Commit with the identity in this repo's git config; keep the
  `Co-Authored-By: Claude` trailer.

## Workflow
- Work in the phases in `PLAN.md` and tick them off when done.
- After each phase: `ruff check .`, `ruff format --check .`, `pytest -q`, then commit
  and push to `main`. Never force-push.
- Add user-visible changes to `CHANGELOG.md` under "Unreleased".
- `scripts/check_forbidden.py` (pre-commit hook + CI) must pass. Enable the hook
  with `git config core.hooksPath .githooks`.
- Large files: always stream; never read a whole container into memory.
- Real-file testing (Phase 6) uses only the owner's own dumps and keys: the owner
  runs `scripts/smoke.py` and shares its output.
