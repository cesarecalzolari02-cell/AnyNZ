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

## Scope
- Local decrypt/extract only. Nothing in this project downloads anything (keys,
  firmware, games, title keys, updates), and nothing distributes keys, patches,
  signs or bypasses online checks.
- Personalized tickets, BKTR/patch NCAs, NSZ/XCZ, unknown key generations: report
  clearly as unsupported, don't crash.

## Repo
- The GitHub repo stays private. Only the owner decides whether to make it public.
- Work only inside this project folder.

## Workflow
- Work in the phases in `PLAN.md` and tick them off when done.
- After each phase: `ruff check .`, `ruff format --check .`, `pytest -q`, then commit.
- `scripts/check_forbidden.py` (pre-commit hook + CI) must pass. Enable the hook
  with `git config core.hooksPath .githooks`.
- Large files: always stream; never read a whole container into memory.
