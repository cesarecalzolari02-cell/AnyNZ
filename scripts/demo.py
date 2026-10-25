#!/usr/bin/env python3
"""Run every nx-decode command on a synthetic library, without a console or real keys.

    python scripts/demo.py [--keep DIR]

Builds a small fake library (a base game XCI, two updates with real BKTR sections,
two DLC and one DLC whose base is missing) with randomly generated keys, using the
same builders as the test suite, then runs ``info``, ``list``, ``verify``,
``nca-extract`` (with and without an update applied) and ``titles`` on it. Nothing
here is real Nintendo data. The files live in a temporary directory that is deleted
afterwards, unless ``--keep DIR`` is given (DIR must be outside the repository).
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from builders import (  # noqa: E402
    build_dlc,
    build_game,
    build_patch,
    build_pfs0,
    build_xci,
    write_keys_file,
)

from nx_decode.cli import main as nx_main  # noqa: E402

BASE = 0x0100DE0000010000
ORPHAN_BASE = 0x0100DE0000020000


def build_library(root: Path) -> Path:
    """Write the synthetic library under ``root``; return the keys file path."""
    game = build_game(title_id=BASE, rights_id=True)
    (root / "games").mkdir(parents=True)
    (root / "updates").mkdir()
    (root / "dlc").mkdir()
    (root / "games" / "base.xci").write_bytes(
        build_xci({"update": [], "normal": [], "secure": game.files})
    )
    for version in (0x10000, 0x20000):
        patch = build_patch(game.keys, BASE, version=version, base=game)
        (root / "updates" / f"update-v{version}.nsp").write_bytes(build_pfs0(patch.files))
    for index in (1, 2):
        dlc = build_dlc(game.keys, BASE, index=index)
        (root / "dlc" / f"dlc{index}.nsp").write_bytes(build_pfs0(dlc.files))
    orphan = build_dlc(game.keys, ORPHAN_BASE, index=1)
    (root / "dlc" / "orphan-dlc.nsp").write_bytes(build_pfs0(orphan.files))
    return write_keys_file(root / "synthetic.keys", game.keys)


def run(label: str, argv: list[str], expect: int) -> bool:
    print(f"\n=== {label} ===", flush=True)
    code = nx_main(argv)
    ok = code == expect
    print(f"--- exit {code}{'' if ok else f' (expected {expect})'}", flush=True)
    return ok


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--keep", metavar="DIR", help="build the library here and keep it")
    args = p.parse_args(argv)

    if args.keep:
        root = Path(args.keep).resolve()
        if root == ROOT or ROOT in root.parents:
            p.error("--keep must point outside the repository")
        if root.exists() and any(root.iterdir()):
            p.error(f"{root} is not empty")
    else:
        root = Path(tempfile.mkdtemp(prefix="nx-decode-demo-"))
    try:
        keys = ["--keys", str(build_library(root))]
        print(f"synthetic library (random keys, no real data) in {root}")
        base, upd = root / "games" / "base.xci", root / "updates" / "update-v131072.nsp"
        old_upd = root / "updates" / "update-v65536.nsp"
        dlc, out = root / "dlc" / "dlc1.nsp", root / "extracted"
        applied = ["--update", str(old_upd), "--update", str(upd), "-o", str(root / "patched")]
        results = [
            run("info: base game", ["info", *keys, str(base)], 0),
            run("info: update alone (BKTR needs --base)", ["info", *keys, str(upd)], 0),
            run(
                "verify: update against its base",
                ["verify", *keys, str(upd), "--base", str(base)],
                0,
            ),
            run("info: DLC", ["info", *keys, str(dlc)], 0),
            run("list", ["list", str(base)], 0),
            run("verify", ["verify", *keys, str(base)], 0),
            run("nca-extract: DLC", ["nca-extract", *keys, str(dlc), "-o", str(out)], 0),
            run(
                "nca-extract: update without --base (expected to skip)",
                ["nca-extract", *keys, str(upd), "-o", str(out)],
                1,
            ),
            run(
                "nca-extract: base game with the highest update applied",
                ["nca-extract", *keys, str(base), *applied],
                0,
            ),
            run("titles", ["titles", *keys, str(root)], 0),
        ]
    finally:
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)
    print(f"\n{sum(results)}/{len(results)} steps behaved as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
