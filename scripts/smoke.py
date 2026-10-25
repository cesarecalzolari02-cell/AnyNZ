#!/usr/bin/env python3
"""Smoke-test nx-decode on your own files, locally.

    python scripts/smoke.py KEYS FILE [--base BASE] [--full] [--extract]

Runs ``info``, ``list``, ``verify --quick`` (``--full`` for the full hash
check) and ``titles`` on FILE using the keys file KEYS. With ``--extract``, also runs
``nca-extract`` into a temporary directory outside the repository and deletes
it afterwards, reporting only file counts. When FILE is an update, ``--base BASE``
(your dump of the base game) applies it: ``verify --full --base`` checks the whole
patched RomFS against the update's hash tree.

Everything is printed to the terminal. Nothing (paths, output, keys) is written
to the repository or anywhere else, and key values are never printed.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nx_decode.cli import main as nx_main


def run(label: str, argv: list[str]) -> int:
    print(f"\n=== {label} ===", flush=True)
    start = time.monotonic()
    code = nx_main(argv)
    print(f"--- exit {code} in {time.monotonic() - start:.1f}s", flush=True)
    return code


def count_files(root: Path) -> tuple[int, int]:
    files = [p for p in root.rglob("*") if p.is_file()]
    return len(files), sum(p.stat().st_size for p in files)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("keys", help="path to your prod.keys")
    p.add_argument("file", help="an XCI, NSP or NCA you own")
    p.add_argument("--base", help="the base game, when FILE is an update")
    p.add_argument("--full", action="store_true", help="full verify (hashes every byte)")
    p.add_argument("--extract", action="store_true", help="also test nca-extract (temp dir)")
    args = p.parse_args()

    keys, target = ["--keys", args.keys], args.file
    base = ["--base", args.base] if args.base else []
    quick = [] if args.full else ["--quick"]
    results = {
        "info": run("info", ["info", *keys, target, *base]),
        "list": run("list", ["list", *keys, target]),
        "verify": run("verify", ["verify", *keys, target, *base, *quick]),
        "titles": run("titles", ["titles", *keys, target, *base[1:]]),
    }
    if args.extract:
        tmp = Path(tempfile.mkdtemp(prefix="nx-decode-smoke-"))
        try:
            out = io.StringIO()
            print("\n=== nca-extract (to a temporary directory, deleted afterwards) ===")
            with contextlib.redirect_stdout(out):
                code = nx_main(["nca-extract", *keys, target, *base, "-o", str(tmp)])
            skipped = [line.strip() for line in out.getvalue().splitlines() if "skipped" in line]
            n, total = count_files(tmp)
            print(f"extracted {n} files, {total:,} bytes; exit {code}")
            for line in skipped:
                print(f"  {line}")
            results["nca-extract"] = code
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print("\n=== summary ===")
    for name, code in results.items():
        print(f"  {name:12} {'ok' if code == 0 else f'exit {code}'}")
    return 0 if all(c == 0 for c in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
