#!/usr/bin/env python3
"""Refuse to commit anything that looks like a keys file or a Switch container.

Usage:
    check_forbidden.py FILE...      check these files on disk (pre-commit framework style)
    check_forbidden.py --staged     check the blobs staged in the git index (git hook)
    check_forbidden.py --all        check every tracked file (CI)

Exit status is 1 if anything is flagged. Offending lines are never printed, only
their file and line number, so a leaked key does not end up in CI logs.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

KEY_LINE = re.compile(rb"^\s*[A-Za-z0-9_]+\s*[=:]\s*(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{32})\s*$")

FORBIDDEN_SUFFIXES = {
    ".keys",
    ".xci",
    ".xcz",
    ".nsp",
    ".nsz",
    ".nca",
    ".ncz",
    ".tik",
    ".cert",
    ".cnmt",
    ".nacp",
}

# (offset, magic) pairs identifying Switch containers and NCAs.
MAGICS: list[tuple[int, bytes]] = [
    (0x0, b"PFS0"),
    (0x0, b"HFS0"),
    (0x100, b"HEAD"),
    (0x1100, b"HEAD"),
    (0x200, b"NCA3"),
    (0x200, b"NCA2"),
    (0x4000, b"NCZSECTN"),
]

MAX_SCAN = 4 * 1024 * 1024  # key lines are scanned in the first 4 MiB only


def problems(name: str, data: bytes) -> Iterator[str]:
    """Yield human-readable reasons why ``data`` (stored as ``name``) must not be committed."""
    suffix = Path(name).suffix.lower()
    if suffix in FORBIDDEN_SUFFIXES:
        yield f"{name}: forbidden file type '{suffix}'"
    for offset, magic in MAGICS:
        if data[offset : offset + len(magic)] == magic:
            yield f"{name}: looks like a Switch container ({magic.decode()} at {offset:#x})"
    for lineno, line in enumerate(data[:MAX_SCAN].splitlines(), start=1):
        if KEY_LINE.match(line):
            yield f"{name}:{lineno}: looks like a key entry (name = hex key)"


def _git(*args: str) -> bytes:
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def staged_files() -> Iterable[tuple[str, bytes]]:
    names = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split(b"\0")
    for raw in filter(None, names):
        name = raw.decode()
        yield name, _git("show", f":{name}")


def tracked_files() -> Iterable[tuple[str, bytes]]:
    for raw in filter(None, _git("ls-files", "-z").split(b"\0")):
        name = raw.decode()
        path = Path(name)
        if path.is_file():
            yield name, path.read_bytes()


def disk_files(paths: Iterable[str]) -> Iterable[tuple[str, bytes]]:
    for name in paths:
        path = Path(name)
        if path.is_file():
            yield name, path.read_bytes()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--staged", action="store_true", help="check staged blobs")
    group.add_argument("--all", action="store_true", help="check all tracked files")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args(argv)

    if args.staged:
        source = staged_files()
    elif args.all:
        source = tracked_files()
    else:
        source = disk_files(args.files)

    found = [msg for name, data in source for msg in problems(name, data)]
    for msg in found:
        print(f"forbidden: {msg}", file=sys.stderr)
    if found:
        print(
            "Refusing: keys and Switch container files must never be committed.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
