"""Command-line interface: ``nx-decode {info,list,extract,nca-extract,verify}``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .containers import open_container
from .errors import NxError
from .io import FileStorage, safe_join

EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2


def human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    raise AssertionError("unreachable")


def cmd_list(args: argparse.Namespace) -> int:
    with FileStorage.open(args.file) as st:
        c = open_container(st, Path(args.file).name)
        print(f"{c.kind}: {len(c.files)} files")
        for f in c.files:
            print(f"  {f.size:>14,}  {f.path}")
    return EXIT_OK


def cmd_extract(args: argparse.Namespace) -> int:
    out = Path(args.output)
    with FileStorage.open(args.file) as st:
        c = open_container(st, Path(args.file).name)
        selected = [f for f in c.files if not args.partition or f.partition == args.partition]
        if args.partition and not selected:
            raise NxError(f"no files in partition {args.partition!r}")
        for f in selected:
            dest = safe_join(out, f.path)
            print(f"  {f.path} ({human(f.size)})")
            f.storage.copy_to(dest)
        print(f"extracted {len(selected)} files to {out}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nx-decode",
        description="Read and decrypt Switch XCI/NSP/NCA files you own, using your own keys.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--debug", action="store_true", help="show tracebacks for unexpected errors")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    s = sub.add_parser("list", help="list files inside an XCI or NSP")
    s.add_argument("file")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("extract", help="dump the files inside an XCI or NSP as-is")
    s.add_argument("file")
    s.add_argument("-o", "--output", required=True, help="output directory")
    s.add_argument("--partition", help="XCI only: just this partition (e.g. secure)")
    s.set_defaults(func=cmd_extract)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except NxError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as e:
        print(f"error: {e.strerror or e}: {e.filename or ''}".rstrip(": "), file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        if args.debug:
            raise
        print(f"internal error: {type(e).__name__}: {e} (rerun with --debug)", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
