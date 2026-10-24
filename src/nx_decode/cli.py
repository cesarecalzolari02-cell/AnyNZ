"""Command-line interface: ``nx-decode {info,list,extract,nca-extract,verify}``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .containers import (
    Container,
    ContainerFile,
    PartitionFS,
    check_not_compressed,
    open_container,
    sniff,
)
from .errors import KeysError, NxError
from .io import FileStorage, MemoryStorage, Storage, safe_join
from .keys import Keyset
from .nca import DISTRIBUTION, ENC_NAMES, HASH_NAMES, Nca, Section
from .romfs import RomFS
from .title import TitleReport, inspect, load_tickets
from .verify import verify_container

EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2


def human(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    raise AssertionError("unreachable")


def load_keyset(args: argparse.Namespace, required: bool) -> Keyset | None:
    try:
        return Keyset.load(args.keys)
    except KeysError as e:
        if required:
            raise
        print(f"warning: {e}; NCAs will not be decrypted", file=sys.stderr)
        return None


def open_input(storage: Storage, path: str, ticket: str | None = None) -> Container:
    """Open an XCI/NSP, or wrap a standalone NCA (plus optional ticket) as a container."""
    name = Path(path).name
    check_not_compressed(name)
    if sniff(storage) or not name.lower().endswith(".nca"):
        if ticket:
            raise NxError("--ticket is only used with a standalone .nca file")
        return open_container(storage, name)
    files = [ContainerFile(name, storage.size, storage)]
    if ticket:
        tik = Path(ticket).read_bytes()
        files.append(ContainerFile(Path(ticket).name, len(tik), MemoryStorage(tik)))
    return Container("NCA", storage, files)


# ----------------------------------------------------------------------------- list / extract


def cmd_list(args: argparse.Namespace) -> int:
    with FileStorage.open(args.file) as st:
        c = open_input(st, args.file)
        if c.kind == "NCA":
            return _list_nca(c.files[0], load_keyset(args, required=True))
        print(f"{c.kind}: {len(c.files)} files")
        for f in c.files:
            print(f"  {f.size:>14,}  {f.path}")
    return EXIT_OK


def _list_nca(f: ContainerFile, keyset: Keyset | None) -> int:
    nca = Nca(f.storage, keyset, name=f.name)
    for s in nca.sections:
        print(f"section {s.index} ({s.kind}, {human(s.size)})")
        if reason := s.unsupported_reason():
            print(f"  [unsupported: {reason}]")
        elif s.kind == "PFS0":
            for e in PartitionFS.parse(s.data()).entries:
                print(f"  {e.size:>14,}  {e.name}")
        else:
            for rf in RomFS(s.data()).walk():
                print(f"  {rf.size:>14,}  {rf.path}")
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


# ----------------------------------------------------------------------------- info


def _yesno(rep_ok: bool, problem: str) -> str:
    return "yes" if rep_ok else f"no: {problem}" if problem else "no"


def print_info(report: TitleReport, name: str) -> None:
    c = report.container
    print(f"File:     {name} ({c.kind})")
    if c.kind == "XCI" and c.xci_header:
        print(f"Partitions: {', '.join(c.partitions)}")
    for m in report.metas:
        print()
        print(f"Title ID: {m.title_id:016x}")
        print(f"Type:     {m.type_name}")
        print(f"Version:  v{m.version}")
        nacp = report.nacp_for(m.title_id)
        if nacp:
            title, publisher = nacp.preferred()
            print(f"Name:     {title}")
            print(f"Publisher: {publisher}")
            if nacp.display_version:
                print(f"Display version: {nacp.display_version}")
        else:
            print("Name:     (no Control NCA for this title; DLC and some updates have none)")
    if not report.metas:
        print("Title:    (no readable content metadata)")
    print()
    print("NCAs:")
    for rep in report.ncas:
        nca = rep.nca
        tid = f"{nca.header.title_id:016x}" if nca else "-"
        gen = str(nca.header.key_generation) if nca else "-"
        print(f"  {rep.file.path}")
        print(
            f"      type {rep.content_type}, size {human(rep.file.size)}, "
            f"title {tid}, key generation {gen}"
        )
        print(f"      decrypts with your keys: {_yesno(rep.decrypts, rep.problem)}")
        for note in rep.section_notes:
            print(f"      note: {note}")
    if report.tickets:
        kinds = ["personalized" if t.is_personalized else "common" for t in report.tickets.values()]
        print(f"Tickets:  {len(kinds)} ({', '.join(sorted(set(kinds)))})")
    for note in report.notes:
        print(f"note: {note}")


def print_nca_header(nca: Nca) -> None:
    h = nca.header
    print(f"NCA:      {h.magic}{' (plaintext header)' if nca.plaintext else ''}")
    print(f"Title ID: {h.title_id:016x}")
    print(f"Content:  {h.content_type_name}, {DISTRIBUTION.get(h.distribution, h.distribution)}")
    print(f"Key generation: {h.key_generation} (master key revision {h.master_key_revision})")
    print(f"Rights ID: {h.rights_id.hex() if h.has_rights_id else 'none'}")
    for s in nca.sections:
        enc = ENC_NAMES.get(s.fs.encryption_type, str(s.fs.encryption_type))
        hsh = HASH_NAMES.get(s.fs.hash_type, str(s.fs.hash_type))
        print(f"  section {s.index}: {s.kind}, {human(s.size)}, {enc}, {hsh}")


def cmd_info(args: argparse.Namespace) -> int:
    keyset = load_keyset(args, required=False)
    with FileStorage.open(args.file) as st:
        c = open_input(st, args.file, args.ticket)
        report = inspect(c, keyset)
        if c.kind == "NCA" and report.ncas and report.ncas[0].nca:
            print_nca_header(report.ncas[0].nca)
            print()
        print_info(report, Path(args.file).name)
        return EXIT_OK if all(r.decrypts for r in report.ncas) else EXIT_ERROR


# ----------------------------------------------------------------------------- nca-extract


def extract_section(s: Section, out: Path) -> str:
    """Extract one section's files. Returns a one-line summary."""
    if s.kind == "PFS0":
        pfs = PartitionFS.parse(s.data())
        names = {e.name for e in pfs.entries}
        label = "exefs" if "main.npdm" in names else "pfs0"
        dest = out / f"section{s.index}_{label}"
        dest.mkdir(parents=True, exist_ok=True)
        for e in pfs.entries:
            pfs.open(e).copy_to(safe_join(dest, e.name))
        return f"section {s.index}: {label}, {len(pfs.entries)} files -> {dest}"
    dest = out / f"section{s.index}_romfs"
    count, total = RomFS(s.data()).extract(dest)
    return f"section {s.index}: romfs, {count} files ({human(total)}) -> {dest}"


def cmd_nca_extract(args: argparse.Namespace) -> int:
    keyset = load_keyset(args, required=True)
    out = Path(args.output)
    problems = 0
    with FileStorage.open(args.file) as st:
        c = open_input(st, args.file, args.ticket)
        files = c.content_files()
        tickets = load_tickets(files, [])
        ncas = [f for f in files if f.name.lower().endswith(".nca")]
        if args.nca:
            ncas = [f for f in ncas if f.name in args.nca or f.path in args.nca]
            if not ncas:
                raise NxError(f"no NCA named {', '.join(args.nca)}")
        for f in ncas:
            dest = out if c.kind == "NCA" else safe_join(out, f.name.split(".")[0])
            print(f"{f.path}:")
            try:
                nca = Nca(f.storage, keyset, tickets, name=f.name)
                sections = [
                    s for s in nca.sections if args.section is None or s.index == args.section
                ]
                for s in sections:
                    try:
                        s.check_supported()
                        print("  " + extract_section(s, dest))
                    except NxError as e:
                        problems += 1
                        print(f"  skipped section {s.index}: {e}")
            except NxError as e:
                problems += 1
                print(f"  skipped: {e}")
    if problems:
        print(f"{problems} item(s) could not be extracted (see above)", file=sys.stderr)
    return EXIT_ERROR if problems else EXIT_OK


# ----------------------------------------------------------------------------- verify


def cmd_verify(args: argparse.Namespace) -> int:
    keyset = load_keyset(args, required=False)
    with FileStorage.open(args.file) as st:
        c = open_input(st, args.file, args.ticket)
        checks = verify_container(c, keyset, quick=args.quick)
    failed = skipped = 0
    for ch in checks:
        tag = "OK  " if ch.ok else "SKIP" if ch.ok is None else "FAIL"
        failed += ch.ok is False
        skipped += ch.ok is None
        detail = f" ({ch.detail})" if ch.detail else ""
        print(f"{tag} {ch.subject}: {ch.what}{detail}")
    print(f"{len(checks) - failed - skipped} ok, {failed} failed, {skipped} skipped")
    return EXIT_ERROR if failed else EXIT_OK


# ----------------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--keys",
        metavar="PATH",
        help="your prod.keys (default: $SWITCH_KEYS, then ~/.switch/prod.keys)",
    )
    ticket = argparse.ArgumentParser(add_help=False)
    ticket.add_argument("--ticket", metavar="TIK", help="ticket for a standalone rights-ID .nca")

    p = argparse.ArgumentParser(
        prog="nx-decode",
        description="Read and decrypt Switch XCI/NSP/NCA files you own, using your own keys. "
        "Nothing is downloaded; you supply your own keys and files.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--debug", action="store_true", help="show tracebacks for unexpected errors")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    s = sub.add_parser("info", parents=[common, ticket], help="title, version, name and NCA status")
    s.add_argument("file", help="XCI, NSP or NCA")
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("list", parents=[common], help="list files inside an XCI/NSP (or NCA)")
    s.add_argument("file")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("extract", help="dump the files inside an XCI or NSP as-is")
    s.add_argument("file")
    s.add_argument("-o", "--output", required=True, help="output directory")
    s.add_argument("--partition", help="XCI only: just this partition (e.g. secure)")
    s.set_defaults(func=cmd_extract)

    s = sub.add_parser(
        "nca-extract",
        parents=[common, ticket],
        help="decrypt NCAs and extract ExeFS/PFS0/RomFS sections",
    )
    s.add_argument("file", help="NCA, or an XCI/NSP (all NCAs unless --nca is given)")
    s.add_argument("-o", "--output", required=True, help="output directory")
    s.add_argument("--nca", action="append", metavar="NAME", help="only this NCA (repeatable)")
    s.add_argument("--section", type=int, choices=range(4), help="only this section index")
    s.set_defaults(func=cmd_nca_extract)

    s = sub.add_parser("verify", parents=[common, ticket], help="check hashes and content IDs")
    s.add_argument("file")
    s.add_argument("--quick", action="store_true", help="skip full-data hashing")
    s.set_defaults(func=cmd_verify)
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
