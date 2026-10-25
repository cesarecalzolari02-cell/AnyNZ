"""Command-line interface: ``nx-decode {info,list,extract,nca-extract,verify,titles}``."""

from __future__ import annotations

import argparse
import io
import sys
from collections.abc import Sequence
from contextlib import ExitStack
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
from .errors import KeysError, NxError, OutputPathError
from .io import FileStorage, MemoryStorage, Storage, safe_join, write_entry
from .keys import Keyset
from .library import Library, scan
from .nca import DISTRIBUTION, ENC_NAMES, HASH_NAMES, Nca, Section
from .romfs import RomFS
from .title import NcaReport, TitleReport, inspect
from .update import Pairing, apply_base, choose_update, pair
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


def inspect_file(
    stack: ExitStack, path: str, keyset: Keyset | None, ticket: str | None = None
) -> TitleReport:
    """Open and inspect a file; it stays open until ``stack`` closes."""
    storage = stack.enter_context(FileStorage.open(path))
    return inspect(open_input(storage, path, ticket), keyset)


def with_base(
    stack: ExitStack, update: TitleReport, base_path: str | None, keyset: Keyset | None, name: str
) -> Pairing | None:
    """With ``--base``, pair the update with that base game so BKTR sections decode."""
    if not base_path:
        return None
    base = inspect_file(stack, base_path, keyset)
    pairing = pair(update, base, name, Path(base_path).name)
    apply_base(update, pairing, keyset)
    return pairing


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
        skipped = 0
        for f in selected:
            print(f"  {f.path} ({human(f.size)})")
            try:
                write_entry(f.storage, out, f.path)
            except OutputPathError as e:
                skipped += 1
                print(f"    skipped: {e}")
        print(f"extracted {len(selected) - skipped} files to {out}")
    if skipped:
        print(f"{skipped} file(s) could not be written (see above)", file=sys.stderr)
    return EXIT_ERROR if skipped else EXIT_OK


# ----------------------------------------------------------------------------- info


def _yesno(rep_ok: bool, problem: str) -> str:
    return "yes" if rep_ok else f"no: {problem}" if problem else "no"


def print_info(report: TitleReport, name: str, base_name: str = "") -> None:
    c = report.container
    print(f"File:     {name} ({c.kind})")
    if base_name:
        print(f"Base game: {base_name} (the update's BKTR sections read from it)")
    if c.kind == "XCI" and c.xci_header:
        print(f"Partitions: {', '.join(c.partitions)}")
    for m in report.metas:
        print()
        print(f"Title ID: {m.title_id:016x}")
        print(f"Type:     {m.type_name}")
        print(f"Version:  v{m.version}")
        if m.application_id is not None and m.application_id != m.title_id:
            print(f"Base title: {m.application_id:016x}")
        for info in m.meta_infos:
            print(f"Contains: {info.title_id:016x} v{info.version} ({info.type_name})")
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
    name = Path(args.file).name
    with ExitStack() as stack:
        report = inspect_file(stack, args.file, keyset, args.ticket)
        with_base(stack, report, args.base, keyset, name)
        if report.container.kind == "NCA" and report.ncas and report.ncas[0].nca:
            print_nca_header(report.ncas[0].nca)
            print()
        print_info(report, name, Path(args.base).name if args.base else "")
        return EXIT_OK if all(r.decrypts for r in report.ncas) else EXIT_ERROR


# ----------------------------------------------------------------------------- nca-extract


def extract_section(s: Section, out: Path, skipped: list[tuple[str, str]]) -> str:
    """Extract one section's files. Returns a one-line summary; files that can't be
    written under their name are added to ``skipped`` and the rest still extract."""
    before = len(skipped)
    if s.kind == "PFS0":
        pfs = PartitionFS.parse(s.data())
        names = {e.name for e in pfs.entries}
        label = "exefs" if "main.npdm" in names else "pfs0"
        dest = out / f"section{s.index}_{label}"
        dest.mkdir(parents=True, exist_ok=True)
        for e in pfs.entries:
            try:
                write_entry(pfs.open(e), dest, e.name)
            except OutputPathError as err:
                skipped.append((e.name, str(err)))
        count = len(pfs.entries) - (len(skipped) - before)
        summary = f"section {s.index}: {label}, {count} files -> {dest}"
    else:
        dest = out / f"section{s.index}_romfs"
        count, total = RomFS(s.data()).extract(dest, skipped)
        summary = f"section {s.index}: romfs, {count} files ({human(total)}) -> {dest}"
    if len(skipped) > before:
        summary += f", {len(skipped) - before} skipped"
    return summary


def nca_extract_jobs(
    stack: ExitStack, args: argparse.Namespace, keyset: Keyset
) -> tuple[list[tuple[NcaReport, str]], bool]:
    """The NCAs to extract, each with a label, and whether FILE is a standalone NCA.

    With ``--base`` or ``--update`` that is the updated title: the update's NCAs
    (BKTR sections patched from the base game) plus the base contents it keeps.
    """
    if args.base and args.update:
        raise NxError("give --base (FILE is the update) or --update (FILE is the base), not both")
    if args.update_version is not None and not args.update:
        raise NxError("--update-version chooses among the --update files")
    target = inspect_file(stack, args.file, keyset, args.ticket)
    standalone = target.container.kind == "NCA"
    if not (args.base or args.update):
        return [(rep, "") for rep in target.ncas], standalone
    if args.base:
        update, update_path = target, args.file
        base, base_path = inspect_file(stack, args.base, keyset), args.base
    else:
        updates = [(path, inspect_file(stack, path, keyset)) for path in args.update]
        update_path, update = choose_update(updates, args.update_version)
        base, base_path = target, args.file
    pairing = pair(update, base, Path(update_path).name, Path(base_path).name)
    apply_base(update, pairing, keyset)
    if pairing.patch_meta and pairing.base_meta:
        others = len(args.update or [])
        choice = f" (highest of {others})" if others > 1 and args.update_version is None else ""
        print(
            f"update v{pairing.patch_meta.version}{choice} from {update_path} "
            f"on base game {pairing.base_meta.title_id:016x} from {base_path}"
        )
    for note in update.notes:
        print(f"note: {note}")
    jobs = [(rep, "") for rep in update.ncas]
    return jobs + [(rep, " (kept from the base game)") for rep in pairing.base_only], standalone


def cmd_nca_extract(args: argparse.Namespace) -> int:
    keyset = load_keyset(args, required=True)
    assert keyset is not None
    out = Path(args.output)
    problems = 0
    with ExitStack() as stack:
        jobs, standalone = nca_extract_jobs(stack, args, keyset)
        if args.nca:
            jobs = [(r, lb) for r, lb in jobs if {r.file.name, r.file.path} & set(args.nca)]
            if not jobs:
                raise NxError(f"no NCA named {', '.join(args.nca)}")
        for rep, label in jobs:
            f = rep.file
            dest = out if standalone else safe_join(out, f.name.split(".")[0])
            print(f"{f.path}{label}:")
            if rep.nca is None:
                problems += 1
                print(f"  skipped: {rep.problem}")
                continue
            for s in rep.nca.sections:
                if args.section is not None and s.index != args.section:
                    continue
                try:
                    s.check_supported()
                    skipped: list[tuple[str, str]] = []
                    print("  " + extract_section(s, dest, skipped))
                    for path, reason in skipped:
                        print(f"    skipped file {path}: {reason}")
                    problems += len(skipped)
                except NxError as e:
                    problems += 1
                    print(f"  skipped section {s.index}: {e}")
    if problems:
        print(f"{problems} item(s) could not be extracted (see above)", file=sys.stderr)
    return EXIT_ERROR if problems else EXIT_OK


# ----------------------------------------------------------------------------- verify


def cmd_verify(args: argparse.Namespace) -> int:
    keyset = load_keyset(args, required=False)
    with ExitStack() as stack:
        report = inspect_file(stack, args.file, keyset, args.ticket)
        with_base(stack, report, args.base, keyset, Path(args.file).name)
        checks = verify_container(report.container, keyset, quick=args.quick, report=report)
    failed = skipped = 0
    for ch in checks:
        tag = "OK  " if ch.ok else "SKIP" if ch.ok is None else "FAIL"
        failed += ch.ok is False
        skipped += ch.ok is None
        detail = f" ({ch.detail})" if ch.detail else ""
        print(f"{tag} {ch.subject}: {ch.what}{detail}")
    print(f"{len(checks) - failed - skipped} ok, {failed} failed, {skipped} skipped")
    return EXIT_ERROR if failed else EXIT_OK


# ----------------------------------------------------------------------------- titles


def print_library(lib: Library) -> None:
    for aid in sorted(lib.titles):
        g = lib.titles[aid]
        print(f"{aid:016x}  {g.name or '(name unknown: no Control NCA found)'}")
        for s in g.base:
            print(f"  base:    v{s.cnmt.version:<10} {s.source}")
        if not g.base:
            print("  base:    (not found)")
        if latest := g.latest_update:
            extra = f" (highest of {len(g.updates)})" if len(g.updates) > 1 else ""
            print(f"  update:  v{latest.cnmt.version:<10} {latest.source}{extra}")
        for s in sorted(g.dlc, key=lambda s: (s.cnmt.title_id, s.cnmt.version)):
            print(f"  DLC:     {s.cnmt.title_id:016x} v{s.cnmt.version:<6} {s.source}")
        for s in g.other:
            print(f"  {s.cnmt.type_name}: {s.cnmt.title_id:016x} v{s.cnmt.version} {s.source}")
        for w in g.warnings:
            print(f"  warning: {w}")
    if lib.ungrouped:
        print("Not part of a title:")
        for s in lib.ungrouped:
            print(f"  {s.label()}  {s.source}")
            for info in s.cnmt.meta_infos:
                print(f"      contains {info.title_id:016x} v{info.version} ({info.type_name})")
    for e in lib.errors:
        print(f"error: {e}")
    updates = sum(1 for g in lib.titles.values() if g.updates)
    dlc = sum(len({s.cnmt.title_id for s in g.dlc}) for g in lib.titles.values())
    warnings = sum(len(g.warnings) for g in lib.titles.values())
    print(
        f"{len(lib.titles)} title(s), {updates} with updates, {dlc} DLC, "
        f"{warnings} warning(s), {len(lib.errors)} error(s)"
    )


def cmd_titles(args: argparse.Namespace) -> int:
    keyset = load_keyset(args, required=True)
    lib = scan(args.paths, keyset, open_input)
    print_library(lib)
    return EXIT_ERROR if lib.errors else EXIT_OK


# ----------------------------------------------------------------------------- parser


def update_version(text: str) -> int:
    """A CNMT version as ``titles`` prints it: ``65536``, ``v65536`` or ``0x10000``."""
    return int(text.lower().removeprefix("v"), 0)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--keys",
        metavar="PATH",
        help="your prod.keys (default: $SWITCH_KEYS, then ~/.switch/prod.keys)",
    )
    ticket = argparse.ArgumentParser(add_help=False)
    ticket.add_argument("--ticket", metavar="TIK", help="ticket for a standalone rights-ID .nca")
    base = argparse.ArgumentParser(add_help=False)
    base.add_argument(
        "--base",
        metavar="FILE",
        help="FILE is an update: decode its BKTR (patched RomFS) sections against this base game",
    )

    p = argparse.ArgumentParser(
        prog="nx-decode",
        description="Read and decrypt Switch XCI/NSP/NCA files you own, using your own keys. "
        "Nothing is downloaded; you supply your own keys and files.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--debug", action="store_true", help="show tracebacks for unexpected errors")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")

    s = sub.add_parser(
        "info", parents=[common, ticket, base], help="title, version, name and NCA status"
    )
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
        parents=[common, ticket, base],
        help="decrypt NCAs and extract ExeFS/PFS0/RomFS sections",
    )
    s.add_argument("file", help="NCA, or an XCI/NSP (all NCAs unless --nca is given)")
    s.add_argument("-o", "--output", required=True, help="output directory")
    s.add_argument("--nca", action="append", metavar="NAME", help="only this NCA (repeatable)")
    s.add_argument("--section", type=int, choices=range(4), help="only this section index")
    s.add_argument(
        "--update",
        action="append",
        metavar="FILE",
        help="FILE is the base game: extract it with this update applied "
        "(repeatable; the highest version is used)",
    )
    s.add_argument(
        "--update-version",
        type=update_version,
        metavar="N",
        help="with several --update files, use this version (e.g. 65536 or v65536)",
    )
    s.set_defaults(func=cmd_nca_extract)

    s = sub.add_parser(
        "verify", parents=[common, ticket, base], help="check hashes and content IDs"
    )
    s.add_argument("file")
    s.add_argument("--quick", action="store_true", help="skip full-data hashing")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser(
        "titles",
        parents=[common],
        help="group XCI/NSP/NCA files into titles: base, latest update, DLC",
    )
    s.add_argument(
        "paths", nargs="+", metavar="PATH", help="files or folders (searched recursively)"
    )
    s.set_defaults(func=cmd_titles)
    return p


def _tolerate_unencodable_output() -> None:
    """Print names the console can't encode as ``?`` instead of crashing.

    Redirected output on Windows uses the legacy code page (cp1252 and the like),
    which has no Japanese or Chinese title names.
    """
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="replace")


def main(argv: Sequence[str] | None = None) -> int:
    _tolerate_unencodable_output()
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
