"""Inspect a container: tickets, NCAs, content metadata and control data.

Ties together :mod:`containers`, :mod:`ticket`, :mod:`nca`, :mod:`romfs` and
:mod:`meta` to answer "what is in this file and can my keys decrypt it?".
Problems with individual NCAs are recorded, not raised, so one bad or
unsupported NCA never hides the rest of the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .containers import Container, ContainerFile, PartitionFS, is_ncz
from .errors import MissingKeyError, MissingTicketError, NxError, UnsupportedError
from .keys import Keyset
from .meta import Cnmt, Nacp, parse_cnmt, parse_nacp
from .nca import Nca
from .romfs import RomFS
from .ticket import Ticket, parse_ticket


@dataclass
class NcaReport:
    file: ContainerFile
    nca: Nca | None = None
    decrypts: bool = False
    problem: str = ""  # why it doesn't (fully) decrypt
    # True if the problem means the file is bad, False if it is just unsupported/missing keys
    problem_is_failure: bool = False
    section_notes: list[str] = field(default_factory=list)

    @property
    def content_type(self) -> str:
        return self.nca.header.content_type_name if self.nca else "?"


@dataclass
class TitleReport:
    container: Container
    tickets: dict[bytes, Ticket]
    ncas: list[NcaReport]
    metas: list[Cnmt]
    nacps: dict[int, Nacp]  # by Control NCA title ID
    notes: list[str]

    def nacp_for(self, title_id: int) -> Nacp | None:
        return self.nacps.get(title_id)


def load_tickets(files: list[ContainerFile], notes: list[str]) -> dict[bytes, Ticket]:
    tickets: dict[bytes, Ticket] = {}
    for f in files:
        if not f.name.lower().endswith(".tik"):
            continue
        try:
            t = parse_ticket(f.storage.read_at(0, min(f.size, 0x1000)))
        except NxError as e:
            notes.append(f"{f.path}: {e}")
            continue
        tickets[t.rights_id] = t
    return tickets


def probe_nca(
    f: ContainerFile,
    keyset: Keyset | None,
    tickets: dict[bytes, Ticket],
    base: Nca | None = None,
) -> NcaReport:
    """Open one NCA and check that every supported section decrypts (master hashes match).

    ``base`` is the base game's NCA, for an update NCA with BKTR sections.
    """
    rep = NcaReport(f)
    if f.name.lower().endswith(".ncz") or is_ncz(f.storage):
        rep.problem = "NCZ (compressed NCA): not supported, decompress first"
        return rep
    try:
        rep.nca = Nca(f.storage, keyset, tickets, name=f.name, base=base)
        checked = 0
        for s in rep.nca.sections:
            if reason := s.unsupported_reason():
                rep.section_notes.append(f"section {s.index}: {reason}")
                continue
            if not s.check_master_hash():
                rep.problem = f"section {s.index} master hash mismatch (wrong key or corrupt)"
                rep.problem_is_failure = True
                return rep
            checked += 1
        rep.decrypts = checked > 0 or not rep.nca.sections
        if not rep.decrypts:
            rep.problem = "no section could be decoded"
    except (MissingKeyError, MissingTicketError, UnsupportedError) as e:
        rep.problem = str(e)
    except NxError as e:
        rep.problem = str(e)
        rep.problem_is_failure = True
    return rep


def read_cnmt(nca: Nca) -> Cnmt | None:
    for s in nca.sections:
        if s.kind != "PFS0" or s.unsupported_reason():
            continue
        pfs = PartitionFS.parse(s.data())
        for e in pfs.entries:
            if e.name.endswith(".cnmt"):
                return parse_cnmt(pfs.open(e).read_at(0, e.size))
    return None


def read_nacp(nca: Nca) -> Nacp | None:
    for s in nca.sections:
        if s.kind != "RomFS" or s.unsupported_reason():
            continue
        romfs = RomFS(s.data())
        f = romfs.find("control.nacp")
        return parse_nacp(romfs.open(f).read_at(0, f.size))
    return None


def inspect(container: Container, keyset: Keyset | None) -> TitleReport:
    notes: list[str] = []
    files = container.content_files()
    tickets = load_tickets(files, notes)
    ncas = [
        probe_nca(f, keyset, tickets)
        for f in files
        if Path(f.name).suffix.lower() in (".nca", ".ncz")
    ]
    metas: list[Cnmt] = []
    nacps: dict[int, Nacp] = {}
    for rep in ncas:
        if not (rep.nca and rep.decrypts):
            continue
        try:
            if rep.nca.header.content_type == 1 and (cnmt := read_cnmt(rep.nca)):
                metas.append(cnmt)
            elif rep.nca.header.content_type == 2 and (nacp := read_nacp(rep.nca)):
                nacps[rep.nca.header.title_id] = nacp
        except NxError as e:
            notes.append(f"{rep.file.path}: {e}")
    return TitleReport(container, tickets, ncas, metas, nacps, notes)
