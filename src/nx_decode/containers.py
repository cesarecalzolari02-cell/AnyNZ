"""PFS0 / HFS0 partition filesystems, and the XCI and NSP containers built on them.

* PFS0 and HFS0: https://switchbrew.org/wiki/NCA#PFS0 and
  https://switchbrew.org/wiki/XCI#Hash_File_System_.28HFS0.29
  (cross-checked: hactool ``pfs0.h``/``hfs0.h``, libnintendo-hac ``pfs.h``).
* XCI (gamecard image): https://switchbrew.org/wiki/XCI
  (cross-checked: hactool ``xci.h``/``xci.c``, libnintendo-hac ``gc.h``).
* NSP is a plain PFS0 holding NCAs, tickets and certificates.

Compressed variants (NSZ/XCZ, NCZ entries) are detected and reported, not decoded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .errors import FormatError, UnsupportedError
from .io import Storage, cstr, u32, u64

PFS0_MAGIC = b"PFS0"
HFS0_MAGIC = b"HFS0"
XCI_MAGIC = b"HEAD"
NCZ_MAGIC = b"NCZSECTN"
NCZ_MAGIC_OFFSET = 0x4000

PFS0_ENTRY_SIZE = 0x18
HFS0_ENTRY_SIZE = 0x40
MAX_ENTRIES = 0x10000
MAX_STRING_TABLE = 0x100000

XCI_HEADER_OFFSETS = (0x0, 0x1000)  # plain card header, or after a 0x1000-byte key area
XCI_PARTITIONS = ("update", "normal", "secure", "logo")

COMPRESSED_SUFFIXES = {".nsz": "NSZ", ".xcz": "XCZ", ".ncz": "NCZ"}


@dataclass
class PartitionEntry:
    """One file inside a PFS0/HFS0. ``offset`` is relative to the partition start."""

    name: str
    offset: int
    size: int
    hashed_size: int = 0
    hash: bytes = b""


@dataclass
class PartitionFS:
    """A parsed PFS0 or HFS0 ("partition filesystem")."""

    storage: Storage
    kind: str
    header_size: int
    entries: list[PartitionEntry]

    @classmethod
    def parse(cls, storage: Storage, expect: bytes | None = None) -> PartitionFS:
        head = storage.read_at(0, 0x10) if storage.size >= 0x10 else b""
        magic = head[:4]
        if magic not in (PFS0_MAGIC, HFS0_MAGIC) or (expect and magic != expect):
            want = (expect or b"PFS0/HFS0").decode()
            raise FormatError(f"not a {want} partition (bad magic)")
        count, strtab_size = u32(head, 4), u32(head, 8)
        if count > MAX_ENTRIES or strtab_size > MAX_STRING_TABLE:
            raise FormatError(f"implausible {magic.decode()} header ({count} entries)")
        esize = HFS0_ENTRY_SIZE if magic == HFS0_MAGIC else PFS0_ENTRY_SIZE
        header_size = 0x10 + count * esize + strtab_size
        table = storage.read_at(0x10, count * esize + strtab_size)
        strtab = table[count * esize :]
        entries = []
        for i in range(count):
            e = table[i * esize : (i + 1) * esize]
            name_off = u32(e, 0x10)
            if name_off >= max(strtab_size, 1):
                raise FormatError(f"{magic.decode()} entry {i} has a bad name offset")
            entry = PartitionEntry(name=cstr(strtab, name_off), offset=u64(e, 0), size=u64(e, 8))
            if magic == HFS0_MAGIC:
                entry.hashed_size = u32(e, 0x14)
                entry.hash = e[0x20:0x40]
            if header_size + entry.offset + entry.size > storage.size:
                raise FormatError(f"{entry.name!r} extends past the end of the partition")
            entries.append(entry)
        return cls(storage, magic.decode(), header_size, entries)

    def open(self, entry: PartitionEntry | str) -> Storage:
        """Return a storage over one entry's data."""
        if isinstance(entry, str):
            entry = self.find(entry)
        return self.storage.slice(self.header_size + entry.offset, entry.size)

    def find(self, name: str) -> PartitionEntry:
        for e in self.entries:
            if e.name == name:
                return e
        raise FormatError(f"no file named {name!r} in {self.kind}")


@dataclass
class XciHeader:
    """The gamecard header fields nx-decode needs (https://switchbrew.org/wiki/XCI#CardHeader)."""

    base: int  # 0, or 0x1000 if the dump starts with the key area
    rom_size: int
    root_offset: int
    root_header_size: int
    root_header_hash: bytes


def parse_xci_header(storage: Storage) -> XciHeader:
    for base in XCI_HEADER_OFFSETS:
        if storage.size >= base + 0x200 and storage.read_at(base + 0x100, 4) == XCI_MAGIC:
            h = storage.read_at(base, 0x200)
            return XciHeader(
                base=base,
                rom_size=h[0x10D],
                root_offset=u64(h, 0x130),
                root_header_size=u64(h, 0x138),
                root_header_hash=h[0x140:0x160],
            )
    raise FormatError("not an XCI (no 'HEAD' card header)")


@dataclass
class ContainerFile:
    """A file inside a container, with its display path (``secure/abc.nca`` for XCIs)."""

    path: str
    size: int
    storage: Storage
    partition: str = ""
    entry: PartitionEntry | None = None

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass
class Container:
    """An opened XCI or NSP."""

    kind: str  # "XCI" or "NSP"
    storage: Storage
    files: list[ContainerFile]
    xci_header: XciHeader | None = None
    root: PartitionFS | None = None
    partitions: dict[str, PartitionFS] = field(default_factory=dict)

    def content_files(self) -> list[ContainerFile]:
        """Files that make up the title: the NSP root, or the XCI ``secure`` partition."""
        if self.kind == "XCI":
            return [f for f in self.files if f.partition == "secure"]
        return list(self.files)


def check_not_compressed(name: str) -> None:
    kind = COMPRESSED_SUFFIXES.get(Path(name).suffix.lower())
    if kind:
        raise UnsupportedError(
            f"{name}: {kind} files are compressed; decompress to "
            f"{'XCI' if kind == 'XCZ' else 'NSP/NCA'} first (nx-decode does not decompress)"
        )


def is_ncz(storage: Storage) -> bool:
    end = NCZ_MAGIC_OFFSET + len(NCZ_MAGIC)
    return storage.size >= end and storage.read_at(NCZ_MAGIC_OFFSET, len(NCZ_MAGIC)) == NCZ_MAGIC


def sniff(storage: Storage) -> str:
    """Guess the container type from magic bytes: ``"NSP"``, ``"XCI"`` or ``""``."""
    if storage.size >= 4 and storage.read_at(0, 4) == PFS0_MAGIC:
        return "NSP"
    for base in XCI_HEADER_OFFSETS:
        if storage.size >= base + 0x104 and storage.read_at(base + 0x100, 4) == XCI_MAGIC:
            return "XCI"
    return ""


def open_container(storage: Storage, name: str = "") -> Container:
    """Open an XCI or NSP, choosing by magic bytes."""
    if name:
        check_not_compressed(name)
    kind = sniff(storage)
    if kind == "NSP":
        pfs = PartitionFS.parse(storage, PFS0_MAGIC)
        files = [ContainerFile(e.name, e.size, pfs.open(e), entry=e) for e in pfs.entries]
        return Container("NSP", storage, files, root=pfs)
    if kind == "XCI":
        return _open_xci(storage)
    raise FormatError(f"{name or 'file'}: not an XCI or NSP (unrecognised magic)")


def _open_xci(storage: Storage) -> Container:
    header = parse_xci_header(storage)
    root_off = header.base + header.root_offset
    if root_off >= storage.size:
        raise FormatError("XCI root partition offset is past the end of the file (trimmed dump?)")
    root = PartitionFS.parse(storage.slice(root_off, storage.size - root_off), HFS0_MAGIC)
    partitions: dict[str, PartitionFS] = {}
    files: list[ContainerFile] = []
    for entry in root.entries:
        if entry.size == 0:
            partitions[entry.name] = PartitionFS(root.open(entry), "HFS0", 0, [])
            continue
        part = PartitionFS.parse(root.open(entry), HFS0_MAGIC)
        partitions[entry.name] = part
        for e in part.entries:
            files.append(
                ContainerFile(f"{entry.name}/{e.name}", e.size, part.open(e), entry.name, e)
            )
    return Container("XCI", storage, files, header, root, partitions)
