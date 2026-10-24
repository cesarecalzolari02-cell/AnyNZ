"""RomFS: the read-only filesystem in NCA RomFS sections (after the IVFC levels).

Spec: https://switchbrew.org/wiki/RomFS (cross-checked: hactool ``ivfc.h``,
libnintendo-hac ``romfs.h``).

Header (0x50 bytes): header size, then (offset, size) pairs for the directory hash
table, directory metadata table, file hash table and file metadata table, then the
file data offset. All offsets are relative to the RomFS start.

Directory entry: parent, sibling, first child, first file, hash-bucket next,
name length (u32 each), then the name, padded to 4 bytes.
File entry: parent, sibling (u32), data offset, size (u64), hash-bucket next,
name length (u32), then the name. ``0xFFFFFFFF`` means "none"; the root
directory is at offset 0 of the directory table.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .errors import FormatError
from .io import Storage, safe_join, u32, u64

HEADER_SIZE = 0x50
NONE = 0xFFFFFFFF
MAX_TABLE = 512 * 1024 * 1024


@dataclass(frozen=True)
class RomFile:
    path: str  # "/"-separated, relative to the RomFS root
    offset: int  # relative to the RomFS data region
    size: int


class RomFS:
    """A parsed RomFS image. Only the metadata tables are held in memory."""

    def __init__(self, storage: Storage) -> None:
        self.storage = storage
        if storage.size < HEADER_SIZE:
            raise FormatError("RomFS is too small")
        h = storage.read_at(0, HEADER_SIZE)
        if u64(h, 0) != HEADER_SIZE:
            raise FormatError("not a RomFS (bad header size)")
        dir_off, dir_size = u64(h, 0x18), u64(h, 0x20)
        file_off, file_size = u64(h, 0x38), u64(h, 0x40)
        self.data_offset = u64(h, 0x48)
        if dir_size > MAX_TABLE or file_size > MAX_TABLE:
            raise FormatError("RomFS metadata tables are implausibly large")
        self._dirs = storage.read_at(dir_off, dir_size)
        self._files = storage.read_at(file_off, file_size)

    @staticmethod
    def _name(table: bytes, off: int, fixed: int) -> str:
        n = u32(table, off + fixed - 4)
        raw = table[off + fixed : off + fixed + n]
        if len(raw) != n:
            raise FormatError("RomFS entry name runs past its table")
        return raw.decode("utf-8", errors="replace")

    def walk(self) -> Iterator[RomFile]:
        """Yield every file, depth first, with its full path."""
        seen_dirs: set[int] = set()
        stack: list[tuple[int, str]] = [(0, "")]
        while stack:
            d, prefix = stack.pop()
            if d in seen_dirs or d + 0x18 > len(self._dirs):
                raise FormatError("RomFS directory table is corrupt (loop or bad offset)")
            seen_dirs.add(d)
            f = u32(self._dirs, d + 0xC)
            seen_files: set[int] = set()
            while f != NONE:
                if f in seen_files or f + 0x20 > len(self._files):
                    raise FormatError("RomFS file table is corrupt (loop or bad offset)")
                seen_files.add(f)
                name = self._name(self._files, f, 0x20)
                yield RomFile(prefix + name, u64(self._files, f + 0x8), u64(self._files, f + 0x10))
                f = u32(self._files, f + 0x4)
            children = []
            c = u32(self._dirs, d + 0x8)
            while c != NONE:
                if c in seen_dirs or c + 0x18 > len(self._dirs) or len(children) > len(self._dirs):
                    raise FormatError("RomFS directory table is corrupt (loop or bad offset)")
                children.append((c, prefix + self._name(self._dirs, c, 0x18) + "/"))
                c = u32(self._dirs, c + 0x4)
            stack.extend(reversed(children))

    def open(self, f: RomFile) -> Storage:
        return self.storage.slice(self.data_offset + f.offset, f.size)

    def find(self, path: str) -> RomFile:
        path = path.lstrip("/")
        for f in self.walk():
            if f.path == path:
                return f
        raise FormatError(f"no file {path!r} in RomFS")

    def extract(self, out: Path) -> tuple[int, int]:
        """Write the tree under ``out``. Returns ``(files, bytes)``."""
        count = total = 0
        out.mkdir(parents=True, exist_ok=True)
        for f in self.walk():
            self.open(f).copy_to(safe_join(out, f.path))
            count += 1
            total += f.size
        return count, total
