"""Random-access byte sources that never load whole files into memory.

Every layer (file, container entry, decrypted NCA section, RomFS file) is a
:class:`Storage`: something with a ``size`` and a ``read_at(offset, size)``.
Layers nest by wrapping a parent storage, so a file inside a RomFS inside an
NCA inside an XCI is read by translating offsets down the stack, a chunk at a
time.
"""

from __future__ import annotations

import errno
import hashlib
import os
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from .errors import FormatError, OutputPathError

CHUNK = 1024 * 1024
WINDOWS = os.name == "nt"
WINDOWS_FORBIDDEN = frozenset('<>:"|?*') | frozenset(map(chr, range(32)))
WINDOWS_DEVICES = frozenset(
    [
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    ]
)
# Write errors that would hit every following file too: stop instead of skipping.
FATAL_WRITE_ERRORS = frozenset({errno.ENOSPC, errno.EROFS, getattr(errno, "EDQUOT", errno.ENOSPC)})


class Storage(ABC):
    """A fixed-size, random-access, read-only byte source."""

    size: int

    @abstractmethod
    def _read(self, offset: int, size: int) -> bytes:
        """Read exactly ``size`` bytes at ``offset``; bounds are already checked."""

    def read_at(self, offset: int, size: int) -> bytes:
        """Read ``size`` bytes at ``offset``, raising :class:`FormatError` if out of bounds."""
        if offset < 0 or size < 0 or offset + size > self.size:
            raise FormatError(
                f"read of {size:#x} bytes at {offset:#x} is outside the "
                f"{self.size:#x}-byte {self.describe()}"
            )
        if size == 0:
            return b""
        return self._read(offset, size)

    def describe(self) -> str:
        return "region"

    def slice(self, offset: int, size: int) -> SubStorage:
        """Return a view of ``size`` bytes starting at ``offset``."""
        return SubStorage(self, offset, size)

    def iter_chunks(self, offset: int = 0, size: int | None = None) -> Iterator[bytes]:
        """Yield the given range in chunks of at most :data:`CHUNK` bytes."""
        end = self.size if size is None else offset + size
        pos = offset
        while pos < end:
            n = min(CHUNK, end - pos)
            yield self.read_at(pos, n)
            pos += n

    def sha256(self, offset: int = 0, size: int | None = None) -> bytes:
        h = hashlib.sha256()
        for chunk in self.iter_chunks(offset, size):
            h.update(chunk)
        return h.digest()


class FileStorage(Storage):
    """A storage backed by an open binary file."""

    def __init__(self, fp: BinaryIO, name: str = "file") -> None:
        self._fp = fp
        self.name = name
        fp.seek(0, os.SEEK_END)
        self.size = fp.tell()

    @classmethod
    def open(cls, path: str | Path) -> FileStorage:
        return cls(open(path, "rb"), name=Path(path).name)

    def close(self) -> None:
        self._fp.close()

    def __enter__(self) -> FileStorage:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def describe(self) -> str:
        return f"file {self.name!r}"

    def _read(self, offset: int, size: int) -> bytes:
        self._fp.seek(offset)
        data = self._fp.read(size)
        if len(data) != size:
            raise FormatError(f"short read from {self.name!r} at {offset:#x}")
        return data


class MemoryStorage(Storage):
    """A storage over an in-memory buffer (small structures and tests)."""

    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)
        self.size = len(self._data)

    def describe(self) -> str:
        return "buffer"

    def _read(self, offset: int, size: int) -> bytes:
        return self._data[offset : offset + size]


class SubStorage(Storage):
    """A window of ``size`` bytes at ``offset`` inside a parent storage."""

    def __init__(self, parent: Storage, offset: int, size: int) -> None:
        if offset < 0 or size < 0 or offset + size > parent.size:
            raise FormatError(
                f"region {offset:#x}+{size:#x} does not fit in the "
                f"{parent.size:#x}-byte {parent.describe()}"
            )
        self.parent = parent
        self.offset = offset
        self.size = size

    def describe(self) -> str:
        return f"region of {self.parent.describe()}"

    def _read(self, offset: int, size: int) -> bytes:
        return self.parent.read_at(self.offset + offset, size)


def u16(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 2], "little")


def u32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 4], "little")


def u64(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 8], "little")


def cstr(data: bytes, off: int = 0, limit: int | None = None) -> str:
    """Decode a NUL-terminated UTF-8 string starting at ``off``."""
    end = len(data) if limit is None else min(len(data), off + limit)
    nul = data.find(b"\0", off, end)
    raw = data[off : end if nul < 0 else nul]
    return raw.decode("utf-8", errors="replace")


def windows_name_problem(piece: str) -> str | None:
    """Why Windows can't hold a file or folder called ``piece``, or ``None``."""
    if any(ch in WINDOWS_FORBIDDEN for ch in piece):
        return "has a character Windows does not allow in file names"
    if piece[-1] in " .":
        return "ends with a space or dot, which Windows would drop"
    if piece.split(".")[0].rstrip(" ").upper() in WINDOWS_DEVICES:
        return "is a reserved device name on Windows"
    return None


def safe_join(base: Path, *parts: str) -> Path:
    """Join untrusted path components under ``base``, refusing traversal.

    On Windows, names Windows can't hold are refused too, so nothing is silently
    renamed or written to a device such as ``NUL``.
    """
    out = base
    for part in parts:
        for piece in part.replace("\\", "/").split("/"):
            if piece in ("", "."):
                continue
            if piece == ".." or ":" in piece:
                raise OutputPathError(f"refusing unsafe path component {piece!r}")
            if WINDOWS and (why := windows_name_problem(piece)):
                raise OutputPathError(f"{piece!r} {why}")
            out = out / piece
    return out


def native_path(path: Path) -> str:
    """``path`` as the OS should get it. On Windows: absolute, with the ``\\\\?\\``
    prefix, so paths longer than 260 characters work even with Windows' long-path
    setting off (its default)."""
    if not WINDOWS:
        return os.fspath(path)
    full = os.path.abspath(path)
    if full.startswith("\\\\?\\"):
        return full
    if full.startswith("\\\\"):  # \\server\share\...
        return "\\\\?\\UNC\\" + full[2:]
    return "\\\\?\\" + full


def same_file(a: Path, b: Path) -> bool:
    """Whether ``a`` and ``b`` are one file on disk, such as two names that differ only
    in letter case on a file system that ignores case (Windows, macOS by default)."""
    try:
        return os.path.samefile(native_path(a), native_path(b))
    except OSError:  # one of them does not exist
        return False


def write_entry(storage: Storage, base: Path, name: str) -> None:
    """Stream ``storage`` into the file ``base/name`` (``name`` from a container).

    A name that can't be a file here raises :class:`OutputPathError`, so callers can
    skip that one file. Running out of space, or a read-only disk, still raises.
    """
    target = native_path(safe_join(base, name))
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        out = open(target, "wb")  # noqa: SIM115 (closed below)
    except ValueError as e:  # e.g. a NUL in the name
        raise OutputPathError(f"{name!r} cannot be a file name: {e}") from None
    except OSError as e:
        if e.errno in FATAL_WRITE_ERRORS:
            raise
        raise OutputPathError(f"{name!r} cannot be created here: {e.strerror or e}") from None
    with out:
        for chunk in storage.iter_chunks():
            out.write(chunk)
