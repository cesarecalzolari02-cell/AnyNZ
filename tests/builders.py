"""Build tiny synthetic Switch-format files for tests.

Everything here is generated at test time from random bytes and randomly
generated keys. No real keys or Nintendo data are used or stored.
"""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path


def rand_key(n: int = 16) -> bytes:
    return os.urandom(n)


def write_keys_file(path: Path, keys: dict[str, bytes]) -> Path:
    lines = ["# synthetic test keys, generated at runtime"]
    lines += [f"{name} = {value.hex().upper()}" for name, value in keys.items()]
    path.write_text("\n".join(lines) + "\n")
    return path


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def _string_table(names: list[str], align_to: int, prefix: int) -> tuple[bytes, list[int]]:
    offsets, table = [], b""
    for name in names:
        offsets.append(len(table))
        table += name.encode() + b"\0"
    # Pad so the data region starts aligned, like real tools do.
    total = prefix + len(table)
    table += b"\0" * (_align(total, align_to) - total)
    return table, offsets


def build_pfs0(files: list[tuple[str, bytes]], align: int = 0x20) -> bytes:
    names = [n for n, _ in files]
    table, name_offs = _string_table(names, align, 0x10 + 0x18 * len(files))
    entries, data, off = b"", b"", 0
    for (_, content), noff in zip(files, name_offs, strict=True):
        entries += struct.pack("<QQII", off, len(content), noff, 0)
        data += content
        off += len(content)
    header = b"PFS0" + struct.pack("<III", len(files), len(table), 0)
    return header + entries + table + data


def build_hfs0(files: list[tuple[str, bytes]], align: int = 0x200) -> bytes:
    names = [n for n, _ in files]
    table, name_offs = _string_table(names, align, 0x10 + 0x40 * len(files))
    entries, data, off = b"", b"", 0
    for (_, content), noff in zip(files, name_offs, strict=True):
        hashed = min(len(content), 0x200)
        digest = hashlib.sha256(content[:hashed]).digest()
        entries += struct.pack("<QQIIQ", off, len(content), noff, hashed, 0) + digest
        data += content
        off += len(content)
    header = b"HFS0" + struct.pack("<III", len(files), len(table), 0)
    return header + entries + table + data


def hfs0_header_size(blob: bytes) -> int:
    count, strtab = struct.unpack_from("<II", blob, 4)
    return 0x10 + 0x40 * count + strtab


def build_xci(partitions: dict[str, list[tuple[str, bytes]]], key_area: bool = False) -> bytes:
    """Build an XCI: card header at 0 (or 0x1000 with ``key_area``), root HFS0 at 0xF000."""
    parts = [(name, build_hfs0(files)) for name, files in partitions.items()]
    root = bytearray(build_hfs0(parts))
    # Root entries hash the first 0x200 bytes; real cards hash each partition header.
    root_hdr_size = hfs0_header_size(bytes(root))
    root_off = 0xF000
    header = bytearray(0x200)
    header[0x100:0x104] = b"HEAD"
    header[0x10D] = 0xFA
    struct.pack_into("<QQ", header, 0x130, root_off, root_hdr_size)
    header[0x140:0x160] = hashlib.sha256(bytes(root[:root_hdr_size])).digest()
    image = bytearray(header) + b"\0" * (root_off - len(header)) + root
    if key_area:
        image = bytearray(0x1000) + image
    return bytes(image)
