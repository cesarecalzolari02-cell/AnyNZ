"""Build tiny synthetic Switch-format files for tests.

Everything here is generated at test time from random bytes and randomly
generated keys. No real keys or Nintendo data are used or stored.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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


# --------------------------------------------------------------------------- NCA
#
# The builders below implement the encryption side independently of nx_decode
# (straight on top of `cryptography`) so tests exercise the decryption code
# against a separate implementation of the same spec.


def _ecb_enc(key: bytes, data: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(data) + e.finalize()


def _xts_enc(key: bytes, data: bytes, first_sector: int) -> bytes:
    out = b""
    for i in range(0, len(data), 0x200):
        tweak = (first_sector + i // 0x200).to_bytes(16, "big")
        e = Cipher(algorithms.AES(key), modes.XTS(tweak)).encryptor()
        out += e.update(data[i : i + 0x200]) + e.finalize()
    return out


def _ctr_enc(key: bytes, upper: bytes, abs_offset: int, data: bytes) -> bytes:
    counter = upper + (abs_offset >> 4).to_bytes(8, "big")
    e = Cipher(algorithms.AES(key), modes.CTR(counter)).encryptor()
    return e.update(data) + e.finalize()


def make_keys(revisions: tuple[int, ...] = (0,)) -> dict[str, bytes]:
    """Random pre-derived keys, named as in a prod.keys file."""
    keys = {"header_key": rand_key(32)}
    for rev in revisions:
        for kind in ("application", "ocean", "system"):
            keys[f"key_area_key_{kind}_{rev:02x}"] = rand_key()
        keys[f"titlekek_{rev:02x}"] = rand_key()
    return keys


@dataclass
class SectionSpec:
    kind: str  # "pfs0" or "romfs"
    payload: bytes
    crypto: str = "ctr"  # "ctr", "xts" or "none"
    block_size: int = 0x1000  # HierarchicalSha256 block size
    ivfc_block_log2: int = 9
    patch: bool = False  # mark as a BKTR patch section
    hash_type: int | None = None  # override
    secure_value: bytes = field(default_factory=lambda: os.urandom(8))


def hier_sha256_image(payload: bytes, block: int) -> tuple[bytes, bytes]:
    """Return ``(section image, hash_info)`` for a HierarchicalSha256 PFS0 section."""
    table = b"".join(
        hashlib.sha256(payload[i : i + block]).digest() for i in range(0, len(payload), block)
    )
    pfs_off = _align(len(table), 0x200)
    image = table.ljust(pfs_off, b"\0") + payload
    info = hashlib.sha256(table).digest() + struct.pack(
        "<IIQQQQ", block, 2, 0, len(table), pfs_off, len(payload)
    )
    return image, info.ljust(0xF8, b"\0")


def ivfc_image(payload: bytes, block_log2: int) -> tuple[bytes, bytes]:
    """Return ``(section image, hash_info)`` for a 6-level IVFC (RomFS) section."""
    block = 1 << block_log2
    levels = [payload]
    for _ in range(5):
        below = levels[0]
        hashes = b"".join(
            hashlib.sha256(below[i : i + block].ljust(block, b"\0")).digest()
            for i in range(0, max(len(below), 1), block)
        )
        levels.insert(0, hashes)
    image, entries = b"", b""
    for level in levels:
        off = _align(len(image), block)
        image = image.ljust(off, b"\0") + level
        entries += struct.pack("<QQII", off, len(level), block_log2, 0)
    master = hashlib.sha256(levels[0].ljust(block, b"\0")).digest()
    info = b"IVFC" + struct.pack("<III", 0x20000, 0x20, 7) + entries + b"\0" * 0x20 + master
    return image, info.ljust(0xF8, b"\0")


def build_nca(
    keys: dict[str, bytes],
    sections: list[SectionSpec],
    *,
    content_type: int = 0,
    key_generation: int = 1,
    kaek_index: int = 0,
    title_id: int = 0x0100000000001000,
    rights_id: bytes | None = None,
    title_key: bytes | None = None,
    nca2: bool = False,
    plaintext: bool = False,
) -> bytes:
    """Build an NCA3 (or NCA2) with the given sections, encrypted with ``keys``."""
    rev = max(key_generation - 1, 0)
    key_area = os.urandom(0x40)
    xts_key, ctr_key = key_area[:0x20], key_area[0x20:0x30]
    if rights_id is not None:
        assert title_key is not None
        ctr_key = title_key

    body, fs_headers, table = b"", [], []
    for spec in sections:
        if spec.kind == "pfs0":
            image, info = hier_sha256_image(spec.payload, spec.block_size)
            fs_type, hash_type = 1, 2
        else:
            image, info = ivfc_image(spec.payload, spec.ivfc_block_log2)
            fs_type, hash_type = 0, 3
        if spec.hash_type is not None:
            hash_type = spec.hash_type
        image = image.ljust(_align(len(image), 0x200), b"\0")
        start = 0xC00 + len(body)
        enc_type = {"none": 1, "xts": 2, "ctr": 3}[spec.crypto]
        if spec.patch:
            enc_type = 4
        fs = bytearray(0x200)
        struct.pack_into("<HBBB", fs, 0, 2, fs_type, hash_type, enc_type)
        fs[0x8:0x100] = info
        fs[0x140:0x148] = spec.secure_value
        if spec.patch:
            struct.pack_into("<QQ", fs, 0x100, len(image) // 2, 0x100)
            struct.pack_into("<QQ", fs, 0x120, len(image) // 2 + 0x100, 0x100)
        if not plaintext:
            if spec.crypto == "ctr":
                image = _ctr_enc(ctr_key, bytes(fs[0x140:0x148])[::-1], start, image)
            elif spec.crypto == "xts":
                image = _xts_enc(xts_key, image, 0)
        fs_headers.append(bytes(fs))
        table.append((start, start + len(image)))
        body += image

    hdr = bytearray(0x200)
    hdr[0:4] = b"NCA2" if nca2 else b"NCA3"
    hdr[5] = content_type
    hdr[6] = min(key_generation, 2)
    hdr[7] = kaek_index
    struct.pack_into("<QQ", hdr, 0x8, 0xC00 + len(body), title_id)
    hdr[0x20] = key_generation if key_generation > 2 else 0
    if rights_id is not None:
        hdr[0x30:0x40] = rights_id
    for i, (start, end) in enumerate(table):
        struct.pack_into("<IIB", hdr, 0x40 + 0x10 * i, start // 0x200, end // 0x200, 1)
    for i, fs in enumerate(fs_headers):
        hdr[0x80 + 0x20 * i : 0xA0 + 0x20 * i] = hashlib.sha256(fs).digest()
    if rights_id is None:
        kind = ("application", "ocean", "system")[kaek_index]
        hdr[0x100:0x140] = _ecb_enc(keys[f"key_area_key_{kind}_{rev:02x}"], key_area)

    fs_block = b"".join(fs_headers).ljust(0x800, b"\0")
    header = os.urandom(0x200) + bytes(hdr) + fs_block
    if not plaintext:
        hk = keys["header_key"]
        if nca2:
            header = _xts_enc(hk, header[:0x400], 0) + b"".join(
                _xts_enc(hk, header[o : o + 0x200], 0) for o in range(0x400, 0xC00, 0x200)
            )
        else:
            header = _xts_enc(hk, header, 0)
    return header + body


def make_rights_id(title_id: int, rev: int) -> bytes:
    return title_id.to_bytes(8, "big") + bytes(7) + bytes([rev])


def build_ticket(
    rights_id: bytes,
    enc_title_key: bytes,
    personalized: bool = False,
    big_endian_sig: bool = False,
) -> bytes:
    sig = (0x010004).to_bytes(4, "big" if big_endian_sig else "little")
    body = bytearray(0x180)
    body[0:0x1A] = b"Root-CA00000003-XS00000020"
    body[0x40:0x50] = enc_title_key
    body[0x140] = 2
    body[0x141] = 1 if personalized else 0
    body[0x160:0x170] = rights_id
    return sig + os.urandom(0x100) + b"\0" * 0x3C + bytes(body)


def encrypt_title_key(keys: dict[str, bytes], rev: int, title_key: bytes) -> bytes:
    return _ecb_enc(keys[f"titlekek_{rev:02x}"], title_key)
