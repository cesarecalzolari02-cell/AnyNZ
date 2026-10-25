"""Build tiny synthetic Switch-format files for tests.

Everything here is generated at test time from random bytes and randomly
generated keys. No real keys or Nintendo data are used or stored.
"""

from __future__ import annotations

import copy
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


# Bucket trees as Switchbrew's NCA page lays them out: an offset node, then full
# 0x4000-byte entry sets (the last one may be partial).


def bucket_header(entry_count: int) -> bytes:
    return b"BKTR" + struct.pack("<III", 1, entry_count, 0)


def indirect_entry(virtual: int, physical: int, storage: int) -> bytes:
    """Relocation entry: storage 0 is the base game, 1 the update's patch data."""
    return struct.pack("<QQI", virtual, physical, storage)


def aes_ctr_ex_entry(offset: int, generation: int, encrypted: bool = True) -> bytes:
    return struct.pack("<QB3xI", offset, 0 if encrypted else 1, generation)


def build_bucket_tree(entries: list[bytes], end_offset: int) -> bytes:
    per_set = (0x4000 - 0x10) // len(entries[0])
    sets = [entries[i : i + per_set] for i in range(0, len(entries), per_set)]
    starts = [struct.unpack_from("<Q", s[0])[0] for s in sets]
    offset_node = struct.pack("<IIQ", 0, len(sets), end_offset)
    offset_node += struct.pack(f"<{len(starts)}Q", *starts)
    nodes = [offset_node.ljust(0x4000, b"\0")]
    for i, entry_set in enumerate(sets):
        set_end = starts[i + 1] if i + 1 < len(sets) else end_offset
        node = struct.pack("<IIQ", i, len(entry_set), set_end) + b"".join(entry_set)
        nodes.append(node.ljust(0x4000, b"\0"))
    return b"".join(nodes)


@dataclass
class BktrSpec:
    """Make a RomFS section an update's BKTR section, patching ``base_section``.

    The section payload is the *patched* RomFS. Blocks of the patched image that
    also occur in the base section are relocated there; the rest becomes patch
    data, split into subsections with ``generations``, then an unencrypted one if
    ``plain_tail``. Tables and subsection counters follow hactool/nxdumptool.
    """

    base_section: bytes  # the base game's plaintext section image
    generations: tuple[int, ...] = (1, 2)
    plain_tail: bool = True
    block: int = 0x200


def _bktr_section(
    spec: BktrSpec, virtual: bytes, fs: bytearray, start: int, key: bytes | None
) -> bytes:
    """Fill PatchInfo in ``fs``; return the physical section (patch data and tables)."""
    where: dict[bytes, int] = {}
    for off in range(0, len(spec.base_section) - spec.block + 1, spec.block):
        where.setdefault(spec.base_section[off : off + spec.block], off)
    relocations: list[tuple[int, int, int]] = []  # (virtual, physical, storage)
    patch = bytearray()
    for off in range(0, len(virtual), spec.block):
        piece = virtual[off : off + spec.block]
        found = where.get(piece)
        storage, phys = (0, found) if found is not None else (1, len(patch))
        if storage:
            patch += piece
        if relocations:
            v, p, st = relocations[-1]
            if st == storage and p + off - v == phys:
                continue  # extends the previous entry
        relocations.append((off, phys, storage))
    assert patch, "the patched image must differ from the base"

    parts = len(spec.generations) + spec.plain_tail
    step = _align(max(len(patch) // parts, 0x10), 0x10)
    subsections = [(i * step, gen, True) for i, gen in enumerate(spec.generations)]
    if spec.plain_tail:
        subsections.append((len(spec.generations) * step, 0, False))
    subsections = [sub for sub in subsections if sub[0] < len(patch)]

    indirect_off = len(patch)
    indirect = build_bucket_tree([indirect_entry(*r) for r in relocations], len(virtual))
    aes_off = indirect_off + len(indirect)
    aes = build_bucket_tree([aes_ctr_ex_entry(*sub) for sub in subsections], len(patch))
    fs[0x100:0x140] = (
        struct.pack("<QQ", indirect_off, len(indirect))
        + bucket_header(len(relocations))
        + struct.pack("<QQ", aes_off, len(aes))
        + bucket_header(len(subsections))
    )
    if key is None:
        image = bytes(patch) + indirect + aes
    else:
        upper = bytes(fs[0x140:0x148])[::-1]  # SecureValue | Generation, big-endian
        image = b""
        for i, (off, gen, encrypted) in enumerate(subsections):
            end = subsections[i + 1][0] if i + 1 < len(subsections) else len(patch)
            chunk = bytes(patch[off:end])
            counter = upper[:4] + gen.to_bytes(4, "big")
            image += _ctr_enc(key, counter, start + off, chunk) if encrypted else chunk
        image += _ctr_enc(key, upper, start + indirect_off, indirect)
        image += _ctr_enc(key, upper, start + aes_off, aes)
    return image.ljust(_align(len(image), 0x200), b"\0")


@dataclass
class SectionSpec:
    kind: str  # "pfs0" or "romfs"
    payload: bytes
    crypto: str = "ctr"  # "ctr", "xts" or "none"
    block_size: int = 0x1000  # HierarchicalSha256 block size
    ivfc_block_log2: int = 9
    patch: bool = False  # mark as a BKTR patch section (fake tables)
    bktr: BktrSpec | None = None  # a real BKTR section patching a base game section
    hash_type: int | None = None  # override
    enc_type: int | None = None  # override the FS header's encryption type byte
    fs_bytes: dict[int, bytes] = field(default_factory=dict)  # raw FS header overrides
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
        if spec.patch or spec.bktr:
            enc_type = 4
        if spec.enc_type is not None:
            enc_type = spec.enc_type
        fs = bytearray(0x200)
        struct.pack_into("<HBBB", fs, 0, 2, fs_type, hash_type, enc_type)
        fs[0x8:0x100] = info
        fs[0x140:0x148] = spec.secure_value
        if spec.bktr is not None:
            image = _bktr_section(spec.bktr, image, fs, start, None if plaintext else ctr_key)
        for off, value in spec.fs_bytes.items():
            fs[off : off + len(value)] = value
        if spec.patch:
            struct.pack_into("<QQ", fs, 0x100, len(image) // 2, 0x100)
            struct.pack_into("<QQ", fs, 0x120, len(image) // 2 + 0x100, 0x100)
        if not plaintext and spec.bktr is None:
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


# signature type -> (signature size, padding size), from Switchbrew's Ticket page
TICKET_SIGNATURES = {
    0x010000: (0x200, 0x3C),
    0x010001: (0x100, 0x3C),
    0x010002: (0x3C, 0x40),
    0x010003: (0x200, 0x3C),
    0x010004: (0x100, 0x3C),
    0x010005: (0x3C, 0x40),
    0x010006: (0x14, 0x28),
}


def build_ticket(
    rights_id: bytes,
    enc_title_key: bytes,
    personalized: bool = False,
    big_endian_sig: bool = False,
    sig_type: int = 0x010004,
    master_key_revision: int = 0,
) -> bytes:
    sig_size, pad_size = TICKET_SIGNATURES[sig_type]
    sig = sig_type.to_bytes(4, "big" if big_endian_sig else "little")
    body = bytearray(0x180)
    body[0:0x1A] = b"Root-CA00000003-XS00000020"
    body[0x40:0x50] = enc_title_key
    body[0x140] = 2
    body[0x141] = 1 if personalized else 0
    body[0x145] = master_key_revision
    body[0x160:0x170] = rights_id
    return sig + os.urandom(sig_size) + b"\0" * pad_size + bytes(body)


def encrypt_title_key(keys: dict[str, bytes], rev: int, title_key: bytes) -> bytes:
    return _ecb_enc(keys[f"titlekek_{rev:02x}"], title_key)


# ------------------------------------------------------------------ RomFS / CNMT / NACP

Tree = dict  # name -> bytes (file) or Tree (directory)


def build_romfs(tree: Tree) -> bytes:
    """Build a RomFS image. Hash-bucket tables are present but unused (all empty)."""
    dirs: list[dict] = []  # each: name, parent, children, files
    files: list[dict] = []  # each: name, parent, data

    def visit(name: str, node: Tree, parent: int) -> int:
        idx = len(dirs)
        dirs.append({"name": name, "parent": parent, "children": [], "files": []})
        for child, value in node.items():
            if isinstance(value, dict):
                dirs[idx]["children"].append(visit(child, value, idx))
            else:
                files.append({"name": child, "parent": idx, "data": value})
                dirs[idx]["files"].append(len(files) - 1)
        return idx

    visit("", tree, 0)

    def entry_size(name: str, fixed: int) -> int:
        return fixed + _align(len(name.encode()), 4)

    dir_offs, off = [], 0
    for d in dirs:
        dir_offs.append(off)
        off += entry_size(d["name"], 0x18)
    file_offs, off = [], 0
    for f in files:
        file_offs.append(off)
        off += entry_size(f["name"], 0x20)

    data, data_offs = b"", []
    for f in files:
        data = data.ljust(_align(len(data), 0x10), b"\0")
        data_offs.append(len(data))
        data += f["data"]

    none = 0xFFFFFFFF

    def sibling(items: list[int], i: int, offs: list[int]) -> int:
        pos = items.index(i)
        return offs[items[pos + 1]] if pos + 1 < len(items) else none

    dir_table = b""
    for i, d in enumerate(dirs):
        parent = dirs[d["parent"]]
        sib = sibling(parent["children"], i, dir_offs) if i else none
        child = dir_offs[d["children"][0]] if d["children"] else none
        first = file_offs[d["files"][0]] if d["files"] else none
        name = d["name"].encode()
        dir_table += struct.pack("<6I", dir_offs[d["parent"]], sib, child, first, none, len(name))
        dir_table += name.ljust(_align(len(name), 4), b"\0")
    file_table = b""
    for i, f in enumerate(files):
        sib = sibling(dirs[f["parent"]]["files"], i, file_offs)
        name = f["name"].encode()
        file_table += struct.pack(
            "<IIQQII", dir_offs[f["parent"]], sib, data_offs[i], len(f["data"]), none, len(name)
        )
        file_table += name.ljust(_align(len(name), 4), b"\0")

    data_start = 0x200
    tables_start = _align(data_start + len(data), 4)
    dir_hash = struct.pack("<I", none)
    file_hash = struct.pack("<I", none)
    layout, cur = [], tables_start
    for blob in (dir_hash, dir_table, file_hash, file_table):
        layout.append((cur, len(blob)))
        cur += len(blob)
    header = struct.pack("<Q", 0x50) + b"".join(struct.pack("<QQ", o, s) for o, s in layout)
    header += struct.pack("<Q", data_start)
    image = header.ljust(data_start, b"\0") + data
    image = image.ljust(tables_start, b"\0") + dir_hash + dir_table + file_hash + file_table
    return image


def build_nacp(name: str, publisher: str, display_version: str = "1.0.0", lang: int = 0) -> bytes:
    nacp = bytearray(0x4000)
    off = lang * 0x300
    nacp[off : off + len(name.encode())] = name.encode()
    nacp[off + 0x200 : off + 0x200 + len(publisher.encode())] = publisher.encode()
    nacp[0x3060 : 0x3060 + len(display_version)] = display_version.encode()
    return bytes(nacp)


def cnmt_ext(meta_type: int, application_id: int = 0, patch_id: int = 0) -> bytes:
    """The extended header for ``meta_type``, laid out as on Switchbrew's CNMT page."""
    if meta_type == 0x80:  # Application: PatchId, RequiredSystemVersion, RequiredAppVersion
        return struct.pack("<QII", patch_id, 0, 0)
    if meta_type == 0x81:  # Patch: ApplicationId, RequiredSystemVersion, ExtendedDataSize
        return struct.pack("<QII8x", application_id, 0, 0)
    if meta_type == 0x82:  # AddOnContent: ApplicationId, RequiredAppVersion, ..., DataPatchId
        return struct.pack("<QI4xQ", application_id, 0, 0)
    if meta_type == 0x83:  # Delta: ApplicationId, ExtendedDataSize
        return struct.pack("<QI4x", application_id, 0)
    if meta_type == 0x03:  # SystemUpdate: ExtendedDataSize
        return struct.pack("<I", 0)
    return b""


def build_cnmt(
    title_id: int,
    version: int,
    meta_type: int,
    contents: list[tuple[bytes, int]],
    attributes: int = 0,
    ext: bytes | None = None,
    meta_infos: list[tuple[int, int, int]] | None = None,
) -> bytes:
    """``contents`` is ``[(nca bytes, record content type)]``; ``meta_infos`` is
    ``[(title ID, version, meta type)]``. ``ext`` defaults to 0x10 zero bytes."""
    ext = bytes(0x10) if ext is None else ext
    metas = meta_infos or []
    hdr = struct.pack(
        "<QIBBHHHBBBBI4x",
        title_id,
        version,
        meta_type,
        0,
        len(ext),
        len(contents),
        len(metas),
        0,
        0,
        0,
        0,
        0,
    )
    recs = b""
    for blob, ctype in contents:
        digest = hashlib.sha256(blob).digest()
        size = len(blob)
        lo, hi = size & 0xFFFFFFFF, size >> 32
        recs += digest + digest[:16] + struct.pack("<IBBBB", lo, hi, attributes, ctype, 0)
    for tid, ver, mtype in metas:
        recs += struct.pack("<QIBB2x", tid, ver, mtype, 0)
    body = hdr + ext + recs
    return body + hashlib.sha256(body).digest()  # trailing digest, as in real CNMTs


def nca_name(blob: bytes, meta: bool = False) -> str:
    return hashlib.sha256(blob).hexdigest()[:32] + (".cnmt.nca" if meta else ".nca")


@dataclass
class FakeGame:
    keys: dict[str, bytes]
    files: list[tuple[str, bytes]]
    title_id: int
    name: str
    publisher: str
    romfs_tree: Tree
    exefs_files: list[tuple[str, bytes]]
    romfs_section: bytes = b""  # the Program NCA's plaintext RomFS section image


def romfs_section_image(payload: bytes, block_log2: int = 9) -> bytes:
    """The plaintext section image build_nca makes for a RomFS payload."""
    image, _ = ivfc_image(payload, block_log2)
    return image.ljust(_align(len(image), 0x200), b"\0")


def build_game(
    title_id: int = 0x0100ABCD00010000,
    key_generation: int = 3,
    rights_id: bool = False,
    personalized: bool = False,
    name: str = "Test Game",
    plaintext: bool = False,
    manual: bool = False,
    keys: dict[str, bytes] | None = None,
) -> FakeGame:
    """A minimal application: Program (ExeFS + RomFS), Control (NACP) and Meta NCAs.

    ``plaintext`` leaves every NCA unencrypted, so corruption tests reach the parsers.
    ``manual`` adds an HtmlDocument (Manual) NCA, content an update usually keeps.
    ``keys`` reuses another fake game's keys (default: new random keys).
    """
    rev = max(key_generation - 1, 0)
    keys = keys or make_keys(revisions=(rev,))
    title_key = rand_key() if rights_id else None
    rid = make_rights_id(title_id, rev) if rights_id else None
    kw = {
        "key_generation": key_generation,
        "title_id": title_id,
        "rights_id": rid,
        "title_key": title_key,
        "plaintext": plaintext,
    }

    exefs = [("main", os.urandom(0x1800)), ("main.npdm", os.urandom(0x200)), ("rtld", b"r" * 99)]
    tree: Tree = {
        "data": {
            "level1.bin": os.urandom(0x2100),
            "empty": b"",
            "sub": {"deep.txt": b"hi\n"},
            "level2.bin": os.urandom(0x1800),
        },
        "readme.txt": b"synthetic test data\n",
    }
    romfs = build_romfs(tree)
    program = build_nca(
        keys,
        [SectionSpec("pfs0", build_pfs0(exefs)), SectionSpec("romfs", romfs)],
        content_type=0,
        **kw,
    )
    nacp = build_nacp(name, "Test Publisher", "1.2.3")
    control = build_nca(
        keys, [SectionSpec("romfs", build_romfs({"control.nacp": nacp}))], content_type=2, **kw
    )
    contents = [(program, 1), (control, 3)]
    if manual:
        html = build_romfs({"html-document": {"index.html": b"<p>manual</p>\n"}})
        contents.append((build_nca(keys, [SectionSpec("romfs", html)], content_type=3, **kw), 4))
    ext = cnmt_ext(0x80, patch_id=title_id + 0x800)
    meta = build_meta_nca(
        keys, title_id, 0, 0x80, contents, ext, key_generation, plaintext=plaintext
    )
    files = [(nca_name(blob), blob) for blob, _ in contents] + [(nca_name(meta, meta=True), meta)]
    if rights_id:
        assert rid is not None and title_key is not None
        tik = build_ticket(rid, encrypt_title_key(keys, rev, title_key), personalized=personalized)
        files += ticket_files(rid, tik)
    return FakeGame(
        keys, files, title_id, name, "Test Publisher", tree, exefs, romfs_section_image(romfs)
    )


META_NAMES = {0x80: "Application", 0x81: "Patch", 0x82: "AddOnContent", 0x83: "Delta"}


def build_meta_nca(
    keys: dict[str, bytes],
    title_id: int,
    version: int,
    meta_type: int,
    contents: list[tuple[bytes, int]],
    ext: bytes,
    key_generation: int,
    meta_infos: list[tuple[int, int, int]] | None = None,
    plaintext: bool = False,
) -> bytes:
    """A Meta NCA whose PFS0 holds ``<Type>_<title id>.cnmt``."""
    cnmt = build_cnmt(title_id, version, meta_type, contents, ext=ext, meta_infos=meta_infos)
    name = f"{META_NAMES.get(meta_type, 'Unknown')}_{title_id:016x}.cnmt"
    return build_nca(
        keys,
        [SectionSpec("pfs0", build_pfs0([(name, cnmt)]))],
        content_type=1,
        key_generation=key_generation,
        title_id=title_id,
        plaintext=plaintext,
    )


def ticket_files(rights_id: bytes, ticket: bytes) -> list[tuple[str, bytes]]:
    return [(rights_id.hex() + ".tik", ticket), (rights_id.hex() + ".cert", os.urandom(0x700))]


@dataclass
class FakeContent:
    """A patch or DLC content set: its NSP entries and what the tests expect back."""

    files: list[tuple[str, bytes]]
    title_id: int
    version: int
    application_id: int
    romfs_tree: Tree | None = None
    exefs_files: list[tuple[str, bytes]] | None = None


def build_dlc(
    keys: dict[str, bytes],
    application_id: int,
    index: int = 1,
    version: int = 0,
    key_generation: int = 3,
    ext: bytes | None = None,
    title_id: int | None = None,
) -> FakeContent:
    """AddOnContent: a rights-ID Data NCA (RomFS), a Meta NCA and a common ticket.

    The title ID defaults to the usual ``(application ID + 0x1000) + index`` scheme;
    pass ``title_id`` to break it (the CNMT's ApplicationId is what counts).
    """
    rev = max(key_generation - 1, 0)
    tid = title_id if title_id is not None else application_id + 0x1000 + index
    title_key, rid = rand_key(), make_rights_id(tid, rev)
    tree: Tree = {"dlc": {f"item{index}.bin": os.urandom(0x1234)}, "info.txt": b"dlc\n"}
    data = build_nca(
        keys,
        [SectionSpec("romfs", build_romfs(tree))],
        content_type=4,
        key_generation=key_generation,
        title_id=tid,
        rights_id=rid,
        title_key=title_key,
    )
    ext = cnmt_ext(0x82, application_id=application_id) if ext is None else ext
    meta = build_meta_nca(keys, tid, version, 0x82, [(data, 2)], ext, key_generation)
    tik = build_ticket(rid, encrypt_title_key(keys, rev, title_key))
    files = [(nca_name(data), data), (nca_name(meta, meta=True), meta), *ticket_files(rid, tik)]
    return FakeContent(files, tid, version, application_id, tree)


def patched_tree(base: Tree) -> Tree:
    """The base RomFS after an update: a 0x200-byte file added in front (so the
    unchanged data behind it moves), one file changed in place, a new folder."""
    tree: Tree = {"added-first.bin": os.urandom(0x200), **copy.deepcopy(base)}
    tree["data"]["sub"]["deep.txt"] = b"HI\n"
    tree["readme.txt"] = b"patched test data, longer than before\n"
    tree["new"] = {"extra.txt": b"new in the update\n"}
    return tree


def build_patch(
    keys: dict[str, bytes],
    application_id: int,
    version: int = 0x10000,
    key_generation: int = 3,
    base: FakeGame | None = None,
    plaintext: bool = False,
) -> FakeContent:
    """A Patch: a rights-ID Program NCA with a BKTR RomFS section, plus its Meta NCA.

    Without ``base`` the BKTR section is random bytes with fake tables, enough to be
    recognised as a patch. With ``base`` it is a real BKTR section against the base
    game's RomFS; the update also brings a new ExeFS and its own Control NCA, and
    ``romfs_tree`` is what the patched RomFS must contain.
    """
    rev = max(key_generation - 1, 0)
    tid = application_id + 0x800
    title_key, rid = rand_key(), make_rights_id(tid, rev)
    kw = {
        "key_generation": key_generation,
        "title_id": tid,
        "rights_id": rid,
        "title_key": title_key,
        "plaintext": plaintext,
    }
    tree = exefs = None
    if base is None:
        sections = [
            SectionSpec("pfs0", build_pfs0([("main", os.urandom(0x400))])),
            SectionSpec("romfs", os.urandom(0x1000), patch=True),
        ]
        contents = [(build_nca(keys, sections, content_type=0, **kw), 1)]
    else:
        tree = patched_tree(base.romfs_tree)
        exefs = [("main", os.urandom(0x1C00)), ("main.npdm", os.urandom(0x200))]
        sections = [
            SectionSpec("pfs0", build_pfs0(exefs)),
            SectionSpec("romfs", build_romfs(tree), bktr=BktrSpec(base.romfs_section)),
        ]
        control = build_romfs({"control.nacp": build_nacp(base.name, base.publisher, "1.2.4")})
        contents = [
            (build_nca(keys, sections, content_type=0, **kw), 1),
            (build_nca(keys, [SectionSpec("romfs", control)], content_type=2, **kw), 3),
        ]
    ext = cnmt_ext(0x81, application_id=application_id)
    meta = build_meta_nca(
        keys, tid, version, 0x81, contents, ext, key_generation, plaintext=plaintext
    )
    tik = build_ticket(rid, encrypt_title_key(keys, rev, title_key))
    files = [(nca_name(blob), blob) for blob, _ in contents] + [(nca_name(meta, meta=True), meta)]
    return FakeContent(files + ticket_files(rid, tik), tid, version, application_id, tree, exefs)
