from __future__ import annotations

import os
import random

import pytest
from builders import (
    _ctr_enc,
    aes_ctr_ex_entry,
    bucket_header,
    build_bucket_tree,
    indirect_entry,
)

from nx_decode.bktr import (
    AES_CTR_EX_ENTRY_SIZE,
    INDIRECT_ENTRY_SIZE,
    AesCtrExStorage,
    IndirectStorage,
    TableInfo,
    read_bucket_tree,
)
from nx_decode.errors import FormatError, UnsupportedError
from nx_decode.io import MemoryStorage


def tree(entries: list[bytes], end: int, entry_size: int, what: str = "test"):
    blob = build_bucket_tree(entries, end)
    return read_bucket_tree(
        MemoryStorage(blob), TableInfo(0, len(blob), len(entries)), entry_size, what
    )


def relocations(rng: random.Random, count: int, base_size: int, patch_size: int):
    """Random relocation entries on 0x10 boundaries, plus the image they describe."""
    base, patch = os.urandom(base_size), os.urandom(patch_size)
    entries, image, virt = [], b"", 0
    for _ in range(count):
        length = rng.randrange(1, 5) * 0x10
        storage = rng.randrange(2)
        source = (base, patch)[storage]
        phys = rng.randrange(0, len(source) - length)
        entries.append(indirect_entry(virt, phys, storage))
        image += source[phys : phys + length]
        virt += length
    return entries, image, MemoryStorage(base), MemoryStorage(patch)


def test_indirect_storage_across_entry_sets() -> None:
    # 2000 entries need three entry sets (0x332 entries each).
    rng = random.Random(5)
    entries, image, base, patch = relocations(rng, 2000, 0x8000, 0x8000)
    storage = IndirectStorage(base, patch, tree(entries, len(image), INDIRECT_ENTRY_SIZE))
    assert storage.size == len(image)
    assert storage.read_at(0, len(image)) == image
    for _ in range(300):
        off = rng.randrange(len(image))
        size = rng.randrange(1, min(0x900, len(image) - off) + 1)
        assert storage.read_at(off, size) == image[off : off + size]


def test_aes_ctr_ex_storage_uses_each_subsection_generation() -> None:
    key, secure_value, section_offset = os.urandom(16), os.urandom(4), 0x4C00
    plain = os.urandom(0x3000)
    # (start, generation, encrypted): the counter's generation changes per subsection
    subsections = [(0x0, 7, True), (0x1230, 0x10000, True), (0x2000, 9, False), (0x2800, 3, True)]
    cipher = bytearray()
    for i, (start, gen, enc) in enumerate(subsections):
        end = subsections[i + 1][0] if i + 1 < len(subsections) else len(plain)
        chunk = plain[start:end]
        if enc:
            upper = secure_value + gen.to_bytes(4, "big")
            aligned = start - start % 16
            pad = start - aligned
            chunk = _ctr_enc(key, upper, section_offset + aligned, bytes(pad) + chunk)[pad:]
        cipher += chunk
    entries = [aes_ctr_ex_entry(s, g, e) for s, g, e in subsections]
    storage = AesCtrExStorage(
        MemoryStorage(bytes(cipher)),
        section_offset,
        key,
        secure_value,
        tree(entries, len(plain), AES_CTR_EX_ENTRY_SIZE),
    )
    assert storage.read_at(0, len(plain)) == plain
    for off, size in [(1, 15), (0x1220, 0x20), (0x1FF8, 0x10), (0x27F1, 0x30), (0x2FFF, 1)]:
        assert storage.read_at(off, size) == plain[off : off + size]


def test_plaintext_aes_ctr_ex_storage() -> None:
    data = os.urandom(0x800)
    table = tree([aes_ctr_ex_entry(0, 1), aes_ctr_ex_entry(0x400, 2)], len(data), 0x10)
    storage = AesCtrExStorage(MemoryStorage(data), 0, None, bytes(4), table)
    assert storage.read_at(0x3F0, 0x20) == data[0x3F0:0x410]


def test_table_info_needs_bktr_magic() -> None:
    raw = (0x100).to_bytes(8, "little") + (0x8000).to_bytes(8, "little") + bucket_header(3)
    assert TableInfo.parse(raw, "relocation") == TableInfo(0x100, 0x8000, 3)
    with pytest.raises(FormatError, match="magic"):
        TableInfo.parse(raw[:0x10] + b"XXXX" + raw[0x14:], "relocation")


def test_corrupt_tables_are_format_errors() -> None:
    entries = [indirect_entry(0, 0, 0), indirect_entry(0x100, 0, 1)]
    blob = bytearray(build_bucket_tree(entries, 0x200))
    st = MemoryStorage(bytes(blob))
    with pytest.raises(FormatError, match="empty"):
        read_bucket_tree(st, TableInfo(0, len(blob), 0), INDIRECT_ENTRY_SIZE, "relocation")
    with pytest.raises(FormatError, match="smaller"):
        read_bucket_tree(st, TableInfo(0, 0x4000, 2), INDIRECT_ENTRY_SIZE, "relocation")
    with pytest.raises(FormatError, match="entry set"):  # count disagrees with the header
        read_bucket_tree(st, TableInfo(0, len(blob), 1), INDIRECT_ENTRY_SIZE, "relocation")
    unordered = build_bucket_tree([indirect_entry(0x100, 0, 0), indirect_entry(0x80, 0, 0)], 0x200)
    with pytest.raises(FormatError, match="order"):
        read_bucket_tree(
            MemoryStorage(unordered), TableInfo(0, len(unordered), 2), INDIRECT_ENTRY_SIZE, "x"
        )
    bad_index = build_bucket_tree([indirect_entry(0, 0, 2)], 0x100)
    table = read_bucket_tree(MemoryStorage(bad_index), TableInfo(0, len(bad_index), 1), 0x14, "x")
    with pytest.raises(FormatError, match="storage index"):
        IndirectStorage(MemoryStorage(b""), MemoryStorage(b""), table)


def test_huge_tables_are_unsupported_not_allocated() -> None:
    # Needs a second offset level; refused before anything is read.
    info = TableInfo(0, 1 << 40, 0x7FE * 0x332 + 1)
    with pytest.raises(UnsupportedError, match="second index level"):
        read_bucket_tree(MemoryStorage(b""), info, INDIRECT_ENTRY_SIZE, "relocation")


def test_reads_past_the_mapped_range_are_format_errors() -> None:
    entries, image, base, patch = relocations(random.Random(1), 4, 0x100, 0x100)
    storage = IndirectStorage(base, patch, tree(entries, len(image), INDIRECT_ENTRY_SIZE))
    with pytest.raises(FormatError):
        storage.read_at(len(image) - 4, 8)
    # An entry pointing past the end of its source is caught when read.
    bad = tree([indirect_entry(0, 0xF0, 1)], 0x40, INDIRECT_ENTRY_SIZE)
    with pytest.raises(FormatError):
        IndirectStorage(base, patch, bad).read_at(0, 0x40)
