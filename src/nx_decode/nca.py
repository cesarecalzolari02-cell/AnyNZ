"""NCA (Nintendo Content Archive): header decryption, key resolution, section access.

Spec: https://switchbrew.org/wiki/NCA (header and FS header layouts, enum values,
key generation, NCA2/NCA3 header sectors, HierarchicalSha256 and IVFC hash data).
Reference: hactool ``nca.c``/``nca.h``, libnintendo-hac ``nca.h`` and
``ContentArchiveUtil.cpp`` (IVFC level count, NCA0; the wiki does not cover these).

Header (0xC00 bytes, AES-128-XTS with ``header_key``, 0x200-byte sectors, Nintendo
big-endian tweak). NCA3 numbers the six sectors 0..5. NCA2 encrypts each FS header
(sectors 2..5) independently with sector number 0. NCA0 is not supported.

Main header (offsets from 0x200):

======  =====  ==============================================
0x004   1      distribution type (0 download, 1 gamecard)
0x005   1      content type (see :data:`CONTENT_TYPES`)
0x006   1      key generation (old field)
0x007   1      key-area encryption key index (app/ocean/system)
0x008   8      content size
0x010   8      program (title) ID
0x020   1      key generation
0x030   0x10   rights ID (non-zero: title key from a ticket)
0x040   4x0x10 section table: start/end in 0x200-byte units
0x080   4x0x20 SHA-256 of each FS header
0x100   0x40   encrypted key area (4 AES-128 keys)
======  =====  ==============================================

FS header (one per section, 0x200 bytes): 0x2 format (0 RomFS, 1 PFS0), 0x3 hash
type, 0x4 encryption type, 0x5 metadata hash type, 0x8 hash info, 0x100 patch info,
0x140 generation, 0x144 secure value, 0x148 sparse info, 0x178 compression info,
0x1A0 metadata hash info. The 14.0.0+ fields (SHA3 hash types, skip-layer-hash
encryption types, metadata hash info), sparse and compressed sections are only
detected, so they can be reported as unsupported.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cached_property

from .bktr import (
    AES_CTR_EX_ENTRY_SIZE,
    INDIRECT_ENTRY_SIZE,
    AesCtrExStorage,
    IndirectStorage,
    TableInfo,
    read_bucket_tree,
)
from .crypto import SECTOR, ctr_crypt, ecb_decrypt, xts_decrypt
from .errors import FormatError, MissingKeyError, MissingTicketError, NxError, UnsupportedError
from .io import Storage, u16, u32, u64
from .keys import Keyset
from .ticket import Ticket

HEADER_SIZE = 0xC00
MEDIA_UNIT = 0x200
# Hash block sizes outside this range are treated as corrupt. Real NCAs use 0x1000 to
# 0x10000 (IVFC: 0x4000); the cap keeps a bad header from allocating huge buffers.
MIN_HASH_BLOCK, MAX_HASH_BLOCK = 0x10, 0x1000000

CONTENT_TYPES = {0: "Program", 1: "Meta", 2: "Control", 3: "Manual", 4: "Data", 5: "PublicData"}
DISTRIBUTION = {0: "Download", 1: "GameCard"}

FS_ROMFS, FS_PFS0 = 0, 1
HASH_AUTO, HASH_NONE, HASH_SHA256, HASH_IVFC = 0, 1, 2, 3
HASH_SHA3 = (4, 5, 6)  # AutoSha3, HierarchicalSha3256, HierarchicalIntegritySha3 (14.0.0+)
ENC_NONE, ENC_XTS, ENC_CTR, ENC_CTR_EX = 1, 2, 3, 4
ENC_CTR_SKIP, ENC_CTR_EX_SKIP = 5, 6  # skip-layer-hash variants (14.0.0+)
HASH_NAMES = {
    0: "auto",
    1: "none",
    2: "HierarchicalSha256",
    3: "HierarchicalIntegrity",
    4: "auto (SHA3)",
    5: "HierarchicalSha3256",
    6: "HierarchicalIntegritySha3",
}
ENC_NAMES = {
    0: "auto",
    1: "none",
    2: "AES-XTS",
    3: "AES-CTR",
    4: "AES-CTR-Ex (BKTR)",
    5: "AES-CTR (skip layer hash)",
    6: "AES-CTR-Ex (BKTR, skip layer hash)",
}


def decrypt_header(raw: bytes, keyset: Keyset | None) -> tuple[bytes, bool]:
    """Return ``(plaintext header, was_plaintext)`` for the first 0xC00 bytes of an NCA."""
    if len(raw) < HEADER_SIZE:
        raise FormatError("file is too small to be an NCA")
    if raw[0x200:0x204] in (b"NCA3", b"NCA2") and not any(raw[0x340:0x400]):
        return raw[:HEADER_SIZE], True
    if keyset is None:
        raise MissingKeyError("header_key")
    key = keyset.header_key()
    first = xts_decrypt(key, raw[:0x400], 0)
    magic = first[0x200:0x204]
    if magic == b"NCA3":
        return xts_decrypt(key, raw[:HEADER_SIZE], 0), False
    if magic == b"NCA2":
        fs = b"".join(
            xts_decrypt(key, raw[off : off + SECTOR], 0)
            for off in range(0x400, HEADER_SIZE, SECTOR)
        )
        return first + fs, False
    if magic == b"NCA0":
        raise UnsupportedError("NCA0 (pre-release format) is not supported")
    raise FormatError("NCA header did not decrypt (not an NCA, or header_key is wrong)")


@dataclass(frozen=True)
class FsHeader:
    """One 0x200-byte FS (section) header."""

    raw: bytes

    @property
    def version(self) -> int:
        return u16(self.raw, 0)

    @property
    def fs_type(self) -> int:
        return self.raw[2]

    @property
    def hash_type(self) -> int:
        return self.raw[3]

    @property
    def encryption_type(self) -> int:
        return self.raw[4]

    @property
    def metadata_hash_type(self) -> int:
        return self.raw[5]

    @property
    def hash_info(self) -> bytes:
        return self.raw[0x8:0x100]

    @property
    def ctr_upper(self) -> bytes:
        """Upper 8 counter bytes: generation/secure value, byte-reversed into big-endian."""
        return self.raw[0x140:0x148][::-1]

    @property
    def has_patch_info(self) -> bool:
        # Indirect (relocation) table size and AesCtrEx table size.
        return u64(self.raw, 0x108) != 0 or u64(self.raw, 0x128) != 0

    @property
    def is_patch(self) -> bool:
        """An update's BKTR section: AES-CTR-EX encryption or a PatchInfo."""
        return self.encryption_type in (ENC_CTR_EX, ENC_CTR_EX_SKIP) or self.has_patch_info

    @property
    def has_sparse_info(self) -> bool:
        # SparseInfo at 0x148: table size at +0x8.
        return u64(self.raw, 0x150) != 0

    @property
    def has_compression_info(self) -> bool:
        # CompressionInfo at 0x178: table size at +0x8.
        return u64(self.raw, 0x180) != 0

    @property
    def has_metadata_hash_info(self) -> bool:
        # MetaDataHashType at 0x5; MetaDataHashDataInfo at 0x1A0: table size at +0x8.
        return self.metadata_hash_type != 0 or u64(self.raw, 0x1A8) != 0


@dataclass(frozen=True)
class NcaHeader:
    """Parsed plaintext NCA header."""

    raw: bytes

    @property
    def _h(self) -> bytes:
        return self.raw[0x200:0x400]

    @property
    def magic(self) -> str:
        return self._h[:4].decode("ascii", errors="replace")

    @property
    def distribution(self) -> int:
        return self._h[4]

    @property
    def content_type(self) -> int:
        return self._h[5]

    @property
    def content_type_name(self) -> str:
        return CONTENT_TYPES.get(self.content_type, f"Unknown({self.content_type})")

    @property
    def kaek_index(self) -> int:
        return self._h[7]

    @property
    def content_size(self) -> int:
        return u64(self._h, 0x8)

    @property
    def title_id(self) -> int:
        return u64(self._h, 0x10)

    @property
    def sdk_version(self) -> int:
        return u32(self._h, 0x1C)

    @property
    def key_generation(self) -> int:
        return max(self._h[6], self._h[0x20])

    @property
    def master_key_revision(self) -> int:
        """Key generations 0 and 1 both use master key 0; after that it is ``gen - 1``."""
        return max(self.key_generation - 1, 0)

    @property
    def rights_id(self) -> bytes:
        return self._h[0x30:0x40]

    @property
    def has_rights_id(self) -> bool:
        return any(self.rights_id)

    def section_bounds(self, i: int) -> tuple[int, int]:
        start = u32(self._h, 0x40 + 0x10 * i) * MEDIA_UNIT
        end = u32(self._h, 0x44 + 0x10 * i) * MEDIA_UNIT
        return start, end

    def fs_header_hash(self, i: int) -> bytes:
        return self._h[0x80 + 0x20 * i : 0xA0 + 0x20 * i]

    @property
    def key_area(self) -> bytes:
        return self._h[0x100:0x140]

    def fs_header(self, i: int) -> FsHeader:
        return FsHeader(self.raw[0x400 + 0x200 * i : 0x600 + 0x200 * i])


@dataclass(frozen=True)
class ContentKeys:
    xts: bytes | None
    ctr: bytes


@dataclass(frozen=True)
class HashLayout:
    """Where the payload sits inside a section, and how it is hashed."""

    kind: int  # HASH_NONE / HASH_SHA256 / HASH_IVFC
    data_offset: int
    data_size: int
    master_hash: bytes = b""
    block_size: int = 0
    # (offset, size, block_size) per level; level i is hashed by level i-1.
    levels: tuple[tuple[int, int, int], ...] = ()


class DecryptedSection(Storage):
    """On-the-fly decrypted view of one NCA section."""

    def __init__(
        self,
        nca: Storage,
        offset: int,
        size: int,
        mode: int,
        keys: ContentKeys | None,
        ctr_upper: bytes,
    ) -> None:
        self.nca = nca
        self.offset = offset
        self.size = size
        self.mode = mode
        self.keys = keys
        self.ctr_upper = ctr_upper

    def describe(self) -> str:
        return "NCA section"

    def _read(self, offset: int, size: int) -> bytes:
        if self.mode == ENC_NONE or self.keys is None:
            return self.nca.read_at(self.offset + offset, size)
        align = 16 if self.mode == ENC_CTR else SECTOR
        start = offset - offset % align
        end = min(-(-(offset + size) // align) * align, self.size)
        raw = self.nca.read_at(self.offset + start, end - start)
        if self.mode == ENC_CTR:
            plain = ctr_crypt(self.keys.ctr, self.ctr_upper, self.offset + start, raw)
        else:
            assert self.keys.xts is not None
            plain = xts_decrypt(self.keys.xts, raw, start // SECTOR)
        return plain[offset - start : offset - start + size]


class Section:
    """One present section (0..3) of an NCA."""

    def __init__(self, nca: Nca, index: int, offset: int, size: int, fs: FsHeader) -> None:
        self.nca = nca
        self.index = index
        self.offset = offset
        self.size = size
        self.fs = fs

    @property
    def kind(self) -> str:
        return {FS_PFS0: "PFS0", FS_ROMFS: "RomFS"}.get(self.fs.fs_type, "unknown")

    @property
    def effective_hash_type(self) -> int:
        h = self.fs.hash_type
        if h == HASH_AUTO:  # hactool infers the layer from the format type
            return HASH_SHA256 if self.fs.fs_type == FS_PFS0 else HASH_IVFC
        return h

    def unsupported_reason(self) -> str | None:
        """Why this section cannot be decoded, or ``None`` if it can."""
        fs = self.fs
        if fs.is_patch and (reason := self._patch_reason()):
            return reason
        if fs.has_sparse_info:
            return "sparse storage section: not supported"
        if fs.has_compression_info:
            return "compressed storage section: not supported"
        if fs.has_metadata_hash_info:
            return "metadata hash layer (14.0.0+): not supported"
        if fs.encryption_type == ENC_CTR_SKIP:
            return "AES-CTR skip-layer-hash section (14.0.0+): not supported"
        if fs.fs_type not in (FS_PFS0, FS_ROMFS):
            return f"unknown section format type {fs.fs_type}"
        known = (ENC_CTR_EX,) if fs.is_patch else (ENC_NONE, ENC_XTS, ENC_CTR)
        if fs.encryption_type not in known and not self.nca.plaintext:
            return f"unknown encryption type {fs.encryption_type}"
        if fs.hash_type in HASH_SHA3:
            return f"unsupported hash type {fs.hash_type} ({HASH_NAMES[fs.hash_type]}, 14.0.0+)"
        if self.effective_hash_type not in (HASH_NONE, HASH_SHA256, HASH_IVFC):
            return f"unsupported hash type {fs.hash_type}"
        if fs.encryption_type == ENC_XTS and self.nca.header.has_rights_id:
            return "AES-XTS section with a rights ID: not supported"
        return None

    def _patch_reason(self) -> str | None:
        fs = self.fs
        if fs.encryption_type == ENC_CTR_EX_SKIP:
            return "BKTR patch section with skip-layer-hash encryption (14.0.0+): not supported"
        if fs.fs_type != FS_ROMFS:
            return "BKTR patch section that is not a RomFS: not supported"
        base = self.nca.base
        if base is None:
            return "BKTR patch section (update/patch NCA): needs the base game (pass --base)"
        try:
            base_section = base.section(self.index)
        except NxError:
            return f"the base game's NCA has no section {self.index} to patch"
        if base_section.kind != "RomFS":
            return f"the base game's section {self.index} is not a RomFS"
        if reason := base_section.unsupported_reason():
            return f"the base game's section {self.index}: {reason}"
        return None

    def check_supported(self) -> None:
        if reason := self.unsupported_reason():
            raise UnsupportedError(f"section {self.index}: {reason}")

    def storage(self) -> Storage:
        """The whole section, decrypted (including hash tables); patched for BKTR."""
        self.check_supported()
        if self.fs.is_patch:
            return self._patched
        keys = (
            None
            if self.nca.plaintext or self.fs.encryption_type == ENC_NONE
            else (self.nca.content_keys())
        )
        mode = ENC_NONE if self.nca.plaintext else self.fs.encryption_type
        return DecryptedSection(
            self.nca.storage, self.offset, self.size, mode, keys, self.fs.ctr_upper
        )

    @cached_property
    def _patched(self) -> IndirectStorage:
        """Base game section + this update's patch data, combined per the BKTR tables."""
        assert self.nca.base is not None
        keys = None if self.nca.plaintext else self.nca.content_keys()
        # Both tables use the section's normal AES-CTR counter. Reference: hactool,
        # nxdumptool (Switchbrew: "the BKTR entries use normal crypto").
        tables = DecryptedSection(
            self.nca.storage, self.offset, self.size, ENC_CTR, keys, self.fs.ctr_upper
        )
        info = self.fs.raw[0x100:0x140]
        relocation = TableInfo.parse(info[:0x20], "relocation")
        subsection = TableInfo.parse(info[0x20:], "subsection")
        patch = AesCtrExStorage(
            self.nca.storage.slice(self.offset, self.size),
            self.offset,
            None if keys is None else keys.ctr,
            self.fs.ctr_upper[:4],  # SecureValue; the generation comes from each entry
            read_bucket_tree(tables, subsection, AES_CTR_EX_ENTRY_SIZE, "subsection"),
        )
        base = self.nca.base.section(self.index).storage()
        return IndirectStorage(
            base, patch, read_bucket_tree(tables, relocation, INDIRECT_ENTRY_SIZE, "relocation")
        )

    @cached_property
    def hash_layout(self) -> HashLayout:
        info = self.fs.hash_info
        htype = self.effective_hash_type
        if htype == HASH_NONE:
            return HashLayout(HASH_NONE, 0, self.size)
        if htype == HASH_SHA256:
            # Spec: https://switchbrew.org/wiki/NCA#HierarchicalSha256
            block, count = u32(info, 0x20), u32(info, 0x24)
            if not 1 <= count <= 5:
                raise FormatError(f"section {self.index}: bad HierarchicalSha256 layer count")
            if not MIN_HASH_BLOCK <= block <= MAX_HASH_BLOCK:
                raise FormatError(f"section {self.index}: bad HierarchicalSha256 block size")
            layers = tuple(
                (u64(info, 0x28 + 0x10 * i), u64(info, 0x30 + 0x10 * i), block)
                for i in range(count)
            )
            off, size, _ = layers[-1]
            return HashLayout(HASH_SHA256, off, size, info[:0x20], block, layers)
        if htype == HASH_IVFC:
            # Spec: https://switchbrew.org/wiki/NCA#HierarchicalIntegrity
            if info[:4] != b"IVFC":
                raise FormatError(f"section {self.index}: missing IVFC header")
            n = u32(info, 0xC) - 1  # MaxLayers counts the master hash (per the references)
            if not 1 <= n <= 6:
                raise FormatError(f"section {self.index}: bad IVFC level count")
            log2s = [u32(info, 0x20 + 0x18 * i) for i in range(n)]
            # min() first: shifting by a corrupt u32 would build a gigantic integer.
            if not all(MIN_HASH_BLOCK <= 1 << min(b, 32) <= MAX_HASH_BLOCK for b in log2s):
                raise FormatError(f"section {self.index}: bad IVFC block size")
            levels = tuple(
                (u64(info, 0x10 + 0x18 * i), u64(info, 0x18 + 0x18 * i), 1 << log2s[i])
                for i in range(n)
            )
            off, size, _ = levels[-1]
            return HashLayout(HASH_IVFC, off, size, info[0xC0:0xE0], 0, levels)
        raise UnsupportedError(f"section {self.index}: unsupported hash type {htype}")

    def data(self) -> Storage:
        """The payload (a PFS0 or RomFS image) with hash tables stripped."""
        layout = self.hash_layout
        return self.storage().slice(layout.data_offset, layout.data_size)

    def check_master_hash(self) -> bool:
        """Cheap decryption check: the top hash level matches the header's master hash."""
        layout = self.hash_layout
        st = self.storage()
        if layout.kind == HASH_SHA256:
            off, size, _ = layout.levels[0]
            return st.sha256(off, size) == layout.master_hash
        if layout.kind == HASH_IVFC:
            off, size, block = layout.levels[0]
            if size > block:  # one master hash covers exactly one level-0 block
                return False
            data = st.read_at(off, size)
            return hashlib.sha256(data.ljust(block, b"\0")).digest() == layout.master_hash
        return True


class Nca:
    """An opened NCA. Tickets are only needed for rights-ID (titlekey) NCAs.

    ``base`` is the base game's NCA of the same content type, for an update NCA
    whose BKTR sections read from it.
    """

    def __init__(
        self,
        storage: Storage,
        keyset: Keyset | None,
        tickets: Mapping[bytes, Ticket] | None = None,
        name: str = "",
        base: Nca | None = None,
    ) -> None:
        self.storage = storage
        self.keyset = keyset
        self.tickets = dict(tickets or {})
        self.name = name
        self.base = base
        raw = storage.read_at(0, HEADER_SIZE) if storage.size >= HEADER_SIZE else b""
        plain, self.plaintext = decrypt_header(raw, keyset)
        self.header = NcaHeader(plain)
        self._keys: ContentKeys | None = None

    @cached_property
    def sections(self) -> list[Section]:
        out = []
        for i in range(4):
            start, end = self.header.section_bounds(i)
            if end <= start:
                continue
            if start < HEADER_SIZE or end > self.storage.size:
                raise FormatError(f"section {i} lies outside the NCA (truncated file?)")
            out.append(Section(self, i, start, end - start, self.header.fs_header(i)))
        return out

    def content_keys(self) -> ContentKeys:
        """Decrypt the key area, or unwrap the title key from the matching ticket."""
        if self._keys is not None:
            return self._keys
        if self.keyset is None:
            raise MissingKeyError("prod.keys")
        h = self.header
        rev = h.master_key_revision
        try:
            if h.has_rights_id:
                ticket = self.tickets.get(h.rights_id)
                if ticket is None:
                    raise MissingTicketError(
                        f"NCA uses rights ID {h.rights_id.hex()} but no matching ticket was "
                        "found (pass --ticket, or use the NSP/XCI that contains it)"
                    )
                if ticket.is_personalized:
                    raise UnsupportedError(
                        "personalized ticket (title key bound to a console): only common "
                        "tickets are supported"
                    )
                title_key = ecb_decrypt(self.keyset.titlekek(rev), ticket.encrypted_title_key)
                self._keys = ContentKeys(xts=None, ctr=title_key)
            else:
                plain = ecb_decrypt(self.keyset.key_area_key(rev, h.kaek_index), h.key_area)
                self._keys = ContentKeys(xts=plain[:0x20], ctr=plain[0x20:0x30])
        except MissingKeyError as e:
            raise MissingKeyError(
                e.key_name,
                f"this NCA uses key generation {h.key_generation}; "
                "your keys may be older than this title",
            ) from None
        return self._keys

    def section(self, index: int) -> Section:
        for s in self.sections:
            if s.index == index:
                return s
        raise NxError(f"NCA has no section {index}")
