"""Content metadata (CNMT) and application control properties (NACP).

* CNMT, the ``*.cnmt`` file in a Meta NCA's PFS0 section.
  Spec: https://switchbrew.org/wiki/CNMT (header, 0x38-byte content record with
  its content type at 0x36 and ID offset at 0x37,
  0x10-byte content meta record, the per-type extended headers),
  https://switchbrew.org/wiki/NCM_services (ContentMetaType, ContentType).
  Reference: libnintendo-hac ``cnmt.h`` (file order: header, extended header,
  content records, content meta records; the wiki lists but does not order them).
* NACP, ``control.nacp`` in a Control NCA's RomFS.
  Spec: https://switchbrew.org/wiki/NACP (title entries, languages 0-15,
  DisplayVersion). Reference: libnintendo-hac ``nacp.h``.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import FormatError
from .io import cstr, u16, u32, u64

META_TYPES = {
    0x01: "SystemProgram",
    0x02: "SystemData",
    0x03: "SystemUpdate",
    0x04: "BootImagePackage",
    0x05: "BootImagePackageSafe",
    0x80: "Application",
    0x81: "Patch",
    0x82: "AddOnContent",
    0x83: "Delta",
    0x84: "DataPatch",
}
META_SYSTEM_UPDATE = 0x03
META_APPLICATION, META_PATCH, META_ADDON, META_DELTA, META_DATA_PATCH = 0x80, 0x81, 0x82, 0x83, 0x84
# Offset of ApplicationId in each type's extended header. The Application header
# starts with PatchId instead; its application ID is its own title ID.
APPLICATION_ID_OFFSET = {META_PATCH: 0x0, META_ADDON: 0x0, META_DELTA: 0x0, META_DATA_PATCH: 0x8}
CONTENT_META_INFO_SIZE = 0x10

CONTENT_RECORD_TYPES = {
    0: "Meta",
    1: "Program",
    2: "Data",
    3: "Control",
    4: "HtmlDocument",
    5: "LegalInformation",
    6: "DeltaFragment",
}
LANGUAGES = (
    "AmericanEnglish",
    "BritishEnglish",
    "Japanese",
    "French",
    "German",
    "LatinAmericanSpanish",
    "Spanish",
    "Italian",
    "Dutch",
    "CanadianFrench",
    "Portuguese",
    "Russian",
    "Korean",
    "TraditionalChinese",
    "SimplifiedChinese",
    "BrazilianPortuguese",
)
NACP_SIZE = 0x4000


@dataclass(frozen=True)
class ContentRecord:
    hash: bytes  # SHA-256 of the whole NCA
    content_id: bytes  # first 16 bytes of that hash; the NCA's file name
    size: int
    type: int
    id_offset: int = 0  # which program of a multi-program application

    @property
    def type_name(self) -> str:
        return CONTENT_RECORD_TYPES.get(self.type, f"Unknown({self.type})")


@dataclass(frozen=True)
class ContentMetaInfo:
    """A content meta referenced by this one (system updates list their titles this way)."""

    title_id: int
    version: int
    type: int

    @property
    def type_name(self) -> str:
        return META_TYPES.get(self.type, f"Unknown({self.type:#x})")


@dataclass(frozen=True)
class Cnmt:
    title_id: int
    version: int
    type: int
    contents: tuple[ContentRecord, ...]
    # The base application this belongs to, from the extended header; ``None`` when
    # the type has no ApplicationId or the extended header is too short.
    application_id: int | None = None
    patch_id: int | None = None  # Application only: its update's title ID
    meta_infos: tuple[ContentMetaInfo, ...] = ()

    @property
    def type_name(self) -> str:
        return META_TYPES.get(self.type, f"Unknown({self.type:#x})")


def parse_cnmt(data: bytes) -> Cnmt:
    """Parse a packaged content meta: 0x20-byte header, extended header, 0x38-byte records."""
    if len(data) < 0x20:
        raise FormatError("CNMT is too short")
    title_id, meta_type = u64(data, 0), data[0xC]
    ext_size, count, meta_count = u16(data, 0xE), u16(data, 0x10), u16(data, 0x12)
    base = 0x20 + ext_size
    metas_at = base + count * 0x38
    if metas_at + meta_count * CONTENT_META_INFO_SIZE > len(data):
        raise FormatError("CNMT content records are truncated")
    ext = data[0x20:base]
    records = []
    for i in range(count):
        r = data[base + i * 0x38 : base + (i + 1) * 0x38]
        # 15.0.0+: 5-byte size, then ContentAttributes at 0x35 (older CNMTs leave it 0).
        size = u32(r, 0x30) | (r[0x34] << 32)
        records.append(ContentRecord(r[:0x20], r[0x20:0x30], size, r[0x36], r[0x37]))
    meta_infos = []
    for i in range(meta_count):
        off = metas_at + i * CONTENT_META_INFO_SIZE
        meta_infos.append(ContentMetaInfo(u64(data, off), u32(data, off + 8), data[off + 0xC]))
    application_id = patch_id = None
    if meta_type == META_APPLICATION:
        application_id = title_id
        if len(ext) >= 8:
            patch_id = u64(ext, 0)
    elif (aid_off := APPLICATION_ID_OFFSET.get(meta_type)) is not None and len(ext) >= aid_off + 8:
        application_id = u64(ext, aid_off)
    return Cnmt(
        title_id,
        u32(data, 8),
        meta_type,
        tuple(records),
        application_id,
        patch_id,
        tuple(meta_infos),
    )


@dataclass(frozen=True)
class Nacp:
    titles: tuple[tuple[str, str, str], ...]  # (language, name, publisher), non-empty only
    display_version: str

    def preferred(self) -> tuple[str, str]:
        """``(name, publisher)``, preferring English."""
        for lang in ("AmericanEnglish", "BritishEnglish"):
            for t in self.titles:
                if t[0] == lang:
                    return t[1], t[2]
        if self.titles:
            return self.titles[0][1], self.titles[0][2]
        return "", ""


def parse_nacp(data: bytes) -> Nacp:
    """Title entries: 16 x (name 0x200 + publisher 0x100) at 0; display version at 0x3060."""
    if len(data) < 0x3070:
        raise FormatError("NACP is too short")
    titles = []
    for i, lang in enumerate(LANGUAGES):
        off = i * 0x300
        name, publisher = cstr(data, off, 0x200), cstr(data, off + 0x200, 0x100)
        if name or publisher:
            titles.append((lang, name, publisher))
    return Nacp(tuple(titles), cstr(data, 0x3060, 0x10))
