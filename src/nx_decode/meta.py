"""Content metadata (CNMT) and application control properties (NACP).

* CNMT, the ``*.cnmt`` file in a Meta NCA's PFS0 section.
  Spec: https://switchbrew.org/wiki/CNMT (header, 0x38-byte content record),
  https://switchbrew.org/wiki/NCM_services (ContentMetaType, ContentType).
  Reference: libnintendo-hac ``cnmt.h`` (records start after the extended header).
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

    @property
    def type_name(self) -> str:
        return CONTENT_RECORD_TYPES.get(self.type, f"Unknown({self.type})")


@dataclass(frozen=True)
class Cnmt:
    title_id: int
    version: int
    type: int
    contents: tuple[ContentRecord, ...]

    @property
    def type_name(self) -> str:
        return META_TYPES.get(self.type, f"Unknown({self.type:#x})")


def parse_cnmt(data: bytes) -> Cnmt:
    """Parse a packaged content meta: 0x20-byte header, extended header, 0x38-byte records."""
    if len(data) < 0x20:
        raise FormatError("CNMT is too short")
    ext_size, count = u16(data, 0xE), u16(data, 0x10)
    base = 0x20 + ext_size
    if base + count * 0x38 > len(data):
        raise FormatError("CNMT content records are truncated")
    records = []
    for i in range(count):
        r = data[base + i * 0x38 : base + (i + 1) * 0x38]
        # 15.0.0+: 5-byte size, then ContentAttributes at 0x35 (older CNMTs leave it 0).
        size = u32(r, 0x30) | (r[0x34] << 32)
        records.append(ContentRecord(r[:0x20], r[0x20:0x30], size, r[0x36]))
    return Cnmt(u64(data, 0), u32(data, 8), data[0xC], tuple(records))


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
