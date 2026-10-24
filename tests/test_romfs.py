from __future__ import annotations

import os

import pytest
from builders import (
    SectionSpec,
    build_cnmt,
    build_nacp,
    build_nca,
    build_romfs,
    cnmt_ext,
    make_keys,
)

from nx_decode.errors import FormatError
from nx_decode.io import MemoryStorage
from nx_decode.keys import Keyset
from nx_decode.meta import parse_cnmt, parse_nacp
from nx_decode.nca import Nca
from nx_decode.romfs import RomFS


def flatten(tree: dict, prefix: str = "") -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for name, value in tree.items():
        if isinstance(value, dict):
            out |= flatten(value, f"{prefix}{name}/")
        else:
            out[prefix + name] = value
    return out


TREE = {
    "a.txt": b"alpha",
    "dir1": {"b.bin": os.urandom(0x123), "nested": {"c": b"", "d.dat": os.urandom(0x2000)}},
    "dir2": {},
    "zé.txt": b"unicode name",
}


def test_romfs_walk_and_read() -> None:
    rom = RomFS(MemoryStorage(build_romfs(TREE)))
    files = {f.path: rom.open(f).read_at(0, f.size) for f in rom.walk()}
    assert files == flatten(TREE)
    assert rom.open(rom.find("dir1/nested/d.dat")).size == 0x2000


def test_romfs_extract_through_encrypted_ivfc(tmp_path) -> None:
    keys = make_keys()
    blob = build_nca(keys, [SectionSpec("romfs", build_romfs(TREE), ivfc_block_log2=12)])
    section = Nca(MemoryStorage(blob), Keyset(keys)).sections[0]
    count, total = RomFS(section.data()).extract(tmp_path / "out")
    expected = flatten(TREE)
    assert count == len(expected) and total == sum(map(len, expected.values()))
    for path, data in expected.items():
        assert (tmp_path / "out" / path).read_bytes() == data


def test_romfs_rejects_loops_and_bad_header() -> None:
    image = bytearray(build_romfs({"a": b"x"}))
    with pytest.raises(FormatError):
        RomFS(MemoryStorage(b"\0" * 0x50))
    # Point the only file's sibling link back at itself.
    file_meta_off = int.from_bytes(image[0x38:0x40], "little")
    image[file_meta_off + 4 : file_meta_off + 8] = (0).to_bytes(4, "little")
    with pytest.raises(FormatError, match="corrupt"):
        list(RomFS(MemoryStorage(bytes(image))).walk())


def test_nacp_and_cnmt() -> None:
    nacp = parse_nacp(build_nacp("Name", "Pub", "2.0.1", lang=2))
    assert nacp.preferred() == ("Name", "Pub") and nacp.display_version == "2.0.1"
    assert parse_nacp(build_nacp("Eng", "P", lang=1)).titles[0][0] == "BritishEnglish"
    blob_a, blob_b = os.urandom(0x400), os.urandom(0x10000)
    cnmt = parse_cnmt(build_cnmt(0x0100000000001000, 0x10000, 0x81, [(blob_a, 1), (blob_b, 3)]))
    assert cnmt.type_name == "Patch" and cnmt.version == 0x10000
    assert [r.size for r in cnmt.contents] == [0x400, 0x10000]
    assert [r.type_name for r in cnmt.contents] == ["Program", "Control"]


BASE = 0x0100000000001000


@pytest.mark.parametrize(
    ("meta_type", "title_id", "application_id", "patch_id"),
    [
        (0x80, BASE, BASE, BASE + 0x800),  # Application: own ID, PatchId in the ext header
        (0x81, BASE + 0x800, BASE, None),  # Patch
        (0x82, BASE + 0x1001, BASE, None),  # AddOnContent
        (0x83, BASE + 0x800, BASE, None),  # Delta
    ],
)
def test_cnmt_extended_header(
    meta_type: int, title_id: int, application_id: int, patch_id: int | None
) -> None:
    ext = cnmt_ext(meta_type, application_id=application_id, patch_id=BASE + 0x800)
    blob = os.urandom(0x200)
    cnmt = parse_cnmt(build_cnmt(title_id, 0x10000, meta_type, [(blob, 1)], ext=ext))
    assert (cnmt.application_id, cnmt.patch_id) == (application_id, patch_id)
    assert cnmt.contents[0].size == 0x200


def test_cnmt_application_id_needs_extended_header() -> None:
    # An AddOnContent CNMT whose ext header is too short has no ApplicationId.
    cnmt = parse_cnmt(build_cnmt(BASE + 0x1001, 0, 0x82, [], ext=b""))
    assert cnmt.application_id is None


def test_cnmt_system_update_meta_infos() -> None:
    infos = [(0x0100000000000809, 0x1000, 0x02), (0x0100000000000006, 0x2000, 0x01)]
    cnmt = parse_cnmt(
        build_cnmt(0x0100000000000816, 0x3000, 0x03, [], ext=cnmt_ext(0x03), meta_infos=infos)
    )
    assert cnmt.type_name == "SystemUpdate" and cnmt.application_id is None
    assert [(m.title_id, m.version, m.type_name) for m in cnmt.meta_infos] == [
        (0x0100000000000809, 0x1000, "SystemData"),
        (0x0100000000000006, 0x2000, "SystemProgram"),
    ]
    with pytest.raises(FormatError, match="truncated"):
        parse_cnmt(build_cnmt(0x0100000000000816, 0, 0x03, [], meta_infos=infos)[:0x30])


def test_cnmt_size_ignores_content_attributes() -> None:
    # 15.0.0+ records: 5-byte size at 0x30, ContentAttributes at 0x35.
    blob = os.urandom(0x400)
    cnmt = parse_cnmt(build_cnmt(0x0100000000001000, 0, 0x80, [(blob, 1)], attributes=0x01))
    assert cnmt.contents[0].size == 0x400
