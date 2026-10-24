from __future__ import annotations

import os

import pytest
from builders import build_hfs0, build_pfs0, build_xci

from nx_decode.containers import PartitionFS, open_container
from nx_decode.errors import FormatError, UnsupportedError
from nx_decode.io import MemoryStorage, safe_join


def sample_files() -> list[tuple[str, bytes]]:
    return [
        ("0123456789abcdef0123456789abcdef.nca", os.urandom(0x1234)),
        ("fedcba9876543210fedcba9876543210.cnmt.nca", os.urandom(0x400)),
        ("empty.bin", b""),
    ]


def test_pfs0_roundtrip() -> None:
    files = sample_files()
    pfs = PartitionFS.parse(MemoryStorage(build_pfs0(files)))
    assert pfs.kind == "PFS0"
    assert [e.name for e in pfs.entries] == [n for n, _ in files]
    for (_, data), e in zip(files, pfs.entries, strict=True):
        assert pfs.open(e).read_at(0, e.size) == data


def test_hfs0_roundtrip_with_hashes() -> None:
    files = sample_files()
    pfs = PartitionFS.parse(MemoryStorage(build_hfs0(files)))
    assert pfs.kind == "HFS0"
    for (_, data), e in zip(files, pfs.entries, strict=True):
        assert pfs.open(e).read_at(0, e.size) == data
        assert e.hashed_size == min(len(data), 0x200)


def test_nsp() -> None:
    files = sample_files()
    c = open_container(MemoryStorage(build_pfs0(files)), "game.nsp")
    assert c.kind == "NSP"
    assert [f.path for f in c.content_files()] == [n for n, _ in files]


@pytest.mark.parametrize("key_area", [False, True])
def test_xci(key_area: bool) -> None:
    secure = sample_files()
    image = build_xci({"update": [], "normal": [], "secure": secure}, key_area=key_area)
    c = open_container(MemoryStorage(image), "game.xci")
    assert c.kind == "XCI"
    assert set(c.partitions) == {"update", "normal", "secure"}
    assert c.xci_header is not None and c.xci_header.base == (0x1000 if key_area else 0)
    content = c.content_files()
    assert [f.path for f in content] == [f"secure/{n}" for n, _ in secure]
    for (_, data), f in zip(secure, content, strict=True):
        assert f.storage.read_at(0, f.size) == data


def test_rejects_garbage_and_truncation() -> None:
    with pytest.raises(FormatError):
        open_container(MemoryStorage(os.urandom(0x400)), "x.bin")
    blob = build_pfs0(sample_files())
    with pytest.raises(FormatError):
        open_container(MemoryStorage(blob[: len(blob) - 10]), "cut.nsp")
    with pytest.raises(FormatError):
        open_container(MemoryStorage(b"PFS0" + b"\xff" * 12), "huge.nsp")


@pytest.mark.parametrize("name", ["game.nsz", "game.XCZ"])
def test_compressed_containers_are_reported(name: str) -> None:
    with pytest.raises(UnsupportedError, match="compressed"):
        open_container(MemoryStorage(build_pfs0(sample_files())), name)


@pytest.mark.parametrize("bad", ["../evil", "a/../../b", "C:evil", "x/..\\..\\y"])
def test_safe_join_rejects_traversal(tmp_path, bad: str) -> None:
    with pytest.raises(FormatError):
        safe_join(tmp_path, bad)


def test_safe_join_keeps_tree(tmp_path) -> None:
    assert safe_join(tmp_path, "secure/a.nca") == tmp_path / "secure" / "a.nca"
