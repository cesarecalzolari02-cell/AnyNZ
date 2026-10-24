from __future__ import annotations

import os

import pytest
from builders import (
    SectionSpec,
    build_nca,
    build_pfs0,
    build_ticket,
    encrypt_title_key,
    make_keys,
    make_rights_id,
    rand_key,
)

from nx_decode.containers import PartitionFS
from nx_decode.crypto import nintendo_tweak
from nx_decode.errors import FormatError, MissingKeyError, NxError, UnsupportedError
from nx_decode.io import MemoryStorage
from nx_decode.keys import Keyset
from nx_decode.nca import Nca
from nx_decode.ticket import parse_ticket


def exefs_payload() -> tuple[bytes, list[tuple[str, bytes]]]:
    files = [("main", os.urandom(0x2345)), ("main.npdm", os.urandom(0x300))]
    return build_pfs0(files), files


def open_nca(blob: bytes, keys: dict[str, bytes], **kw) -> Nca:
    return Nca(MemoryStorage(blob), Keyset(keys), **kw)


def test_tweak_is_big_endian() -> None:
    assert nintendo_tweak(1) == bytes(15) + b"\x01"
    assert nintendo_tweak(0x0102) == bytes(14) + b"\x01\x02"


@pytest.mark.parametrize("crypto", ["ctr", "xts", "none"])
@pytest.mark.parametrize("nca2", [False, True])
def test_section_decryption(crypto: str, nca2: bool) -> None:
    keys = make_keys()
    pfs, files = exefs_payload()
    romfs = os.urandom(0x3000)
    blob = build_nca(
        keys,
        [SectionSpec("pfs0", pfs, crypto=crypto), SectionSpec("romfs", romfs, crypto=crypto)],
        nca2=nca2,
    )
    nca = open_nca(blob, keys)
    assert nca.header.magic == ("NCA2" if nca2 else "NCA3")
    assert nca.header.content_type_name == "Program"
    assert [s.kind for s in nca.sections] == ["PFS0", "RomFS"]

    exefs = nca.sections[0]
    assert exefs.check_master_hash()
    parsed = PartitionFS.parse(exefs.data())
    for (_, data), entry in zip(files, parsed.entries, strict=True):
        assert parsed.open(entry).read_at(0, entry.size) == data

    rom = nca.sections[1]
    assert rom.check_master_hash()
    assert rom.data().read_at(0, len(romfs)) == romfs


def test_unaligned_reads() -> None:
    keys = make_keys()
    payload = os.urandom(0x2000)
    for crypto in ("ctr", "xts"):
        blob = build_nca(keys, [SectionSpec("romfs", payload, crypto=crypto)])
        data = open_nca(blob, keys).sections[0].data()
        for off, size in [(1, 1), (15, 17), (0x1FF, 0x203), (0x1234, 0x0DCC)]:
            assert data.read_at(off, size) == payload[off : off + size]


@pytest.mark.parametrize("kaek_index", [0, 1, 2])
@pytest.mark.parametrize("key_generation", [0, 2, 3, 11])
def test_key_generation_and_kaek(kaek_index: int, key_generation: int) -> None:
    rev = max(key_generation - 1, 0)
    keys = make_keys(revisions=(rev,))
    pfs, _ = exefs_payload()
    blob = build_nca(
        keys, [SectionSpec("pfs0", pfs)], key_generation=key_generation, kaek_index=kaek_index
    )
    nca = open_nca(blob, keys)
    assert nca.header.key_generation == key_generation
    assert nca.header.master_key_revision == rev
    assert nca.sections[0].check_master_hash()


def test_keys_derived_from_master_key() -> None:
    from test_keys import source_keys

    sk = source_keys()
    derived = Keyset(sk)
    pre = {
        "header_key": derived.header_key(),
        "key_area_key_application_00": derived.key_area_key(0, 0),
    }
    pfs, _ = exefs_payload()
    blob = build_nca(pre, [SectionSpec("pfs0", pfs)], key_generation=1)
    # Opened with the *source* keys only; everything is derived on the fly.
    nca = Nca(MemoryStorage(blob), Keyset(sk))
    assert nca.sections[0].check_master_hash()


def test_missing_master_key_is_reported() -> None:
    keys = make_keys(revisions=(0,))
    pfs, _ = exefs_payload()
    blob = build_nca(
        make_keys(revisions=(0x10,)) | {"header_key": keys["header_key"]},
        [SectionSpec("pfs0", pfs)],
        key_generation=0x11,
    )
    nca = open_nca(blob, keys)
    with pytest.raises(MissingKeyError) as e:
        nca.sections[0].check_master_hash()
    msg = str(e.value)
    assert "key_area_key_application_10" in msg and "key generation 17" in msg
    for v in keys.values():
        assert v.hex() not in msg.lower()


def test_wrong_header_key() -> None:
    keys = make_keys()
    blob = build_nca(keys, [SectionSpec("pfs0", exefs_payload()[0])])
    with pytest.raises(FormatError, match="did not decrypt"):
        open_nca(blob, make_keys())


def test_plaintext_nca() -> None:
    pfs, files = exefs_payload()
    blob = build_nca(make_keys(), [SectionSpec("pfs0", pfs)], plaintext=True)
    nca = Nca(MemoryStorage(blob), None)
    assert nca.plaintext
    assert PartitionFS.parse(nca.sections[0].data()).entries[0].name == files[0][0]


@pytest.mark.parametrize("big_endian_sig", [False, True])
def test_rights_id_common_ticket(big_endian_sig: bool) -> None:
    keys = make_keys(revisions=(2,))
    title_key = rand_key()
    rid = make_rights_id(0x0100000000001000, 2)
    pfs, _ = exefs_payload()
    blob = build_nca(
        keys, [SectionSpec("pfs0", pfs)], key_generation=3, rights_id=rid, title_key=title_key
    )
    tik = parse_ticket(
        build_ticket(rid, encrypt_title_key(keys, 2, title_key), big_endian_sig=big_endian_sig)
    )
    assert tik.rights_id == rid and not tik.is_personalized
    nca = open_nca(blob, keys, tickets={rid: tik})
    assert nca.header.has_rights_id
    assert nca.sections[0].check_master_hash()


def test_rights_id_without_ticket_or_personalized() -> None:
    keys = make_keys()
    rid = make_rights_id(0x0100000000001000, 0)
    tk = rand_key()
    blob = build_nca(keys, [SectionSpec("pfs0", exefs_payload()[0])], rights_id=rid, title_key=tk)
    with pytest.raises(NxError, match="no matching ticket"):
        open_nca(blob, keys).sections[0].check_master_hash()
    personal = parse_ticket(build_ticket(rid, os.urandom(16), personalized=True))
    with pytest.raises(UnsupportedError, match="personalized"):
        open_nca(blob, keys, tickets={rid: personal}).sections[0].check_master_hash()


def test_bktr_and_unknown_hash_types_are_unsupported() -> None:
    keys = make_keys()
    blob = build_nca(
        keys,
        [
            SectionSpec("pfs0", exefs_payload()[0]),
            SectionSpec("romfs", os.urandom(0x1000), patch=True),
            SectionSpec("romfs", os.urandom(0x1000), hash_type=5),
        ],
    )
    nca = open_nca(blob, keys)
    ok, patch, sha3 = nca.sections
    assert ok.unsupported_reason() is None
    assert "BKTR" in (patch.unsupported_reason() or "")
    assert "hash type 5" in (sha3.unsupported_reason() or "")
    with pytest.raises(UnsupportedError, match="base game"):
        patch.data()


NEWER_FS_FIELDS = [
    # (SectionSpec overrides, expected reason) per Switchbrew NCA FS header
    ({"fs_bytes": {0x150: (0x40).to_bytes(8, "little")}}, "sparse"),
    ({"fs_bytes": {0x180: (0x40).to_bytes(8, "little")}}, "compressed"),
    ({"fs_bytes": {0x5: b""}}, "metadata hash"),
    ({"fs_bytes": {0x1A8: (0x40).to_bytes(8, "little")}}, "metadata hash"),
    ({"hash_type": 4}, "hash type 4 (auto (SHA3)"),
    ({"hash_type": 5}, "hash type 5 (HierarchicalSha3256"),
    ({"hash_type": 6}, "hash type 6 (HierarchicalIntegritySha3"),
    ({"enc_type": 5}, "skip-layer-hash"),
    ({"enc_type": 6}, "BKTR"),
]


@pytest.mark.parametrize(("overrides", "reason"), NEWER_FS_FIELDS)
def test_newer_fs_header_fields_are_unsupported(overrides: dict, reason: str) -> None:
    keys = make_keys()
    blob = build_nca(keys, [SectionSpec("romfs", os.urandom(0x1000), **overrides)])
    section = open_nca(blob, keys).sections[0]
    assert reason in (section.unsupported_reason() or "")
    with pytest.raises(UnsupportedError):
        section.data()


def test_truncated_nca() -> None:
    keys = make_keys()
    blob = build_nca(keys, [SectionSpec("romfs", os.urandom(0x4000))])
    with pytest.raises(FormatError):
        _ = open_nca(blob[:0x1000], keys).sections
    with pytest.raises(FormatError):
        open_nca(blob[:0x100], keys)
