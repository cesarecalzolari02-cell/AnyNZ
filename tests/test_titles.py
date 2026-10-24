from __future__ import annotations

import os
from pathlib import Path

import pytest
from builders import (
    build_dlc,
    build_game,
    build_meta_nca,
    build_patch,
    build_pfs0,
    build_xci,
    cnmt_ext,
    nca_name,
    write_keys_file,
)

from nx_decode.cli import main
from nx_decode.library import guess_application_id

BASE = 0x0100ABCD00010000


@pytest.fixture
def game():
    return build_game(title_id=BASE)


def write_nsp(path: Path, files: list[tuple[str, bytes]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_pfs0(files))
    return path


def run_titles(tmp_path: Path, keys: dict[str, bytes], *paths: Path, capsys) -> tuple[int, str]:
    kf = write_keys_file(tmp_path / "k.keys", keys)
    code = main(["titles", "--keys", str(kf), *map(str, paths)])
    out = capsys.readouterr().out
    for value in keys.values():
        assert value.hex() not in out.lower()
    return code, out


def test_guess_application_id() -> None:
    assert guess_application_id(BASE, 0x80) == BASE
    assert guess_application_id(BASE + 0x800, 0x81) == BASE
    assert guess_application_id(BASE + 0x1001, 0x82) == BASE
    assert guess_application_id(BASE + 0x1FFF, 0x82) == BASE
    assert guess_application_id(BASE + 0x800, 0x83) == BASE
    assert guess_application_id(0x0100000000000816, 0x03) is None


def test_titles_groups_base_updates_and_dlc(tmp_path, capsys, game) -> None:
    lib = tmp_path / "library"
    lib.mkdir()
    (lib / "base.xci").write_bytes(build_xci({"secure": game.files}))
    write_nsp(lib / "updates" / "v1.nsp", build_patch(game.keys, BASE, version=0x10000).files)
    write_nsp(lib / "updates" / "v2.nsp", build_patch(game.keys, BASE, version=0x20000).files)
    dlc1, dlc2 = build_dlc(game.keys, BASE, index=1), build_dlc(game.keys, BASE, index=2)
    write_nsp(lib / "dlc" / "one.nsp", dlc1.files)
    write_nsp(lib / "dlc" / "two.nsp", dlc2.files)
    (lib / "notes.txt").write_text("ignored")

    code, out = run_titles(tmp_path, game.keys, lib, capsys=capsys)
    assert code == 0, out
    assert f"{BASE:016x}  Test Game" in out
    assert "base:    v0" in out and "base.xci" in out
    assert "update:  v131072" in out and "(highest of 2)" in out
    assert f"DLC:     {dlc1.title_id:016x} v0" in out and f"DLC:     {dlc2.title_id:016x}" in out
    assert "several updates with different versions: v65536" in out
    assert "1 title(s), 1 with updates, 2 DLC, 1 warning(s), 0 error(s)" in out


def test_titles_flags_dlc_without_base_and_duplicates(tmp_path, capsys, game) -> None:
    dlc = build_dlc(game.keys, BASE)
    a = write_nsp(tmp_path / "a" / "dlc.nsp", dlc.files)
    b = write_nsp(tmp_path / "b" / "dlc copy.nsp", dlc.files)
    code, out = run_titles(tmp_path, game.keys, a, b, capsys=capsys)
    assert code == 0
    assert "base:    (not found)" in out
    assert f"DLC without its base game {BASE:016x}" in out
    assert f"duplicate content: {dlc.title_id:016x} v0 (AddOnContent)" in out
    assert str(a) in out and str(b) in out


def test_titles_flags_update_without_base_and_dlc_versions(tmp_path, capsys, game) -> None:
    upd = write_nsp(tmp_path / "u.nsp", build_patch(game.keys, BASE).files)
    old = write_nsp(tmp_path / "d0.nsp", build_dlc(game.keys, BASE, version=0).files)
    new = write_nsp(tmp_path / "d1.nsp", build_dlc(game.keys, BASE, version=0x10000).files)
    _, out = run_titles(tmp_path, game.keys, upd, old, new, capsys=capsys)
    assert f"update without its base game {BASE:016x}" in out
    assert f"{BASE + 0x1001:016x} found in several versions: v0, v65536" in out


def test_titles_uses_cnmt_application_id_over_title_id(tmp_path, capsys, game) -> None:
    # A DLC whose title ID points at another base, but whose CNMT names BASE.
    odd = build_dlc(game.keys, BASE, title_id=0x0100FFFF00020001)
    base = write_nsp(tmp_path / "base.nsp", game.files)
    dlc = write_nsp(tmp_path / "odd.nsp", odd.files)
    _, out = run_titles(tmp_path, game.keys, base, dlc, capsys=capsys)
    assert f"DLC:     {odd.title_id:016x}" in out and "1 title(s)" in out
    assert f"names base {BASE:016x} in its CNMT" in out
    assert "0100ffff00010000" not in out


def test_titles_falls_back_to_title_id_without_extended_header(tmp_path, capsys, game) -> None:
    base = write_nsp(tmp_path / "base.nsp", game.files)
    dlc = write_nsp(tmp_path / "dlc.nsp", build_dlc(game.keys, BASE, ext=b"").files)
    code, out = run_titles(tmp_path, game.keys, base, dlc, capsys=capsys)
    assert code == 0 and "1 title(s), 0 with updates, 1 DLC, 0 warning(s)" in out


def test_titles_lists_system_updates_and_reports_errors(tmp_path, capsys, game) -> None:
    sysupd = build_meta_nca(
        game.keys,
        0x0100000000000816,
        0x30000,
        0x03,
        [],
        cnmt_ext(0x03),
        3,
        meta_infos=[(0x0100000000000809, 0x30000, 0x02)],
    )
    su = write_nsp(tmp_path / "sysupdate.nsp", [(nca_name(sysupd, meta=True), sysupd)])
    junk = tmp_path / "junk.nsp"
    junk.write_bytes(os.urandom(0x400))
    nsz = tmp_path / "game.nsz"
    nsz.write_bytes(b"")
    code, out = run_titles(tmp_path, game.keys, su, junk, nsz, tmp_path / "missing", capsys=capsys)
    assert code == 1
    assert "Not part of a title:" in out
    assert "0100000000000816 v196608 (SystemUpdate)" in out
    assert "contains 0100000000000809 v196608 (SystemData)" in out
    assert "junk.nsp: " in out and "NSZ is compressed" in out and "missing: not found" in out


def test_titles_patch_ncas_stay_unsupported(tmp_path, capsys, game) -> None:
    upd = write_nsp(tmp_path / "u.nsp", build_patch(game.keys, BASE).files)
    kf = write_keys_file(tmp_path / "k.keys", game.keys)
    assert main(["nca-extract", "--keys", str(kf), str(upd), "-o", str(tmp_path / "o")]) == 1
    assert "needs the base game" in capsys.readouterr().out
