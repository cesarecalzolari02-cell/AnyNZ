from __future__ import annotations

import io
import os
import sys

import pytest
from builders import (
    SectionSpec,
    build_dlc,
    build_game,
    build_nca,
    build_patch,
    build_pfs0,
    build_xci,
    make_keys,
    write_keys_file,
)

from nx_decode.cli import main


def test_list_and_extract_nsp(tmp_path, capsys) -> None:
    files = [("a.nca", os.urandom(0x300)), ("b.tik", os.urandom(0x2C0))]
    nsp = tmp_path / "game.nsp"
    nsp.write_bytes(build_pfs0(files))

    assert main(["list", str(nsp)]) == 0
    out = capsys.readouterr().out
    assert "NSP: 2 files" in out and "a.nca" in out and "b.tik" in out

    dest = tmp_path / "out"
    assert main(["extract", str(nsp), "-o", str(dest)]) == 0
    for name, data in files:
        assert (dest / name).read_bytes() == data


def test_extract_xci_partition(tmp_path) -> None:
    secure = [("x.nca", os.urandom(0x500))]
    xci = tmp_path / "game.xci"
    xci.write_bytes(build_xci({"update": [("u.nca", b"u" * 0x20)], "secure": secure}))
    dest = tmp_path / "out"
    assert main(["extract", str(xci), "-o", str(dest), "--partition", "secure"]) == 0
    assert (dest / "secure" / "x.nca").read_bytes() == secure[0][1]
    assert not (dest / "update").exists()


def test_errors_are_reported_not_raised(tmp_path, capsys) -> None:
    junk = tmp_path / "junk.xci"
    junk.write_bytes(os.urandom(0x800))
    assert main(["list", str(junk)]) == 1
    assert "error:" in capsys.readouterr().err
    assert main(["list", str(tmp_path / "missing.nsp")]) == 1
    nsz = tmp_path / "game.nsz"
    nsz.write_bytes(build_pfs0([("a", b"a")]))
    assert main(["list", str(nsz)]) == 1
    assert "compressed" in capsys.readouterr().err


# ------------------------------------------------------------------ decrypting commands


def game_nsp(tmp_path, **kw):
    game = build_game(**kw)
    nsp = tmp_path / "game.nsp"
    nsp.write_bytes(build_pfs0(game.files))
    keys = write_keys_file(tmp_path / "test.keys", game.keys)
    return game, nsp, keys


@pytest.mark.parametrize("rights_id", [False, True])
def test_info(tmp_path, capsys, rights_id: bool) -> None:
    game, nsp, keys = game_nsp(tmp_path, rights_id=rights_id)
    assert main(["info", "--keys", str(keys), str(nsp)]) == 0
    out = capsys.readouterr().out
    assert f"Title ID: {game.title_id:016x}" in out
    assert "Name:     Test Game" in out and "Publisher: Test Publisher" in out
    assert "Type:     Application" in out and "Display version: 1.2.3" in out
    assert out.count("decrypts with your keys: yes") == 3
    for value in game.keys.values():
        assert value.hex() not in out.lower()


def test_info_without_keys_or_with_personalized_ticket(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.delenv("SWITCH_KEYS", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "nohome"))
    _, nsp, _ = game_nsp(tmp_path)
    assert main(["info", str(nsp)]) == 1
    captured = capsys.readouterr()
    assert "keys file not found" in captured.err
    assert "missing key: header_key" in captured.out

    _, nsp, keys = game_nsp(tmp_path, rights_id=True, personalized=True)
    assert main(["info", "--keys", str(keys), str(nsp)]) == 1
    assert "personalized ticket" in capsys.readouterr().out


def test_info_reports_unknown_key_generation(tmp_path, capsys) -> None:
    game, nsp, _ = game_nsp(tmp_path, key_generation=20)
    keys = write_keys_file(tmp_path / "old.keys", {"header_key": game.keys["header_key"]})
    assert main(["info", "--keys", str(keys), str(nsp)]) == 1
    out = capsys.readouterr().out
    assert "missing key: key_area_key_application_13" in out
    assert "key generation 20" in out


def test_nca_extract_container(tmp_path, capsys) -> None:
    game, nsp, keys = game_nsp(tmp_path, rights_id=True)
    out = tmp_path / "out"
    assert main(["nca-extract", "--keys", str(keys), str(nsp), "-o", str(out)]) == 0
    program = game.files[0][0].split(".")[0]
    for name, data in game.exefs_files:
        assert (out / program / "section0_exefs" / name).read_bytes() == data
    assert (out / program / "section1_romfs" / "data" / "sub" / "deep.txt").read_bytes() == b"hi\n"
    meta = game.files[2][0].split(".")[0]
    assert any((out / meta / "section0_pfs0").glob("*.cnmt"))


def test_nca_extract_standalone_with_ticket(tmp_path) -> None:
    game, _, keys = game_nsp(tmp_path, rights_id=True)
    (tmp_path / "p.nca").write_bytes(game.files[0][1])
    (tmp_path / "t.tik").write_bytes(game.files[3][1])
    out = tmp_path / "out"
    args = ["nca-extract", "--keys", str(keys), str(tmp_path / "p.nca"), "-o", str(out)]
    assert main(args) == 1  # no ticket: reported, not crashed
    assert main([*args, "--ticket", str(tmp_path / "t.tik"), "--section", "1"]) == 0
    assert (out / "section1_romfs" / "readme.txt").exists()
    assert not (out / "section0_exefs").exists()


def test_list_standalone_nca(tmp_path, capsys) -> None:
    game, _, keys = game_nsp(tmp_path)
    (tmp_path / "p.nca").write_bytes(game.files[0][1])
    assert main(["list", "--keys", str(keys), str(tmp_path / "p.nca")]) == 0
    out = capsys.readouterr().out
    assert "main.npdm" in out and "data/sub/deep.txt" in out


def test_verify_ok_then_corrupted(tmp_path, capsys) -> None:
    _, nsp, keys = game_nsp(tmp_path)
    assert main(["verify", "--keys", str(keys), str(nsp)]) == 0
    out = capsys.readouterr().out
    assert "FAIL" not in out and "CNMT hash" in out and "content ID" in out

    blob = bytearray(nsp.read_bytes())
    blob[-0x10] ^= 0xFF  # last NCA (meta), inside its PFS0 data
    nsp.write_bytes(bytes(blob))
    assert main(["verify", "--keys", str(keys), str(nsp)]) == 1
    assert "FAIL" in capsys.readouterr().out


def test_verify_xci_and_quick(tmp_path, capsys) -> None:
    game = build_game()
    xci = tmp_path / "game.xci"
    xci.write_bytes(build_xci({"update": [], "normal": [], "secure": game.files}))
    keys = write_keys_file(tmp_path / "k.keys", game.keys)
    assert main(["verify", "--keys", str(keys), str(xci), "--quick"]) == 0
    out = capsys.readouterr().out
    assert "OK   XCI: root HFS0 header hash" in out and "skipped (--quick)" in out
    assert main(["info", "--keys", str(keys), str(xci)]) == 0
    assert "Test Game" in capsys.readouterr().out


def test_dlc_info_and_extract(tmp_path, capsys) -> None:
    game = build_game()
    dlc = build_dlc(game.keys, game.title_id, index=2)
    nsp = tmp_path / "dlc.nsp"
    nsp.write_bytes(build_pfs0(dlc.files))
    keys = write_keys_file(tmp_path / "k.keys", game.keys)

    assert main(["info", "--keys", str(keys), str(nsp)]) == 0
    out = capsys.readouterr().out
    assert f"Title ID: {dlc.title_id:016x}" in out and "Type:     AddOnContent" in out
    assert f"Base title: {game.title_id:016x}" in out
    assert "type Data" in out and out.count("decrypts with your keys: yes") == 2
    assert "Tickets:  1 (common)" in out

    dest = tmp_path / "out"
    assert main(["nca-extract", "--keys", str(keys), str(nsp), "-o", str(dest)]) == 0
    data_nca = dlc.files[0][0].split(".")[0]
    romfs = dest / data_nca / "section0_romfs"
    assert dlc.romfs_tree is not None
    assert (romfs / "dlc" / "item2.bin").read_bytes() == dlc.romfs_tree["dlc"]["item2.bin"]
    assert (romfs / "info.txt").read_bytes() == b"dlc\n"


def test_patch_nsp_info_keeps_bktr_unsupported(tmp_path, capsys) -> None:
    game = build_game()
    patch = build_patch(game.keys, game.title_id, version=0x20000)
    nsp = tmp_path / "update.nsp"
    nsp.write_bytes(build_pfs0(patch.files))
    keys = write_keys_file(tmp_path / "k.keys", game.keys)
    assert main(["info", "--keys", str(keys), str(nsp)]) == 0
    out = capsys.readouterr().out
    assert "Type:     Patch" in out and "Version:  v131072" in out
    assert f"Base title: {game.title_id:016x}" in out
    assert "BKTR patch section" in out and "needs the base game" in out


def test_patch_nca_is_reported(tmp_path, capsys) -> None:
    keys = make_keys()
    blob = build_nca(keys, [SectionSpec("romfs", os.urandom(0x800), patch=True)])
    (tmp_path / "patch.nca").write_bytes(blob)
    kf = write_keys_file(tmp_path / "k.keys", keys)
    assert (
        main(
            [
                "nca-extract",
                "--keys",
                str(kf),
                str(tmp_path / "patch.nca"),
                "-o",
                str(tmp_path / "o"),
            ]
        )
        == 1
    )
    assert "needs the base game" in capsys.readouterr().out
    assert main(["info", "--keys", str(kf), str(tmp_path / "patch.nca")]) == 1


def test_names_the_console_cannot_encode_do_not_crash(tmp_path, monkeypatch) -> None:
    # Redirected output on Windows uses a legacy code page such as cp1252.
    _, nsp, keys = game_nsp(tmp_path, name="ゼルダ Test")
    out = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", out)
    assert main(["info", "--keys", str(keys), str(nsp)]) == 0
    out.flush()
    assert b"Name:     ??? Test" in out.buffer.getvalue()
    assert main(["titles", "--keys", str(keys), str(nsp)]) == 0


def test_verify_rights_id_nca_without_ticket_skips_not_fails(tmp_path, capsys) -> None:
    game, _, keys = game_nsp(tmp_path, rights_id=True)
    nca, tik = tmp_path / "p.nca", tmp_path / "t.tik"
    nca.write_bytes(game.files[0][1])
    tik.write_bytes(game.files[3][1])
    assert main(["verify", "--keys", str(keys), str(nca)]) == 0
    out = capsys.readouterr().out
    assert "FAIL" not in out and "no matching ticket" in out and "2 skipped" not in out
    assert main(["verify", "--keys", str(keys), str(nca), "--ticket", str(tik)]) == 0
    out = capsys.readouterr().out
    assert "OK   p.nca: section 1 (RomFS) hash tables" in out
