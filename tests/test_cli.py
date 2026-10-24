from __future__ import annotations

import os

from builders import build_pfs0, build_xci

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
