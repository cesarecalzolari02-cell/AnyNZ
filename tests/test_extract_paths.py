"""Extraction when a name inside a container can't be a file here: skip it, keep going."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest
from builders import SectionSpec, build_nca, build_pfs0, build_romfs, make_keys, write_keys_file

import nx_decode.io as nx_io
from nx_decode.cli import main
from nx_decode.errors import OutputPathError
from nx_decode.io import MemoryStorage, native_path, windows_name_problem, write_entry

windows_only = pytest.mark.skipif(os.name != "nt", reason="Windows file-name rules")


def romfs_nca(tmp_path: Path, tree: dict) -> tuple[Path, Path]:
    """A standalone plaintext NCA whose RomFS holds ``tree``, and a keys file."""
    keys = make_keys()
    nca = tmp_path / "content.nca"
    nca.write_bytes(build_nca(keys, [SectionSpec("romfs", build_romfs(tree))], plaintext=True))
    return nca, write_keys_file(tmp_path / "k.keys", keys)


def extract(tmp_path: Path, tree: dict) -> tuple[int, Path]:
    nca, keys = romfs_nca(tmp_path, tree)
    out = tmp_path / "out"
    code = main(["nca-extract", "--keys", str(keys), str(nca), "-o", str(out)])
    return code, out / "section0_romfs"


def test_paths_longer_than_260_characters(tmp_path, capsys) -> None:
    deep: dict = {"payload.bin": b"deep data\n"}
    for level in range(6):
        deep = {f"{level}-{'d' * 55}": deep}
    code, root = extract(tmp_path, deep)
    assert code == 0, capsys.readouterr().out
    files = [p for p in Path(native_path(root)).rglob("*") if p.is_file()]
    assert len(files) == 1 and len(str(files[0]).removeprefix("\\\\?\\")) > 300
    assert files[0].read_bytes() == b"deep data\n"


def test_unsafe_names_are_skipped_and_the_rest_extracts(tmp_path, capsys) -> None:
    tree = {"ok.txt": b"fine\n", "c:evil.txt": b"x", "..": {"escape.txt": b"x"}, "z.txt": b"z\n"}
    code, root = extract(tmp_path, tree)
    out = capsys.readouterr().out
    assert code == 1
    assert "skipped file c:evil.txt" in out and "skipped file ../escape.txt" in out
    assert "2 skipped" in out
    assert (root / "ok.txt").read_bytes() == b"fine\n" and (root / "z.txt").exists()
    assert not (tmp_path / "out" / "escape.txt").exists()


WINDOWS_TROUBLE = {
    "bad?.txt": b"q",
    "aux.dat": b"device",
    "trail.": b"dot",
    "sub": {"x|y": b"pipe"},
}


@windows_only
def test_names_windows_forbids_are_skipped_on_windows(tmp_path, capsys) -> None:
    code, root = extract(tmp_path, {"ok.txt": b"fine\n", **WINDOWS_TROUBLE})
    out = capsys.readouterr().out
    assert code == 1
    for name in ("bad?.txt", "aux.dat", "trail.", "sub/x|y"):
        assert f"skipped file {name}" in out
    assert (root / "ok.txt").read_bytes() == b"fine\n"


@pytest.mark.skipif(os.name == "nt", reason="these names are fine outside Windows")
def test_names_windows_forbids_extract_elsewhere(tmp_path) -> None:
    code, root = extract(tmp_path, {"ok.txt": b"fine\n", **WINDOWS_TROUBLE})
    assert code == 0
    assert (root / "bad?.txt").read_bytes() == b"q" and (root / "sub" / "x|y").exists()


@windows_only
def test_container_extract_skips_unwritable_names(tmp_path, capsys) -> None:
    nsp = tmp_path / "odd.nsp"
    nsp.write_bytes(build_pfs0([("ok.bin", b"ok"), ("con.bin", b"device"), ("q?.bin", b"q")]))
    assert main(["extract", str(nsp), "-o", str(tmp_path / "out")]) == 1
    out = capsys.readouterr().out
    assert "extracted 1 files" in out and out.count("skipped:") == 2
    assert (tmp_path / "out" / "ok.bin").read_bytes() == b"ok"


def test_windows_name_rules() -> None:
    assert windows_name_problem("normal_name.bin") is None
    assert windows_name_problem("con") and windows_name_problem("NUL.txt")
    assert windows_name_problem("COM1") and windows_name_problem("lpt9.log")
    assert windows_name_problem("console") is None and windows_name_problem("com10") is None
    assert windows_name_problem('a"b') and windows_name_problem("tab\there")
    assert windows_name_problem("dot.") and windows_name_problem("space ")


@windows_only
def test_native_path_uses_the_extended_prefix() -> None:
    assert native_path(Path("C:/games/out/x.bin")) == "\\\\?\\C:\\games\\out\\x.bin"
    assert native_path(Path("//server/share/x.bin")) == "\\\\?\\UNC\\server\\share\\x.bin"


def test_a_full_disk_stops_extraction_instead_of_skipping(tmp_path, monkeypatch) -> None:
    def no_space(*args, **kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(nx_io, "open", no_space, raising=False)
    with pytest.raises(OSError) as e:
        write_entry(MemoryStorage(b"data"), tmp_path, "file.bin")
    assert not isinstance(e.value, OutputPathError)


def test_names_differing_only_in_case_never_overwrite_each_other(tmp_path, capsys) -> None:
    (tmp_path / "Probe").write_bytes(b"")
    ignores_case = (tmp_path / "probe").exists()  # Windows, macOS: yes; Linux: no
    tree = {"Data.bin": b"upper", "data.bin": b"lower", "sub": {"X.txt": b"x", "x.TXT": b"y"}}
    code, root = extract(tmp_path, tree)
    out = capsys.readouterr().out
    if ignores_case:
        assert code == 1
        assert (
            "skipped file data.bin: 'data.bin' differs only in letter case from 'Data.bin'" in out
        )
        assert "skipped file sub/x.TXT" in out
        assert (root / "Data.bin").read_bytes() == b"upper"  # the first one is kept intact
        assert (root / "sub" / "X.txt").read_bytes() == b"x"
    else:
        assert code == 0
        assert (root / "data.bin").read_bytes() == b"lower" and (root / "sub" / "x.TXT").exists()


def test_reextracting_into_the_same_folder_still_overwrites(tmp_path) -> None:
    # Files left by an earlier run are not mistaken for case collisions.
    nca, keys = romfs_nca(tmp_path, {"a.bin": b"one", "b.bin": b"two"})
    out = tmp_path / "out"
    for _ in range(2):
        assert main(["nca-extract", "--keys", str(keys), str(nca), "-o", str(out)]) == 0
    assert (out / "section0_romfs" / "b.bin").read_bytes() == b"two"
