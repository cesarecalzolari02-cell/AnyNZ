"""Updates applied to their base game: BKTR sections, pairing and choosing updates."""

from __future__ import annotations

from pathlib import Path

import pytest
from builders import (
    build_dlc,
    build_game,
    build_patch,
    build_pfs0,
    build_xci,
    nca_name,
    write_keys_file,
)

from nx_decode.cli import main
from nx_decode.io import MemoryStorage
from nx_decode.keys import Keyset
from nx_decode.nca import Nca


def flatten(tree: dict, prefix: str = "") -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for name, value in tree.items():
        if isinstance(value, dict):
            out |= flatten(value, f"{prefix}{name}/")
        else:
            out[prefix + name] = value
    return out


def read_tree(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def library(tmp_path: Path, versions=(0x10000,), plaintext: bool = False):
    """A base game XCI (with a manual the updates keep) and updates built against it."""
    game = build_game(manual=True, plaintext=plaintext)
    base = tmp_path / "base.xci"
    base.write_bytes(build_xci({"update": [], "normal": [], "secure": game.files}))
    updates = []
    for v in versions:
        patch = build_patch(game.keys, game.title_id, version=v, base=game, plaintext=plaintext)
        path = tmp_path / f"update-v{v}.nsp"
        path.write_bytes(build_pfs0(patch.files))
        updates.append((path, patch))
    return game, base, updates, write_keys_file(tmp_path / "k.keys", game.keys)


def program_dir(out: Path, patch) -> Path:
    return out / patch.files[0][0].split(".")[0]


@pytest.mark.parametrize("plaintext", [False, True])
def test_nca_extract_with_base_produces_the_patched_romfs(tmp_path, capsys, plaintext) -> None:
    game, base, [(update, patch)], keys = library(tmp_path, plaintext=plaintext)
    out = tmp_path / "out"
    assert (
        main(["nca-extract", "--keys", str(keys), str(update), "--base", str(base), "-o", str(out)])
        == 0
    )
    text = capsys.readouterr().out
    assert f"update v65536 from {update} on base game {game.title_id:016x}" in text
    program = program_dir(out, patch)
    assert read_tree(program / "section1_romfs") == flatten(patch.romfs_tree)
    assert patch.exefs_files is not None
    for name, data in patch.exefs_files:
        assert (program / "section0_exefs" / name).read_bytes() == data
    # The base game's manual is not in the update, so it comes from the base.
    assert "(kept from the base game)" in text
    manual = out / game.files[2][0].split(".")[0] / "section0_romfs" / "html-document"
    assert (manual / "index.html").read_bytes() == b"<p>manual</p>\n"


def test_update_option_uses_the_highest_version_or_the_one_asked(tmp_path, capsys) -> None:
    _, base, updates, keys = library(tmp_path, versions=(0x10000, 0x20000))
    (old, old_patch), (new, new_patch) = updates
    args = [
        "nca-extract",
        "--keys",
        str(keys),
        str(base),
        "--update",
        str(old),
        "--update",
        str(new),
    ]

    assert main([*args, "-o", str(tmp_path / "a")]) == 0
    assert "update v131072 (highest of 2)" in capsys.readouterr().out
    got = read_tree(program_dir(tmp_path / "a", new_patch) / "section1_romfs")
    assert got == flatten(new_patch.romfs_tree)

    assert main([*args, "--update-version", "v65536", "-o", str(tmp_path / "b")]) == 0
    got = read_tree(program_dir(tmp_path / "b", old_patch) / "section1_romfs")
    assert got == flatten(old_patch.romfs_tree)

    assert main([*args, "--update-version", "7", "-o", str(tmp_path / "c")]) == 1
    assert "no update with version v7 (given: v65536, v131072)" in capsys.readouterr().err


def test_info_and_verify_with_base(tmp_path, capsys) -> None:
    _, base, [(update, patch)], keys = library(tmp_path)
    assert main(["info", "--keys", str(keys), str(update)]) == 0
    assert "needs the base game (pass --base)" in capsys.readouterr().out

    assert main(["info", "--keys", str(keys), str(update), "--base", str(base)]) == 0
    out = capsys.readouterr().out
    assert "Base game: base.xci" in out and "needs the base game" not in out
    assert out.count("decrypts with your keys: yes") == 3

    assert main(["verify", "--keys", str(keys), str(update), "--base", str(base)]) == 0
    out = capsys.readouterr().out
    program = patch.files[0][0]
    assert f"OK   {program}: section 1 (RomFS) hash tables" in out
    assert "FAIL" not in out and "BKTR" not in out


def test_corrupt_patch_data_fails_verify(tmp_path, capsys) -> None:
    game, base, [(update, patch)], keys = library(tmp_path)
    name, blob = patch.files[0]
    section = Nca(MemoryStorage(blob), Keyset(game.keys)).sections[1]
    damaged = bytearray(blob)
    damaged[section.offset + 0x10] ^= 0xFF  # first subsection of the patch data
    files = [(name, bytes(damaged)), *patch.files[1:]]
    update.write_bytes(build_pfs0(files))
    assert main(["verify", "--keys", str(keys), str(update), "--base", str(base)]) == 1
    assert f"FAIL {name}: section 1 (RomFS)" in capsys.readouterr().out


def test_standalone_ncas_pair_directly(tmp_path) -> None:
    game, _, [(_, patch)], keys = library(tmp_path)
    base_nca, update_nca = tmp_path / "base.nca", tmp_path / "update.nca"
    base_nca.write_bytes(game.files[0][1])
    update_nca.write_bytes(patch.files[0][1])
    ticket = tmp_path / "update.tik"
    ticket.write_bytes(next(b for n, b in patch.files if n.endswith(".tik")))
    out = tmp_path / "out"
    args = ["nca-extract", "--keys", str(keys), str(update_nca), "--ticket", str(ticket)]
    assert main([*args, "--base", str(base_nca), "-o", str(out)]) == 0
    assert read_tree(out / "section1_romfs") == flatten(patch.romfs_tree)


def test_mismatched_base_or_not_an_update(tmp_path, capsys) -> None:
    game, base, [(update, _)], keys = library(tmp_path)
    other = build_game(title_id=0x0100ABCD00020000, keys=game.keys)
    other_xci = tmp_path / "other.xci"
    other_xci.write_bytes(build_xci({"secure": other.files}))

    assert main(["info", "--keys", str(keys), str(update), "--base", str(other_xci)]) == 1
    err = capsys.readouterr().err
    assert "is an update for 0100abcd00010000, but other.xci is 0100abcd00020000" in err

    assert main(["info", "--keys", str(keys), str(base), "--base", str(base)]) == 1
    assert "base.xci is not an update (needs one Patch CNMT, none found)" in capsys.readouterr().err

    out = str(tmp_path / "o")
    both = ["nca-extract", "--keys", str(keys), str(update), "--base", str(base), "-o", out]
    assert main([*both, "--update", str(update)]) == 1
    assert "not both" in capsys.readouterr().err
    assert (
        main(["nca-extract", "--keys", str(keys), str(base), "--update-version", "1", "-o", out])
        == 1
    )
    assert "--update-version chooses among the --update files" in capsys.readouterr().err


def test_content_names_are_content_ids(tmp_path) -> None:
    # The pairing finds NCAs by content ID, which is what the builders name them.
    _, _, [(_, patch)], _ = library(tmp_path)
    for name, blob in patch.files:
        if name.endswith(".nca"):
            assert name == nca_name(blob, meta=name.endswith(".cnmt.nca"))


def test_combined_container_extracts_only_the_updated_title(tmp_path, capsys) -> None:
    # One NSP holding the base game, its update and a DLC, as some tools pack them.
    game = build_game(manual=True)
    patch = build_patch(game.keys, game.title_id, base=game)
    dlc = build_dlc(game.keys, game.title_id)
    combined = tmp_path / "all-in-one.nsp"
    combined.write_bytes(build_pfs0(game.files + patch.files + dlc.files))
    keys = write_keys_file(tmp_path / "k.keys", game.keys)
    out = tmp_path / "out"
    args = ["--keys", str(keys), str(combined), "--base", str(combined)]
    assert main(["nca-extract", *args, "-o", str(out)]) == 0
    update_ncas = {n.split(".")[0] for n, _ in patch.files if n.endswith(".nca")}
    manual = game.files[2][0].split(".")[0]
    assert {p.name for p in out.iterdir()} == update_ncas | {manual}
    assert read_tree(program_dir(out, patch) / "section1_romfs") == flatten(patch.romfs_tree)
    assert capsys.readouterr().out.count("(kept from the base game)") == 1
    assert main(["info", *args]) == 0


def test_a_truncated_base_is_reported_as_unreadable(tmp_path, capsys) -> None:
    game, _, [(_, patch)], keys = library(tmp_path)
    base_nca, update_nca = tmp_path / "base.nca", tmp_path / "update.nca"
    base_nca.write_bytes(game.files[0][1][:0x1000])  # header intact, sections cut off
    update_nca.write_bytes(patch.files[0][1])
    ticket = tmp_path / "update.tik"
    ticket.write_bytes(next(b for n, b in patch.files if n.endswith(".tik")))
    args = ["info", "--keys", str(keys), str(update_nca), "--ticket", str(ticket)]
    main([*args, "--base", str(base_nca)])
    assert "the base game's NCA can't be read: section 0 lies outside the NCA" in (
        capsys.readouterr().out
    )
