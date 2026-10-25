"""Corrupt files must give clean errors, never a crash.

Seeded mutations of synthetic containers go through every command. Each must
exit 0 or 1 with its own message, never "internal error" (an exception that
escaped nx-decode's error handling). Mutations aim at the headers and tables the
parsers read; the plaintext samples expose them without a layer of ciphertext.
"""

from __future__ import annotations

import random

import pytest
from builders import build_dlc, build_game, build_patch, build_pfs0, build_xci, write_keys_file

from nx_decode.bktr import TableInfo
from nx_decode.cli import main
from nx_decode.io import MemoryStorage
from nx_decode.nca import Nca

ROUNDS = 6  # mutated copies per sample and seed
UPDATE_ROUNDS = 12  # update/base pairs: half mutate the update, half the base
INTERESTING = [0, 1, 0x7F, 0x80, 0xFF, 0x200, 0x7FFFFFFF, 0xFFFFFFFF, 1 << 40, (1 << 64) - 1]
# (marker, where the structure starts relative to it, how many bytes of it to target)
TARGETS = (
    (b"PFS0", 0, 0x100),
    (b"HFS0", 0, 0x200),
    (b"HEAD", -0x100, 0x200),  # XCI card header
    (b"NCA3", -0x200, 0xC00),  # NCA main header and FS headers
    (b"IVFC", 0, 0xF8),
    (b"\x50" + bytes(7), 0, 0x50),  # RomFS header (it starts with its own size)
)


def samples() -> dict[str, tuple[bytes, dict[str, bytes]]]:
    game = build_game(rights_id=True)
    plain = build_game(key_generation=1, plaintext=True)
    return {
        "game.nsp": (build_pfs0(game.files), game.keys),
        "game.xci": (build_xci({"update": [], "normal": [], "secure": game.files}), game.keys),
        "dlc.nsp": (build_pfs0(build_dlc(game.keys, game.title_id).files), game.keys),
        "patch.nsp": (build_pfs0(build_patch(game.keys, game.title_id).files), game.keys),
        "plain.nsp": (build_pfs0(plain.files), plain.keys),
        "plain.xci": (build_xci({"secure": plain.files}), plain.keys),
        "control.nca": (plain.files[1][1], plain.keys),
        "meta.nca": (plain.files[2][1], plain.keys),
    }


def hot_spans(blob: bytes) -> list[tuple[int, int]]:
    """``(start, length)`` of every structure the parsers read."""
    spans = [(0, 0x200)]
    for marker, back, length in TARGETS:
        i = blob.find(marker)
        while i >= 0:
            spans.append((max(i + back, 0), length))
            i = blob.find(marker, i + 1)
    return spans


def mutate(rng: random.Random, blob: bytes, spans: list[tuple[int, int]]) -> bytes:
    data = bytearray(blob)
    for _ in range(rng.choice([1, 2, 4])):
        if rng.random() < 0.9:
            start, length = rng.choice(spans)
            pos = start + rng.randrange(length)
        else:
            pos = rng.randrange(len(data))
        pos = min(pos, len(data) - 8)
        if rng.random() < 0.5:
            data[pos] = rng.randrange(256)
        else:
            width = rng.choice([4, 8])
            value = rng.choice(INTERESTING) & ((1 << (8 * width)) - 1)
            data[pos : pos + width] = value.to_bytes(width, "little")
    if rng.random() < 0.1:
        del data[rng.randrange(0x100, len(data)) :]
    return bytes(data)


@pytest.mark.parametrize("seed", [1, 2])
def test_corrupt_files_never_crash(tmp_path, capsys, seed: int) -> None:
    rng = random.Random(seed)
    for name, (blob, keys) in samples().items():
        keys_file = write_keys_file(tmp_path / "k.keys", keys)
        target = tmp_path / name
        spans = hot_spans(blob)
        for i in range(ROUNDS):
            target.write_bytes(mutate(rng, blob, spans))
            out = tmp_path / f"out{i}"
            k = ["--keys", str(keys_file)]
            for argv in (
                ["info", *k, str(target)],
                ["list", *k, str(target)],
                ["verify", *k, str(target)],
                ["nca-extract", *k, str(target), "-o", str(out)],
                ["titles", *k, str(target)],
            ):
                code = main(argv)
                err = capsys.readouterr().err
                where = f"seed {seed}, {name} round {i}, {argv[0]}"
                assert code in (0, 1), f"{where}: exit {code}"
                assert "internal error" not in err, f"{where}: {err}"


def bktr_spans(container: bytes, nca: bytes) -> list[tuple[int, int]]:
    """The relocation and subsection tables of a plaintext update NCA inside ``container``."""
    section = Nca(MemoryStorage(nca), None).sections[1]
    base = container.find(nca[:0x400]) + section.offset
    info = section.fs.raw[0x100:0x140]
    spans = []
    for half in (info[:0x20], info[0x20:]):
        table = TableInfo.parse(half, "test")
        spans += [(base + table.offset, 0x40), (base + table.offset + 0x4000, 0x80)]
    return spans


@pytest.mark.parametrize("seed", [3, 4])
def test_corrupt_updates_and_bases_never_crash(tmp_path, capsys, seed: int) -> None:
    rng = random.Random(seed)
    for plaintext in (False, True):
        gen = 1 if plaintext else 3
        game = build_game(plaintext=plaintext, key_generation=gen)
        patch = build_patch(
            game.keys, game.title_id, key_generation=gen, base=game, plaintext=plaintext
        )
        keys = write_keys_file(tmp_path / "k.keys", game.keys)
        base_blob = build_xci({"secure": game.files})
        update_blob = build_pfs0(patch.files)
        update_spans = hot_spans(update_blob)
        if plaintext:
            update_spans += bktr_spans(update_blob, patch.files[0][1])
        base, update = tmp_path / "base.xci", tmp_path / "update.nsp"
        for i in range(UPDATE_ROUNDS):
            mutate_update = i % 2 == 0
            update.write_bytes(
                mutate(rng, update_blob, update_spans) if mutate_update else update_blob
            )
            base.write_bytes(
                base_blob if mutate_update else mutate(rng, base_blob, hot_spans(base_blob))
            )
            k = ["--keys", str(keys), "--base", str(base)]
            for argv in (
                ["info", *k, str(update)],
                ["verify", *k, str(update)],
                ["nca-extract", *k, str(update), "-o", str(tmp_path / f"out{i}")],
            ):
                code = main(argv)
                err = capsys.readouterr().err
                where = f"seed {seed}, plaintext={plaintext} round {i}, {argv[0]}"
                assert code in (0, 1), f"{where}: exit {code}"
                assert "internal error" not in err, f"{where}: {err}"
