"""Large files must be streamed, never read into memory whole."""

from __future__ import annotations

import subprocess
import sys
import tracemalloc
from pathlib import Path

from builders import build_game, build_pfs0, write_keys_file

from nx_decode.cli import main

BIG = 96 * 1024 * 1024


def test_extract_big_entry_with_bounded_memory(tmp_path) -> None:
    # A PFS0 whose single entry is a 96 MiB sparse file: cheap on disk, big in memory.
    header = build_pfs0([("big.bin", b"")])
    header = header[:0x10] + header[0x10:0x18] + BIG.to_bytes(8, "little") + header[0x20:]
    nsp = tmp_path / "big.nsp"
    with open(nsp, "wb") as f:
        f.write(header)
        f.truncate(len(header) + BIG)

    tracemalloc.start()
    try:
        assert main(["extract", str(nsp), "-o", str(tmp_path / "out")]) == 0
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert (tmp_path / "out" / "big.bin").stat().st_size == BIG
    assert peak < 16 * 1024 * 1024, f"peak memory {peak:,} bytes"


def test_smoke_script_prints_only(tmp_path) -> None:
    game = build_game(rights_id=True)
    nsp = tmp_path / "g.nsp"
    nsp.write_bytes(build_pfs0(game.files))
    keys = write_keys_file(tmp_path / "k.keys", game.keys)
    before = set(tmp_path.iterdir())
    script = Path(__file__).resolve().parent.parent / "scripts" / "smoke.py"
    run = subprocess.run(
        [sys.executable, str(script), str(keys), str(nsp), "--extract", "--full"],
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert "Test Game" in run.stdout and "extracted" in run.stdout
    assert set(tmp_path.iterdir()) == before
    for value in game.keys.values():
        assert value.hex() not in (run.stdout + run.stderr).lower()
