from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest
from builders import build_hfs0, build_pfs0, build_xci, rand_key

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_forbidden.py"

spec = importlib.util.spec_from_file_location("check_forbidden", SCRIPT)
assert spec and spec.loader
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def flagged(name: str, data: bytes) -> bool:
    return any(check.problems(name, data))


def test_flags_key_lines() -> None:
    assert flagged("notes.txt", f"master_key_00 = {rand_key().hex()}\n".encode())
    assert flagged("notes.txt", f"  header_key={rand_key(32).hex().upper()}  \n".encode())
    assert not flagged("notes.txt", b"header_key = <your key here>\n")
    assert not flagged("notes.txt", f"x = {rand_key(8).hex()}\n".encode())


def test_flags_containers() -> None:
    assert flagged("blob.bin", build_pfs0([("a", b"x")]))
    assert flagged("blob.bin", build_hfs0([("a", b"x")]))
    assert flagged("blob.bin", build_xci({"secure": [("a", b"x")]}))
    assert flagged("blob.bin", build_xci({"secure": [("a", b"x")]}, key_area=True))
    ncz = bytearray(os.urandom(0x5000))
    ncz[0x4000:0x4008] = b"NCZSECTN"
    assert flagged("blob.bin", bytes(ncz))
    for ext in (".keys", ".xci", ".nsp", ".nca", ".tik", ".cert", ".nsz", ".xcz"):
        assert flagged(f"file{ext}", b"")
    assert not flagged("src/module.py", b"print('hello')\n")


def test_staged_mode_blocks_commit(tmp_path) -> None:
    def git(*args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(["git", *args], cwd=tmp_path, capture_output=True)

    git("init", "-q")
    (tmp_path / "ok.txt").write_text("fine\n")
    (tmp_path / "leak.txt").write_text(f"titlekek_00 = {rand_key().hex()}\n")
    git("add", "ok.txt")
    run = subprocess.run(["python3", str(SCRIPT), "--staged"], cwd=tmp_path, capture_output=True)
    assert run.returncode == 0
    git("add", "leak.txt")
    run = subprocess.run(["python3", str(SCRIPT), "--staged"], cwd=tmp_path, capture_output=True)
    assert run.returncode == 1
    assert b"leak.txt:1" in run.stderr
    assert b"titlekek_00 =" not in run.stderr


@pytest.mark.skipif(not (ROOT / ".git").exists(), reason="not a git checkout (e.g. an sdist)")
def test_repository_is_clean() -> None:
    run = subprocess.run(["python3", str(SCRIPT), "--all"], cwd=ROOT, capture_output=True)
    assert run.returncode == 0, run.stderr.decode()
