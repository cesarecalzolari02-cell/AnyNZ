from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parent.parent / "scripts" / "demo.py"


def load_demo():
    spec = importlib.util.spec_from_file_location("demo", DEMO)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_demo_runs_end_to_end(capsys) -> None:
    assert load_demo().main([]) == 0
    out = capsys.readouterr().out
    assert "10/10 steps behaved as expected" in out
    assert "DLC without its base game" in out and "needs the base game" in out
    assert "update v131072 (highest of 2)" in out


def test_demo_keep_refuses_the_repository() -> None:
    with pytest.raises(SystemExit):
        load_demo().main(["--keep", str(DEMO.parent)])
