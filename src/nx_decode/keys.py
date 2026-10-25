"""Parse a hactool-style ``prod.keys`` and resolve the keys NCAs need.

File format: one ``name = hexvalue`` per line, ``#`` starts a comment, names are
case-insensitive, indexed names use two lowercase hex digits (``master_key_0a``).

Pre-derived keys (``header_key``, ``key_area_key_{application,ocean,system}_XX``,
``titlekek_XX``) are used when present. Otherwise they are derived from
``master_key_XX`` and the ``*_source`` seeds.
Reference: hactool ``pki.c`` ``pki_derive_keys``/``generate_kek``. Switchbrew's
Cryptosystem, SPL services and SMC pages do not describe this derivation chain.

Key values never leave this module except as raw ``bytes`` handed to the
crypto layer; nothing here formats a value into a string.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path

from .crypto import ecb_decrypt
from .errors import KeysError, MissingKeyError

DEFAULT_KEYS_PATH = Path("~/.switch/prod.keys")
KEYS_ENV = "SWITCH_KEYS"

KAEK_NAMES = ("application", "ocean", "system")

_LINE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*[=,]\s*([0-9A-Fa-f]+)\s*$")


def resolve_keys_path(cli_path: str | os.PathLike[str] | None = None) -> Path:
    """Pick the keys file: ``--keys`` beats ``$SWITCH_KEYS`` beats ``~/.switch/prod.keys``."""
    if cli_path:
        path = Path(cli_path)
    elif os.environ.get(KEYS_ENV):
        path = Path(os.environ[KEYS_ENV])
    else:
        path = DEFAULT_KEYS_PATH
    path = path.expanduser()
    if not path.is_file():
        raise KeysError(
            f"keys file not found: {path} (use --keys PATH or set ${KEYS_ENV}; "
            "nx-decode does not ship or download keys)"
        )
    return path


def parse_keys(text: str) -> dict[str, bytes]:
    """Parse keys-file text into ``{lowercase name: bytes}``.

    Errors report the line number and key name, never the value.
    """
    keys: dict[str, bytes] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _LINE.match(line)
        if not m:
            raise KeysError(f"keys file line {lineno}: expected 'name = hex'")
        name, value = m.group(1).lower(), m.group(2)
        if len(value) % 2:
            raise KeysError(f"keys file line {lineno}: odd-length hex for {name}")
        keys[name] = bytes.fromhex(value)
    return keys


def _gen_kek(src: bytes, master_key: bytes, kek_seed: bytes, key_seed: bytes) -> bytes:
    """``ECB(ECB(ECB(master_key, kek_seed), src), key_seed)``: Nintendo's GenerateAesKek+Key."""
    kek = ecb_decrypt(master_key, kek_seed)
    src_kek = ecb_decrypt(kek, src)
    return ecb_decrypt(src_kek, key_seed)


class Keyset:
    """Lookup and on-demand derivation of NCA-related keys."""

    def __init__(self, keys: dict[str, bytes]) -> None:
        self._keys = dict(keys)
        self._derived: dict[str, bytes] = {}

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> Keyset:
        try:
            # utf-8-sig: Windows Notepad may save the file with a byte-order mark.
            text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
        except OSError as e:
            raise KeysError(f"cannot read keys file {path}: {e.strerror}") from None
        return cls(parse_keys(text))

    @classmethod
    def load(cls, cli_path: str | os.PathLike[str] | None = None) -> Keyset:
        return cls.from_file(resolve_keys_path(cli_path))

    def __repr__(self) -> str:
        return f"<Keyset with {len(self._keys)} entries>"

    __str__ = __repr__

    def names(self) -> set[str]:
        return set(self._keys)

    def has(self, name: str) -> bool:
        return name in self._keys

    def _raw(self, name: str, size: int = 16, hint: str = "") -> bytes:
        try:
            value = self._keys[name]
        except KeyError:
            raise MissingKeyError(name, hint) from None
        if len(value) != size:
            raise KeysError(f"key {name} has the wrong length (expected {size} bytes)")
        return value

    def _missing(self, *names: str) -> list[str]:
        return [n for n in names if n not in self._keys]

    def header_key(self) -> bytes:
        """The 32-byte AES-XTS key for NCA headers."""
        if "header_key" in self._keys:
            return self._raw("header_key", 32)
        if "header_key" in self._derived:
            return self._derived["header_key"]
        needed = (
            "master_key_00",
            "header_kek_source",
            "header_key_source",
            "aes_kek_generation_source",
            "aes_key_generation_source",
        )
        if missing := self._missing(*needed):
            raise MissingKeyError("header_key", "or, to derive it: " + ", ".join(missing))
        kek = _gen_kek(
            self._raw("header_kek_source"),
            self._raw("master_key_00"),
            self._raw("aes_kek_generation_source"),
            self._raw("aes_key_generation_source"),
        )
        key = ecb_decrypt(kek, self._raw("header_key_source", 32))
        self._derived["header_key"] = key
        return key

    def key_area_key(self, revision: int, index: int) -> bytes:
        """Key-area encryption key for master-key ``revision`` and KAEK ``index``."""
        if not 0 <= index < len(KAEK_NAMES):
            raise KeysError(f"unknown key-area key index {index}")
        kind = KAEK_NAMES[index]
        name = f"key_area_key_{kind}_{revision:02x}"
        return self._predefined_or_derived(
            name,
            revision,
            lambda mk: _gen_kek(
                self._raw(f"key_area_key_{kind}_source"),
                mk,
                self._raw("aes_kek_generation_source"),
                self._raw("aes_key_generation_source"),
            ),
            (
                f"key_area_key_{kind}_source",
                "aes_kek_generation_source",
                "aes_key_generation_source",
            ),
        )

    def titlekek(self, revision: int) -> bytes:
        """Title-key encryption key for master-key ``revision``."""
        return self._predefined_or_derived(
            f"titlekek_{revision:02x}",
            revision,
            lambda mk: ecb_decrypt(mk, self._raw("titlekek_source")),
            ("titlekek_source",),
        )

    def _predefined_or_derived(
        self,
        name: str,
        revision: int,
        derive: Callable[[bytes], bytes],
        sources: tuple[str, ...],
    ) -> bytes:
        if name in self._keys:
            return self._raw(name)
        if name in self._derived:
            return self._derived[name]
        master = f"master_key_{revision:02x}"
        if missing := self._missing(master, *sources):
            raise MissingKeyError(
                name,
                f"needed for master key revision {revision}; to derive it: " + ", ".join(missing),
            )
        key = derive(self._raw(master))
        self._derived[name] = key
        return key
