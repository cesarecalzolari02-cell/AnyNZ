from __future__ import annotations

import pytest
from builders import rand_key, write_keys_file
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from nx_decode.errors import KeysError, MissingKeyError
from nx_decode.keys import Keyset, parse_keys, resolve_keys_path


def ref_dec(key: bytes, data: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(data) + d.finalize()


def source_keys() -> dict[str, bytes]:
    return {
        "master_key_00": rand_key(),
        "master_key_0a": rand_key(),
        "aes_kek_generation_source": rand_key(),
        "aes_key_generation_source": rand_key(),
        "key_area_key_application_source": rand_key(),
        "key_area_key_ocean_source": rand_key(),
        "key_area_key_system_source": rand_key(),
        "titlekek_source": rand_key(),
        "header_kek_source": rand_key(),
        "header_key_source": rand_key(32),
    }


def test_parse_comments_case_and_blank_lines() -> None:
    k1, k2 = rand_key(), rand_key(32)
    text = f"# comment\n\nMaster_Key_00 = {k1.hex().upper()}  # trailing\nheader_key={k2.hex()}\n"
    keys = parse_keys(text)
    assert keys == {"master_key_00": k1, "header_key": k2}


def test_parse_error_names_line_not_value() -> None:
    secret = rand_key().hex()
    with pytest.raises(KeysError) as e:
        parse_keys(f"good = {rand_key().hex()}\nthis line is junk {secret}\n")
    assert "line 2" in str(e.value)
    assert secret not in str(e.value)


def test_predefined_keys_win() -> None:
    keys = source_keys()
    pre = rand_key()
    keys["key_area_key_application_0a"] = pre
    assert Keyset(keys).key_area_key(0x0A, 0) == pre


def test_derivation_matches_reference() -> None:
    keys = source_keys()
    ks = Keyset(keys)
    mk = keys["master_key_0a"]

    kek = ref_dec(mk, keys["aes_kek_generation_source"])
    for idx, kind in enumerate(("application", "ocean", "system")):
        src_kek = ref_dec(kek, keys[f"key_area_key_{kind}_source"])
        expected = ref_dec(src_kek, keys["aes_key_generation_source"])
        assert ks.key_area_key(0x0A, idx) == expected

    assert ks.titlekek(0x0A) == ref_dec(mk, keys["titlekek_source"])

    mk0 = keys["master_key_00"]
    hkek = ref_dec(
        ref_dec(ref_dec(mk0, keys["aes_kek_generation_source"]), keys["header_kek_source"]),
        keys["aes_key_generation_source"],
    )
    assert ks.header_key() == ref_dec(hkek, keys["header_key_source"])


def test_missing_key_names_key_without_values() -> None:
    keys = source_keys()
    ks = Keyset(keys)
    with pytest.raises(MissingKeyError) as e:
        ks.key_area_key(0x0B, 0)
    msg = str(e.value)
    assert "key_area_key_application_0b" in msg
    assert "master_key_0b" in msg
    for value in keys.values():
        assert value.hex() not in msg.lower()


def test_repr_hides_values() -> None:
    keys = source_keys()
    text = repr(Keyset(keys)) + str(Keyset(keys))
    for value in keys.values():
        assert value.hex() not in text.lower()


def test_resolve_path_precedence(tmp_path, monkeypatch) -> None:
    a = write_keys_file(tmp_path / "a.keys", {"master_key_00": rand_key()})
    b = write_keys_file(tmp_path / "b.keys", {"master_key_00": rand_key()})
    monkeypatch.setenv("SWITCH_KEYS", str(b))
    assert resolve_keys_path(a) == a
    assert resolve_keys_path(None) == b
    monkeypatch.delenv("SWITCH_KEYS")
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(KeysError, match="keys file not found"):
        resolve_keys_path(None)
    (tmp_path / ".switch").mkdir()
    default = write_keys_file(tmp_path / ".switch" / "prod.keys", {"master_key_00": rand_key()})
    assert resolve_keys_path(None) == default


def test_wrong_length_key() -> None:
    ks = Keyset({"header_key": rand_key(16)})
    with pytest.raises(KeysError, match="wrong length"):
        ks.header_key()
