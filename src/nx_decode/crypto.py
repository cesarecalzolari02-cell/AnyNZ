"""AES primitives as Nintendo uses them, built on ``cryptography``.

* ECB: key derivation, key-area and title-key unwrapping.
* XTS: NCA headers and XTS sections. Nintendo's tweak is the sector number as a
  16-byte *big-endian* integer (standard XTS uses little-endian), see
  https://switchbrew.org/wiki/NCA#Encryption (cross-checked: hactool ``aes.c``
  ``get_tweak``, libnintendo-hac ``AesXtsMakeTweak``).
* CTR: NCA sections. The 16-byte counter is 8 bytes derived from the section
  header followed by ``(absolute NCA offset >> 4)`` as a big-endian u64, see
  https://switchbrew.org/wiki/NCA#Encryption.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SECTOR = 0x200


def ecb_decrypt(key: bytes, data: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(data) + d.finalize()


def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(data) + e.finalize()


def nintendo_tweak(sector: int) -> bytes:
    return sector.to_bytes(16, "big")


def _xts(key: bytes, data: bytes, sector: int, sector_size: int, encrypt: bool) -> bytes:
    if len(key) != 32:
        raise ValueError("AES-128-XTS needs a 32-byte key")
    if len(data) % sector_size:
        raise ValueError("XTS data must be a whole number of sectors")
    out = bytearray()
    for i in range(0, len(data), sector_size):
        cipher = Cipher(algorithms.AES(key), modes.XTS(nintendo_tweak(sector)))
        ctx = cipher.encryptor() if encrypt else cipher.decryptor()
        out += ctx.update(data[i : i + sector_size]) + ctx.finalize()
        sector += 1
    return bytes(out)


def xts_decrypt(key: bytes, data: bytes, sector: int, sector_size: int = SECTOR) -> bytes:
    """Decrypt whole sectors, the first one being sector number ``sector``."""
    return _xts(key, data, sector, sector_size, encrypt=False)


def xts_encrypt(key: bytes, data: bytes, sector: int, sector_size: int = SECTOR) -> bytes:
    return _xts(key, data, sector, sector_size, encrypt=True)


def ctr_counter(upper: bytes, offset: int) -> bytes:
    """Counter block for the 16-byte-aligned absolute NCA ``offset``."""
    return upper + (offset >> 4).to_bytes(8, "big")


def ctr_crypt(key: bytes, upper: bytes, offset: int, data: bytes) -> bytes:
    """En/decrypt ``data`` located at the 16-byte-aligned absolute NCA ``offset``."""
    if offset % 16:
        raise ValueError("CTR offset must be 16-byte aligned")
    c = Cipher(algorithms.AES(key), modes.CTR(ctr_counter(upper, offset))).decryptor()
    return c.update(data) + c.finalize()
