"""eTicket parsing, just enough to unwrap common title keys.

Layout: https://switchbrew.org/wiki/Ticket (cross-checked: libnintendo-es
``ticket.h`` ``sTicketBody_v2``; signature block sizes from hactool/nstool).

A ticket starts with a signature block whose size depends on the signature type,
then the body:

======  =====  =========================================
Offset  Size   Field
======  =====  =========================================
0x000   0x40   issuer
0x040   0x100  title key block (common: first 0x10 bytes)
0x140   1      format version
0x141   1      title key type (0 common, 1 personalized)
0x145   1      common key ID
0x160   0x10   rights ID
======  =====  =========================================

Personalized tickets wrap the title key with the console's RSA key, which
nx-decode cannot (and will not try to) obtain, so they are reported as unsupported.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import FormatError

# signature type -> offset of the ticket body (signature + padding to 0x40)
SIGNATURE_BODY_OFFSET = {
    0x010000: 0x240,  # RSA-4096 SHA-1
    0x010001: 0x140,  # RSA-2048 SHA-1
    0x010002: 0x80,  # ECDSA SHA-1
    0x010003: 0x240,  # RSA-4096 SHA-256
    0x010004: 0x140,  # RSA-2048 SHA-256
    0x010005: 0x80,  # ECDSA SHA-256
}
BODY_SIZE = 0x180

TITLEKEY_COMMON = 0
TITLEKEY_PERSONALIZED = 1


@dataclass(frozen=True)
class Ticket:
    rights_id: bytes
    title_key_type: int
    title_key_block: bytes
    common_key_id: int

    @property
    def is_personalized(self) -> bool:
        return self.title_key_type != TITLEKEY_COMMON

    @property
    def encrypted_title_key(self) -> bytes:
        """The AES-wrapped title key (common tickets only)."""
        return self.title_key_block[:0x10]


def body_offset(data: bytes) -> int:
    """Find where the body starts from the signature type.

    The byte order of the type is not documented consistently (Switch tickets in
    the wild start ``04 00 01 00``), so both orders are accepted.
    """
    if len(data) < 4:
        raise FormatError("ticket is too short")
    for order in ("little", "big"):
        sig_type = int.from_bytes(data[:4], order)  # type: ignore[arg-type]
        if sig_type in SIGNATURE_BODY_OFFSET:
            return SIGNATURE_BODY_OFFSET[sig_type]
    raise FormatError("ticket has an unknown signature type")


def parse_ticket(data: bytes) -> Ticket:
    off = body_offset(data)
    body = data[off : off + BODY_SIZE]
    if len(body) < BODY_SIZE:
        raise FormatError("ticket is truncated")
    return Ticket(
        rights_id=body[0x160:0x170],
        title_key_type=body[0x141],
        title_key_block=body[0x40:0x140],
        common_key_id=body[0x145],
    )
