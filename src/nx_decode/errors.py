"""Exception types.

Messages are written for end users. They may name a key but must never contain
key material.
"""

from __future__ import annotations


class NxError(Exception):
    """Base class for all errors reported by nx-decode."""


class FormatError(NxError):
    """The file is malformed, truncated, or not the format we expected."""


class UnsupportedError(NxError):
    """The file is valid but uses a feature nx-decode does not implement."""


class KeysError(NxError):
    """The keys file is missing or could not be parsed."""


class MissingKeyError(KeysError):
    """A key needed for this operation is not in the keys file.

    Only the key's *name* is ever stored in the exception.
    """

    def __init__(self, name: str, hint: str = "") -> None:
        self.key_name = name
        msg = f"missing key: {name}"
        if hint:
            msg += f" ({hint})"
        super().__init__(msg)
