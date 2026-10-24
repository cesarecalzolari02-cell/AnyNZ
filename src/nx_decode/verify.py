"""Integrity checks for containers and NCAs.

* XCI: root HFS0 header hash (card header 0x140) and each HFS0 entry's hash of
  its first ``hashed_size`` bytes (https://switchbrew.org/wiki/XCI).
* NCA content ID: the file name is the first 16 bytes of the SHA-256 of the
  whole NCA; the CNMT records the full hash and size
  (https://switchbrew.org/wiki/NCA, https://switchbrew.org/wiki/CNMT).
* NCA FS headers: SHA-256 of each FS header is stored in the main header.
* Section hash layers: HierarchicalSha256 (partial last block hashed as-is) and
  IVFC (blocks zero-padded), as in hactool ``nca_section_check_hash_table``.

Every check yields a :class:`Check`; ``ok=None`` means skipped (unsupported or
``quick`` mode), never failed.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass

from .containers import Container, ContainerFile, PartitionFS
from .errors import MissingKeyError, NxError, UnsupportedError
from .io import CHUNK, Storage
from .keys import Keyset
from .meta import ContentRecord
from .nca import HASH_IVFC, HASH_SHA256, Nca, Section
from .title import inspect

CONTENT_ID = re.compile(r"^([0-9a-fA-F]{32})(?:\.cnmt)?\.nca$")


@dataclass(frozen=True)
class Check:
    subject: str
    what: str
    ok: bool | None
    detail: str = ""


def _hfs0_checks(name: str, pfs: PartitionFS) -> Iterator[Check]:
    for e in pfs.entries:
        n = min(e.hashed_size, e.size)
        ok = hashlib.sha256(pfs.open(e).read_at(0, n)).digest() == e.hash
        yield Check(f"{name}/{e.name}", "HFS0 entry hash", ok)


def xci_checks(c: Container) -> Iterator[Check]:
    assert c.xci_header is not None and c.root is not None
    h = c.xci_header
    root = c.root.storage.read_at(0, h.root_header_size)
    yield Check("XCI", "root HFS0 header hash", hashlib.sha256(root).digest() == h.root_header_hash)
    yield from _hfs0_checks("root", c.root)
    for name, part in c.partitions.items():
        yield from _hfs0_checks(name, part)


def _hash_blocks(st: Storage, off: int, size: int, block: int, table: bytes, pad: bool) -> bool:
    """Hash ``size`` bytes at ``off`` in ``block``-sized pieces against ``table``."""
    if block <= 0 or len(table) < 32 * (-(-size // block)):
        return False
    step = max(block, CHUNK // block * block)
    idx = 0
    pos = 0
    while pos < size:
        chunk = st.read_at(off + pos, min(step, size - pos))
        for i in range(0, len(chunk), block):
            piece = chunk[i : i + block]
            if pad:
                piece = piece.ljust(block, b"\0")
            if hashlib.sha256(piece).digest() != table[idx * 32 : idx * 32 + 32]:
                return False
            idx += 1
        pos += len(chunk)
    return True


def section_hash_tables_ok(section: Section) -> bool:
    """Full check of every hash level below the master hash."""
    layout = section.hash_layout
    st = section.storage()
    levels = layout.levels
    for i in range(1, len(levels)):
        h_off, h_size, _ = levels[i - 1]
        d_off, d_size, block = levels[i]
        table = st.read_at(h_off, h_size)
        if not _hash_blocks(st, d_off, d_size, block, table, pad=layout.kind == HASH_IVFC):
            return False
    return True


def nca_checks(nca: Nca, subject: str, quick: bool) -> Iterator[Check]:
    h = nca.header
    for s in nca.sections:
        ok = hashlib.sha256(s.fs.raw).digest() == h.fs_header_hash(s.index)
        yield Check(subject, f"section {s.index} FS header hash", ok)
    for s in nca.sections:
        what = f"section {s.index} ({s.kind})"
        if reason := s.unsupported_reason():
            yield Check(subject, what, None, reason)
            continue
        try:
            if not s.check_master_hash():
                yield Check(subject, f"{what} master hash", False)
                continue
            yield Check(subject, f"{what} master hash", True)
            if quick:
                yield Check(subject, f"{what} hash tables", None, "skipped (--quick)")
            elif s.hash_layout.kind in (HASH_SHA256, HASH_IVFC):
                yield Check(subject, f"{what} hash tables", section_hash_tables_ok(s))
        except (MissingKeyError, UnsupportedError) as e:
            yield Check(subject, what, None, str(e))
        except NxError as e:
            yield Check(subject, what, False, str(e))


def content_id_checks(
    f: ContainerFile, record: ContentRecord | None, quick: bool
) -> Iterator[Check]:
    m = CONTENT_ID.match(f.name)
    if quick:
        yield Check(f.path, "content ID (SHA-256)", None, "skipped (--quick)")
        return
    if not m and record is None:
        yield Check(f.path, "content ID (SHA-256)", None, "file name is not a content ID")
        return
    digest = f.storage.sha256()
    if m:
        yield Check(f.path, "content ID = SHA-256[:16]", digest[:16] == bytes.fromhex(m.group(1)))
    if record is not None:
        yield Check(f.path, "CNMT hash", digest == record.hash)
        yield Check(f.path, "CNMT size", f.size == record.size)


def verify_container(c: Container, keyset: Keyset | None, quick: bool = False) -> list[Check]:
    checks: list[Check] = []
    if c.kind == "XCI":
        checks.extend(xci_checks(c))
    report = inspect(c, keyset)
    records = {r.content_id: r for m in report.metas for r in m.contents}
    for rep in report.ncas:
        m = CONTENT_ID.match(rep.file.name)
        record = records.get(bytes.fromhex(m.group(1))) if m else None
        checks.extend(content_id_checks(rep.file, record, quick))
        if rep.nca is None:
            ok = False if rep.problem_is_failure else None
            checks.append(Check(rep.file.path, "NCA", ok, rep.problem))
            continue
        checks.extend(nca_checks(rep.nca, rep.file.path, quick))
    for note in report.notes:
        checks.append(Check("container", "note", None, note))
    return checks
