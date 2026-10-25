"""Apply an update to its base game: pair their NCAs, and pick one of several updates.

An update's NCAs with BKTR sections read from the base game's NCA of the same
content type and ID offset, both taken from the two CNMTs' content records.
Contents the update does not list stay the base game's. The update's CNMT must
name the base game as its ApplicationId.
Spec: https://switchbrew.org/wiki/CNMT (content records: type at 0x36, IdOffset
at 0x37; the Patch extended header's ApplicationId).
Reference: pairing by content type and ID offset follows nxdumptool (hactool
takes the base NCA by hand with ``--basenca``); Switchbrew does not describe it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import NxError
from .keys import Keyset
from .meta import META_APPLICATION, META_PATCH, META_TYPES, Cnmt
from .nca import CONTENT_META
from .title import NcaReport, TitleReport, probe_nca


@dataclass
class Pairing:
    """Which base NCA each update NCA patches, and what the base keeps."""

    base_meta: Cnmt | None  # None when two standalone NCAs are paired directly
    patch_meta: Cnmt | None
    base_for: dict[str, NcaReport] = field(default_factory=dict)  # update NCA path -> base
    base_only: list[NcaReport] = field(default_factory=list)  # base contents not replaced
    # The update's own content set (its CNMT's records and its Meta NCA), by path: a
    # container can also hold the base game, other updates or DLC.
    update_paths: set[str] = field(default_factory=set)

    def updated_title(self, update: TitleReport) -> list[NcaReport]:
        """The updated title: the update's NCAs, then the base contents it keeps."""
        own = [rep for rep in update.ncas if rep.file.path in self.update_paths]
        return own + self.base_only


def _by_content_id(report: TitleReport) -> dict[str, NcaReport]:
    """The NCAs of a container by content ID (their file name up to the first dot)."""
    return {rep.file.name.split(".")[0].lower(): rep for rep in report.ncas}


def only_meta(report: TitleReport, meta_type: int, name: str, what: str) -> Cnmt:
    """The single CNMT of ``meta_type`` in ``report``; an error names ``name`` otherwise."""
    metas = [m for m in report.metas if m.type == meta_type]
    if len(metas) != 1:
        found = f"{len(metas)} {META_TYPES[meta_type]} content metas" if metas else "none found"
        raise NxError(f"{name} is not {what} (needs one {META_TYPES[meta_type]} CNMT, {found})")
    return metas[0]


def pair(update: TitleReport, base: TitleReport, update_name: str, base_name: str) -> Pairing:
    """Match the update's NCAs to the base game's by content type and ID offset."""
    if update.container.kind == "NCA" and base.container.kind == "NCA":
        # Two standalone NCAs carry no CNMT to match by: they are each other's pair.
        path = update.ncas[0].file.path
        return Pairing(None, None, {path: base.ncas[0]}, update_paths={path})
    patch = only_meta(update, META_PATCH, update_name, "an update")
    app = only_meta(base, META_APPLICATION, base_name, "a base game")
    if patch.application_id != app.title_id:
        raise NxError(
            f"{update_name} is an update for {patch.application_id:016x}, "
            f"but {base_name} is {app.title_id:016x}"
        )
    update_ncas, base_ncas = _by_content_id(update), _by_content_id(base)
    kept = {(r.type, r.id_offset): r for r in app.contents}
    pairing = Pairing(app, patch)
    for record in patch.contents:
        base_record = kept.pop((record.type, record.id_offset), None)
        ours = update_ncas.get(record.content_id.hex())
        theirs = base_ncas.get(base_record.content_id.hex()) if base_record else None
        if ours is not None and theirs is not None:
            pairing.base_for[ours.file.path] = theirs
    pairing.base_only = [
        base_ncas[r.content_id.hex()] for r in kept.values() if r.content_id.hex() in base_ncas
    ]
    listed = {r.content_id.hex() for r in patch.contents}
    pairing.update_paths = {
        rep.file.path
        for content_id, rep in update_ncas.items()
        if content_id in listed
        or (
            rep.nca is not None
            and rep.nca.header.content_type == CONTENT_META
            and rep.nca.header.title_id == patch.title_id
        )
    }
    return pairing


def apply_base(update: TitleReport, pairing: Pairing, keyset: Keyset | None) -> None:
    """Re-open the update's paired NCAs with their base NCA, so BKTR sections decode."""
    for i, rep in enumerate(update.ncas):
        base = pairing.base_for.get(rep.file.path)
        if base is None or rep.nca is None:
            continue
        if base.nca is None:
            update.notes.append(f"{rep.file.path}: its base {base.file.path}: {base.problem}")
            continue
        update.ncas[i] = probe_nca(rep.file, keyset, update.tickets, base=base.nca)


def choose_update(
    updates: list[tuple[str, TitleReport]], version: int | None
) -> tuple[str, TitleReport]:
    """The update with the highest version, or the one with ``version``."""
    found = sorted(
        (
            (only_meta(rep, META_PATCH, path, "an update").version, path, rep)
            for path, rep in updates
        ),
        key=lambda f: f[0],
    )
    if version is None:
        _, path, rep = found[-1]
        return path, rep
    for v, path, rep in found:
        if v == version:
            return path, rep
    listed = ", ".join(f"v{v}" for v, _, _ in found)
    raise NxError(f"no update with version v{version} (given: {listed})")
