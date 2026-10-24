"""Group the content sets found in many files into titles: base, updates and DLC.

A content set is one CNMT (from a Meta NCA) plus the file it came from. Sets are
attached to their base application by the CNMT's ApplicationId (Spec:
https://switchbrew.org/wiki/CNMT, Patch/AddOnContent/Delta extended headers). Only
when a CNMT has none is the base guessed from the title ID: updates are
``base + 0x800`` and DLC ``base + 0x1000 + n``. Reference: the usual title-ID
convention, as used by hactool/nstool-era tooling; Switchbrew does not document it.

System updates and other content without an application are listed, not grouped.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .containers import COMPRESSED_SUFFIXES, Container
from .errors import NxError
from .io import FileStorage, Storage
from .keys import Keyset
from .meta import META_ADDON, META_APPLICATION, META_DELTA, META_PATCH, Cnmt
from .title import inspect

SCAN_SUFFIXES = {".xci", ".nsp", ".nca"}


def guess_application_id(title_id: int, meta_type: int) -> int | None:
    """The base application ID implied by the title-ID convention, if any."""
    if meta_type == META_APPLICATION:
        return title_id
    if meta_type in (META_PATCH, META_DELTA):
        return title_id & ~0xFFF
    if meta_type == META_ADDON:
        return (title_id - 0x1000) & ~0xFFF
    return None


@dataclass(frozen=True)
class ContentSet:
    cnmt: Cnmt
    source: str  # the file it was found in
    name: str = ""  # from the set's own Control NCA, if it has one

    @property
    def application_id(self) -> int | None:
        if self.cnmt.application_id is not None:
            return self.cnmt.application_id
        return guess_application_id(self.cnmt.title_id, self.cnmt.type)

    def label(self) -> str:
        return f"{self.cnmt.title_id:016x} v{self.cnmt.version} ({self.cnmt.type_name})"


@dataclass
class TitleGroup:
    application_id: int
    base: list[ContentSet] = field(default_factory=list)
    updates: list[ContentSet] = field(default_factory=list)
    dlc: list[ContentSet] = field(default_factory=list)
    other: list[ContentSet] = field(default_factory=list)  # deltas, data patches
    warnings: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        for s in [*self.base, *sorted(self.updates, key=lambda s: -s.cnmt.version)]:
            if s.name:
                return s.name
        return ""

    @property
    def latest_update(self) -> ContentSet | None:
        return max(self.updates, key=lambda s: s.cnmt.version, default=None)

    def check(self) -> None:
        """Fill :attr:`warnings` with inconsistencies between the sets in this title."""
        aid = f"{self.application_id:016x}"
        if not self.base and self.dlc:
            self.warnings.append(f"DLC without its base game {aid} ({len(self.dlc)} found)")
        if not self.base and self.updates:
            self.warnings.append(f"update without its base game {aid}")
        sets = [*self.base, *self.updates, *self.dlc, *self.other]
        by_key: dict[tuple[int, int, int], list[ContentSet]] = defaultdict(list)
        versions: dict[tuple[int, int], set[int]] = defaultdict(set)
        for s in sets:
            m = s.cnmt
            by_key[(m.title_id, m.type, m.version)].append(s)
            versions[(m.title_id, m.type)].add(m.version)
        for dupes in by_key.values():
            if len(dupes) > 1:
                where = ", ".join(s.source for s in dupes)
                self.warnings.append(f"duplicate content: {dupes[0].label()} in {where}")
        if len({s.cnmt.version for s in self.updates}) > 1:
            found = ", ".join(
                f"v{s.cnmt.version} ({s.source})"
                for s in sorted(self.updates, key=lambda s: s.cnmt.version)
            )
            latest = self.latest_update
            assert latest is not None
            self.warnings.append(
                f"several updates with different versions: {found}; "
                f"highest is v{latest.cnmt.version}"
            )
        for (tid, mtype), vers in versions.items():
            if mtype != META_PATCH and len(vers) > 1:
                listed = ", ".join(f"v{v}" for v in sorted(vers))
                self.warnings.append(f"{tid:016x} found in several versions: {listed}")
        for s in sets:
            guess = guess_application_id(s.cnmt.title_id, s.cnmt.type)
            if s.cnmt.application_id is not None and guess not in (None, s.cnmt.application_id):
                self.warnings.append(
                    f"{s.label()} names base {s.cnmt.application_id:016x} in its CNMT; "
                    f"its title ID suggests {guess:016x} (the CNMT is used)"
                )


@dataclass
class Library:
    titles: dict[int, TitleGroup] = field(default_factory=dict)
    ungrouped: list[ContentSet] = field(default_factory=list)  # system updates etc.
    errors: list[str] = field(default_factory=list)  # files or NCAs that could not be read

    def add(self, s: ContentSet) -> None:
        aid = s.application_id
        if aid is None:
            self.ungrouped.append(s)
            return
        group = self.titles.setdefault(aid, TitleGroup(aid))
        kind = {
            META_APPLICATION: group.base,
            META_PATCH: group.updates,
            META_ADDON: group.dlc,
        }.get(s.cnmt.type, group.other)
        kind.append(s)


def find_files(paths: list[str]) -> tuple[list[Path], list[str]]:
    """Expand files and folders (recursively) into candidate files, plus skip notes."""
    found: list[Path] = []
    notes: list[str] = []
    for p in map(Path, paths):
        if p.is_dir():
            candidates = sorted(c for c in p.rglob("*") if c.is_file())
        elif p.is_file():
            candidates = [p]
        else:
            notes.append(f"{p}: not found")
            continue
        for c in candidates:
            suffix = c.suffix.lower()
            if suffix in COMPRESSED_SUFFIXES:
                kind = COMPRESSED_SUFFIXES[suffix]
                notes.append(f"{c}: skipped, {kind} is compressed (decompress first)")
            elif suffix in SCAN_SUFFIXES:
                found.append(c)
            elif p.is_file():
                notes.append(f"{c}: skipped, not an XCI/NSP/NCA")
    return found, notes


def scan(
    paths: list[str],
    keyset: Keyset | None,
    open_input: Callable[[Storage, str], Container],
) -> Library:
    """Read the CNMT of every content set in ``paths`` and group them into titles.

    ``open_input(storage, path)`` opens an XCI, NSP or standalone NCA (see the CLI).
    """
    lib = Library()
    files, lib.errors = find_files(paths)
    for path in files:
        try:
            with FileStorage.open(path) as st:
                report = inspect(open_input(st, str(path)), keyset)
            for rep in report.ncas:
                # A Meta NCA that can't be read hides a whole content set.
                is_meta = (
                    rep.nca.header.content_type == 1
                    if rep.nca
                    else rep.file.name.endswith(".cnmt.nca")
                )
                if is_meta and not rep.decrypts:
                    lib.errors.append(f"{path}: {rep.file.path}: {rep.problem}")
            lib.errors.extend(f"{path}: {n}" for n in report.notes)
            for m in report.metas:
                nacp = report.nacp_for(m.title_id)
                lib.add(ContentSet(m, str(path), nacp.preferred()[0] if nacp else ""))
            if not report.metas and path.suffix.lower() != ".nca":
                lib.errors.append(f"{path}: no readable content metadata")
        except (NxError, OSError) as e:
            lib.errors.append(f"{path}: {e}")
    for group in lib.titles.values():
        group.check()
    return lib
