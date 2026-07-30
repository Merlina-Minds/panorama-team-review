"""Locating and opening backup files.

Firewalls and Panorama write scheduled backups in several shapes: a plain XML
export, a gzipped XML, or a tar archive holding one XML per managed device.
This module normalises all of them into ``LoadedConfig`` objects so the parsers
only ever see parsed XML plus provenance.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import re
import tarfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from lxml import etree

from ..config import InputConfig
from ..errors import BackupNotFoundError, BackupStaleError, ParseError

# A hard cap on how much a compressed member may expand to.  Backups are
# untrusted input as far as this tool is concerned, and a decompression bomb in
# a cron job that runs unattended is a real failure mode.
MAX_MEMBER_BYTES = 2 * 1024**3  # 2 GiB


@dataclass(slots=True)
class LoadedConfig:
    """One XML configuration document plus where it came from."""

    tree: etree._ElementTree
    source_name: str
    source_path: Path
    mtime: datetime | None
    config_hash: str

    @property
    def root(self) -> etree._Element:
        return self.tree.getroot()

    def detect_type(self) -> str:
        """Return ``panorama`` or ``firewall`` based on the document structure.

        Panorama configurations carry device groups and/or a ``panorama`` node;
        a firewall configuration carries vsys entries instead.  A Panorama that
        has no device groups configured yet still has the ``panorama`` node, so
        both signals are checked.
        """
        root = self.root
        if root.find(".//devices/entry/device-group") is not None:
            return "panorama"
        if root.find("./panorama") is not None or root.find(".//readonly/devices") is not None:
            return "panorama"
        if root.find(".//devices/entry/vsys") is not None:
            return "firewall"
        raise ParseError(
            f"{self.source_name}: not recognisable as a PAN-OS or Panorama configuration "
            "(no device-group and no vsys node found)"
        )


def find_backups(cfg: InputConfig, explicit: Path | None = None) -> list[Path]:
    """Return the backup files to process, newest first.

    ``explicit`` short-circuits everything -- that is the manual single-run
    case.  Otherwise the configured directory is searched and, with
    ``select: latest``, reduced to the single newest file.
    """
    if explicit is not None:
        if not explicit.is_file():
            raise BackupNotFoundError(f"backup file not found: {explicit}")
        return [explicit]

    if cfg.backup_dir is None:
        raise BackupNotFoundError(
            "no backup specified: set input.backup_dir in the configuration "
            "or pass --backup FILE"
        )
    if not cfg.backup_dir.is_dir():
        raise BackupNotFoundError(f"backup directory does not exist: {cfg.backup_dir}")

    candidates: list[Path] = []
    for pattern in cfg.patterns:
        globber = cfg.backup_dir.rglob if cfg.recursive else cfg.backup_dir.glob
        candidates.extend(p for p in globber(pattern) if p.is_file())

    # rglob with overlapping patterns can yield the same file twice.
    unique = sorted(set(candidates), key=lambda p: _sort_key(p, cfg), reverse=True)
    if not unique:
        raise BackupNotFoundError(
            f"no backup matching {cfg.patterns} found in {cfg.backup_dir}"
            + (" (searched recursively)" if cfg.recursive else "")
        )

    if cfg.max_age_days is not None:
        newest_mtime = datetime.fromtimestamp(unique[0].stat().st_mtime)
        cutoff = datetime.now() - timedelta(days=cfg.max_age_days)
        if newest_mtime < cutoff:
            raise BackupStaleError(
                f"newest backup {unique[0].name} is from {newest_mtime:%Y-%m-%d %H:%M}, "
                f"older than the configured limit of {cfg.max_age_days} days. "
                "The backup job on the firewall is most likely broken."
            )

    return [unique[0]] if cfg.select == "latest" else unique


def _sort_key(path: Path, cfg: InputConfig) -> tuple:
    """Ordering key for "newest first".

    With ``select_by: filename`` the date embedded in the file name decides,
    falling back to the modification time when the name carries no date. That
    fallback matters: mixing the two orderings silently would be worse than
    either, so a file without a date sorts below every file that has one.

    Why this option exists: an mtime is only trustworthy when it was written by
    whatever produced the backup. That holds for a firewall writing directly to
    the directory and for a scheduled job rotating files -- but not for an
    archive extracted after the fact or a copy that did not preserve times. In
    those cases an old configuration can carry a fresh timestamp, and the tool
    would faithfully report on stale policy.
    """
    if cfg.select_by == "mtime":
        return (path.stat().st_mtime, path.name)

    stamp = _date_from_name(path.name, cfg)
    return (
        (1, stamp.timestamp(), path.stat().st_mtime, path.name)
        if stamp
        else (0, 0.0, path.stat().st_mtime, path.name)
    )


def _date_from_name(name: str, cfg: InputConfig) -> datetime | None:
    match = re.search(cfg.filename_date_pattern, name)
    if not match:
        return None
    raw = match.group("date")
    for fmt in cfg.filename_date_formats:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def load(path: Path) -> list[LoadedConfig]:
    """Open a backup file and return every configuration document inside it."""
    suffixes = "".join(path.suffixes[-2:]).lower()
    if suffixes.endswith((".tgz", ".tar.gz")) or path.suffix.lower() == ".tar":
        return list(_load_archive(path))
    if path.suffix.lower() == ".gz":
        return [_parse_bytes(_read_gzip(path), path.name.removesuffix(".gz"), path)]
    return [_parse_bytes(path.read_bytes(), path.name, path)]


def _read_gzip(path: Path) -> bytes:
    with gzip.open(path, "rb") as handle:
        data = handle.read(MAX_MEMBER_BYTES + 1)
    if len(data) > MAX_MEMBER_BYTES:
        raise ParseError(f"{path.name}: decompressed content exceeds {MAX_MEMBER_BYTES} bytes")
    return data


def _load_archive(path: Path) -> Iterator[LoadedConfig]:
    """Yield each XML member of a tar archive.

    Panorama's scheduled backup ships one archive containing the configuration
    of every managed device, so a single file can legitimately produce dozens
    of documents.
    """
    found = False
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not member.name.lower().endswith(".xml"):
                continue
            if member.size > MAX_MEMBER_BYTES:
                raise ParseError(
                    f"{path.name}:{member.name}: member is {member.size} bytes, "
                    f"above the {MAX_MEMBER_BYTES} byte limit"
                )
            handle = archive.extractfile(member)
            if handle is None:
                continue
            found = True
            member_time = datetime.fromtimestamp(member.mtime) if member.mtime else None
            yield _parse_bytes(handle.read(), f"{path.name}:{member.name}", path, member_time)
    if not found:
        raise ParseError(f"{path.name}: archive contains no .xml member")


def _parse_bytes(
    data: bytes, source_name: str, source_path: Path, mtime: datetime | None = None
) -> LoadedConfig:
    # resolve_entities=False and no_network=True: configuration backups are
    # untrusted input, and XXE against a tool that runs unattended is exactly
    # the kind of thing this tool exists to prevent elsewhere.
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        huge_tree=True,
        remove_comments=False,
        recover=False,
    )
    try:
        tree = etree.parse(io.BytesIO(data), parser)
    except etree.XMLSyntaxError as exc:
        raise ParseError(f"{source_name}: XML is not well formed: {exc}") from exc

    if mtime is None:
        try:
            mtime = datetime.fromtimestamp(source_path.stat().st_mtime)
        except OSError:
            mtime = None

    return LoadedConfig(
        tree=tree,
        source_name=source_name,
        source_path=source_path,
        mtime=mtime,
        config_hash=hashlib.sha256(data).hexdigest(),
    )
