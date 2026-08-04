"""Optional live configuration fetch.

Companion to hit-count collection.  If the tool already reaches the devices for
counters, it can pull the running configuration from the same place instead of
depending on a separately scheduled export landing on disk.

Same contract as hit-count collection: off by default, read-only (only the
configuration export endpoint and read-only op commands are used), and it reuses
the ``hitcounts`` connection settings so the access is configured once.

A Panorama export holds only the Panorama-side config -- device groups,
templates, shared -- not the rules configured locally on each managed firewall.
So when the fetched device is a Panorama, each managed firewall's running config
is pulled too (via ``target``) and everything is written into one ``.tgz``
archive, the shape of a scheduled Panorama backup, which the parser then merges
into a single view.
"""

from __future__ import annotations

import io
import re
import tarfile
from collections.abc import Callable
from datetime import date, datetime
from pathlib import Path

from lxml import etree

from . import panos_api
from .config import ConnectionConfig, FetchConfig
from .errors import FetchError, PanReviewError

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def fetch_backups(
    fetch: FetchConfig,
    connection: ConnectionConfig,
    save_dir: Path,
    today: date | None = None,
    progress: Callable[[str], None] | None = None,
) -> tuple[list[Path], list[str]]:
    """Download the running configuration from each device into ``save_dir``.

    Returns ``(written files, human-readable notes)``.  Raises ``FetchError``
    only when nothing at all could be fetched -- a single unreachable device
    among several is reported as a note, not a failure, so one bad device does
    not deny the others a fresh backup.

    ``progress`` is called with short status lines as work proceeds, so an
    interactive run is not silent during the network calls.
    """
    if not connection.devices:
        raise FetchError(
            "no devices to fetch from: list them under hitcounts.devices "
            "(configuration fetch reuses the hitcounts connection)"
        )
    if missing := panos_api.missing_credentials(connection):
        raise FetchError(missing)

    save_dir.mkdir(parents=True, exist_ok=True)
    stamp = (today or date.today()).isoformat()

    session = panos_api.open_session(connection)

    written: list[Path] = []
    notes: list[str] = []
    failures: list[str] = []

    for device in connection.devices:
        _emit(progress, f"{device}: fetching configuration…")
        try:
            key = panos_api.authenticate(session, device, connection)
            content = panos_api.export_configuration(session, device, key, connection)
        except PanReviewError as exc:
            failures.append(f"{device}: {exc}")
            continue

        if _is_panorama_config(content):
            target = _write_panorama_bundle(
                session, device, key, connection, content, save_dir, stamp, notes, progress
            )
        else:
            target = save_dir / fetch.filename_template.format(device=_safe(device), date=stamp)
            target.write_bytes(content)
        written.append(target)
        notes.append(f"fetched configuration from {device} -> {target.name}")

    if failures:
        notes.append("fetch failures: " + "; ".join(failures))
    if failures and not written:
        raise FetchError("; ".join(failures))
    return written, notes


def _write_panorama_bundle(
    session,
    panorama: str,
    key: str,
    connection: ConnectionConfig,
    panorama_config: bytes,
    save_dir: Path,
    stamp: str,
    notes: list[str],
    progress: Callable[[str], None] | None = None,
) -> Path:
    """Bundle the Panorama config and every managed firewall's config into a .tgz."""
    members: list[tuple[str, bytes]] = [(f"{_safe(panorama)}.xml", panorama_config)]

    _emit(progress, f"{panorama}: listing managed firewalls…")
    try:
        connected = panos_api.list_connected_devices(session, panorama, key, connection)
    except PanReviewError as exc:
        notes.append(f"{panorama}: could not list managed devices: {exc}")
        connected = []

    for index, (serial, hostname, _vsys) in enumerate(connected, start=1):
        _emit(
            progress,
            f"{panorama}: fetching {hostname or serial} config ({index}/{len(connected)})…",
        )
        try:
            device_config = panos_api.export_managed_configuration(
                session, panorama, key, serial, connection
            )
        except PanReviewError as exc:
            notes.append(f"{panorama}: could not fetch device {serial}: {exc}")
            continue
        # The trailing serial lets the parser recover it from the member name.
        members.append((f"{_safe(hostname or serial)}_{serial}.xml", device_config))

    notes.append(
        f"{panorama}: bundled Panorama config and {len(members) - 1} managed device config(s)"
    )

    target = save_dir / f"{_safe(panorama)}_{stamp}.tgz"
    now = int(datetime.now().timestamp())
    with tarfile.open(target, "w:gz") as archive:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = now
            archive.addfile(info, io.BytesIO(data))
    return target


def _emit(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _is_panorama_config(content: bytes) -> bool:
    try:
        root = etree.fromstring(
            content, etree.XMLParser(resolve_entities=False, no_network=True)
        )
    except etree.XMLSyntaxError:
        return False
    return (
        root.find(".//devices/entry/device-group") is not None
        or root.find("./panorama") is not None
    )


def _safe(device: str) -> str:
    """Reduce a device name to something usable as a file name component."""
    return _UNSAFE.sub("_", device).strip("._") or "device"
