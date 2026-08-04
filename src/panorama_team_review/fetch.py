"""Optional live configuration fetch.

Companion to hit-count collection.  If the tool already reaches the devices for
counters, it can pull the running configuration from the same place instead of
depending on a separately scheduled export landing on disk.

Same contract as hit-count collection: off by default, read-only (only the
configuration export endpoint is called), and it reuses the ``hitcounts``
connection settings so the access is configured once.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

from . import panos_api
from .config import ConnectionConfig, FetchConfig
from .errors import FetchError, PanReviewError

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def fetch_backups(
    fetch: FetchConfig,
    connection: ConnectionConfig,
    save_dir: Path,
    today: date | None = None,
) -> tuple[list[Path], list[str]]:
    """Download the running configuration from each device into ``save_dir``.

    Returns ``(written files, human-readable notes)``.  Raises ``FetchError``
    only when nothing at all could be fetched -- a single unreachable device
    among several is reported as a note, not a failure, so one bad device does
    not deny the others a fresh backup.
    """
    if not connection.devices:
        raise FetchError(
            "no devices to fetch from: list them under hitcounts.devices "
            "(configuration fetch reuses the hitcounts connection)"
        )

    save_dir.mkdir(parents=True, exist_ok=True)
    stamp = (today or date.today()).isoformat()

    session = panos_api.open_session(connection)
    key = panos_api.resolve_api_key(connection)

    written: list[Path] = []
    notes: list[str] = []
    failures: list[str] = []

    for device in connection.devices:
        try:
            content = panos_api.export_configuration(session, device, key, connection)
        except PanReviewError as exc:
            failures.append(f"{device}: {exc}")
            continue
        target = save_dir / fetch.filename_template.format(device=_safe(device), date=stamp)
        target.write_bytes(content)
        written.append(target)
        notes.append(f"fetched configuration from {device} -> {target.name}")

    if failures:
        notes.append("fetch failures: " + "; ".join(failures))
    if failures and not written:
        raise FetchError("; ".join(failures))
    return written, notes


def _safe(device: str) -> str:
    """Reduce a device name to something usable as a file name component."""
    return _UNSAFE.sub("_", device).strip("._") or "device"
