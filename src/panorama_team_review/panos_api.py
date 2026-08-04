"""Shared PAN-OS / Panorama XML-API transport.

The one place that opens a network connection to a device.  Both optional
network features -- hit-count collection and live configuration fetch -- ride
on it, so credential handling, TLS policy and the read-only guarantee live here
once rather than being reimplemented per feature.

The read-only guarantee is enforced twice over: ``operational`` refuses to send
anything but a ``show`` command, and ``export_configuration`` can only ever
request the configuration category. Neither can change a device.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from lxml import etree

from .errors import EnrichmentError, FetchError

if TYPE_CHECKING:
    from .config import ConnectionConfig

# Operational commands may only carry the read-only ``show`` verb.
_ALLOWED_COMMAND_PREFIX = "<show>"

# The export endpoint is fixed to the configuration, so the module has no way to
# request device state, logs or anything else.
_EXPORT_CATEGORY = "configuration"


def open_session(config: ConnectionConfig) -> Any:
    try:
        import requests
    except ImportError as exc:
        raise EnrichmentError(
            "network access requires the optional 'requests' dependency.\n"
            "  Install it with:  pip install 'panorama-team-review[api]'"
        ) from exc

    session = requests.Session()
    session.headers["User-Agent"] = "panorama-team-review"
    if not config.verify_tls:
        # Explicitly requested; warn loudly because it defeats the point of TLS
        # on a management interface.
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return session


def resolve_api_key(config: ConnectionConfig) -> str:
    if config.api_key_file:
        if not config.api_key_file.is_file():
            raise EnrichmentError(f"API key file not found: {config.api_key_file}")
        key = config.api_key_file.read_text(encoding="utf-8").strip()
        if not key:
            raise EnrichmentError(f"API key file is empty: {config.api_key_file}")
        return key

    key = os.environ.get(config.api_key_env, "").strip()
    if not key:
        raise EnrichmentError(
            f"no API key: set the {config.api_key_env} environment variable, or point "
            "hitcounts.api_key_file at a file containing the key. "
            "Keys are never read from the configuration file itself."
        )
    return key


def _post(session: Any, device: str, data: dict[str, str], config: ConnectionConfig) -> bytes:
    """Issue one API request and return the raw response body."""
    url = f"https://{device}/api/"
    try:
        response = session.post(
            url,
            data=data,
            timeout=config.timeout_seconds,
            verify=str(config.ca_bundle) if config.ca_bundle else config.verify_tls,
        )
    except Exception as exc:  # noqa: BLE001 - network errors of every shape
        raise EnrichmentError(f"request to {device} failed: {exc}") from exc

    if response.status_code != 200:
        raise EnrichmentError(f"{device} returned HTTP {response.status_code}")
    return response.content


def _parse(device: str, content: bytes) -> etree._Element:
    try:
        return etree.fromstring(
            content, etree.XMLParser(resolve_entities=False, no_network=True)
        )
    except etree.XMLSyntaxError as exc:
        raise EnrichmentError(f"{device} returned malformed XML: {exc}") from exc


def operational(
    session: Any, device: str, key: str, command: str, config: ConnectionConfig
) -> etree._Element:
    """Issue one operational command and return the parsed ``<result>``."""
    if not command.startswith(_ALLOWED_COMMAND_PREFIX):
        # Defence in depth: this must never be able to change a device.
        raise EnrichmentError(f"refusing to send a non-'show' command: {command[:40]}")

    root = _parse(device, _post(session, device, {"type": "op", "cmd": command, "key": key}, config))

    if root.get("status") != "success":
        message = root.findtext(".//msg") or root.findtext(".//line") or "unknown error"
        raise EnrichmentError(f"{device} rejected the command: {message.strip()}")

    result = root.find("result")
    if result is None:
        raise EnrichmentError(f"{device} returned no result element")
    return result


def export_configuration(session: Any, device: str, key: str, config: ConnectionConfig) -> bytes:
    """Download the running configuration as a standalone ``<config>`` document.

    Uses the export API, which returns exactly what a scheduled backup writes,
    so the downstream parser sees identical input. Read-only by construction:
    only ``category=configuration`` is ever requested.
    """
    content = _post(
        session, device, {"type": "export", "category": _EXPORT_CATEGORY, "key": key}, config
    )

    try:
        root = etree.fromstring(
            content, etree.XMLParser(resolve_entities=False, no_network=True)
        )
    except etree.XMLSyntaxError as exc:
        raise FetchError(f"{device} returned malformed configuration XML: {exc}") from exc

    # A failure comes back as a ``<response status="error">`` envelope; a
    # success is the bare ``<config>`` document.
    if root.tag == "response":
        message = root.findtext(".//msg") or root.findtext(".//line") or "unknown error"
        raise FetchError(f"{device} rejected the configuration export: {message.strip()}")
    if root.tag != "config":
        raise FetchError(
            f"{device} did not return a configuration document (root element <{root.tag}>)"
        )
    return content


def xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("'", "&apos;")
        .replace('"', "&quot;")
    )
