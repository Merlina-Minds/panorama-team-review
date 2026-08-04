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

import hashlib
import os
import ssl
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
    """Return an explicit API key from the environment or a key file.

    Raises when none is configured. Used where a key is the only accepted
    credential; password authentication goes through ``authenticate``.
    """
    key = _explicit_api_key(config)
    if not key:
        raise EnrichmentError(
            f"no API key: set the {config.api_key_env} environment variable, or point "
            "hitcounts.api_key_file at a file containing the key. "
            "Keys are never read from the configuration file itself."
        )
    return key


def _explicit_api_key(config: ConnectionConfig) -> str | None:
    """The configured API key, or ``None`` if none is set.

    A key *file* that is configured but missing or empty is a misconfiguration
    worth reporting rather than silently falling back to password auth.
    """
    if config.api_key_file:
        if not config.api_key_file.is_file():
            raise EnrichmentError(f"API key file not found: {config.api_key_file}")
        key = config.api_key_file.read_text(encoding="utf-8").strip()
        if not key:
            raise EnrichmentError(f"API key file is empty: {config.api_key_file}")
        return key
    return os.environ.get(config.api_key_env, "").strip() or None


def _resolve_password(config: ConnectionConfig) -> str | None:
    if config.password_file:
        if not config.password_file.is_file():
            raise EnrichmentError(f"password file not found: {config.password_file}")
        password = config.password_file.read_text(encoding="utf-8").strip()
        if not password:
            raise EnrichmentError(f"password file is empty: {config.password_file}")
        return password
    return os.environ.get(config.password_env, "").strip() or None


def missing_credentials(config: ConnectionConfig) -> str | None:
    """Return an actionable message if no credential is configured, else ``None``.

    Lets a caller fail fast before opening a connection, instead of repeating
    the same error once per device.
    """
    has_key = bool(config.api_key_file) or bool(os.environ.get(config.api_key_env, "").strip())
    if has_key or config.username:
        return None
    return (
        f"no credentials: set an API key (the {config.api_key_env} environment variable or "
        f"api_key_file), or a username plus password (username in the config, and the "
        f"{config.password_env} environment variable or password_file). "
        "Secrets are never read from the configuration file itself."
    )


def authenticate(session: Any, device: str, config: ConnectionConfig) -> str:
    """Return a usable API key for ``device``.

    An explicit key is used as-is for every device. Otherwise, a username and
    password obtain a key from the device via a read-only ``keygen`` call --
    the path for a read-only account that was never issued a key.
    """
    key = _explicit_api_key(config)
    if key:
        return key

    if config.username:
        password = _resolve_password(config)
        if not password:
            raise EnrichmentError(
                f"username {config.username!r} is set but no password: set the "
                f"{config.password_env} environment variable, or point password_file at a "
                "file containing it. Passwords are never read from the configuration file."
            )
        return _keygen(session, device, config.username, password, config)

    raise EnrichmentError(missing_credentials(config) or "no credentials configured")


def _keygen(
    session: Any, device: str, username: str, password: str, config: ConnectionConfig
) -> str:
    """Exchange a username and password for an API key (read-only)."""
    root = _parse(
        device,
        _post(session, device, {"type": "keygen", "user": username, "password": password}, config),
    )
    if root.get("status") != "success":
        message = root.findtext(".//msg") or root.findtext(".//line") or "unknown error"
        raise EnrichmentError(f"{device} rejected the credentials: {message.strip()}")
    key = (root.findtext(".//key") or "").strip()
    if not key:
        raise EnrichmentError(f"{device} returned no API key from keygen")
    return key



def _post(
    session: Any,
    device: str,
    data: dict[str, str],
    config: ConnectionConfig,
    target: str | None = None,
) -> bytes:
    """Issue one API request and return the raw response body.

    ``target`` is a managed firewall's serial: Panorama then proxies the request
    to that firewall, which is how per-device runtime state (hit counts, the
    device's own running config) is read through Panorama.
    """
    url = f"https://{device}/api/"
    payload = dict(data)
    if target:
        payload["target"] = target
    try:
        response = session.post(
            url,
            data=payload,
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
    session: Any,
    device: str,
    key: str,
    command: str,
    config: ConnectionConfig,
    target: str | None = None,
) -> etree._Element:
    """Issue one operational command and return the parsed ``<result>``.

    With ``target`` the command runs on that managed firewall via Panorama.
    """
    if not command.startswith(_ALLOWED_COMMAND_PREFIX):
        # Defence in depth: this must never be able to change a device.
        raise EnrichmentError(f"refusing to send a non-'show' command: {command[:40]}")

    root = _parse(
        device,
        _post(session, device, {"type": "op", "cmd": command, "key": key}, config, target=target),
    )

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


def export_managed_configuration(
    session: Any, panorama: str, key: str, serial: str, config: ConnectionConfig
) -> bytes:
    """Return a managed firewall's running configuration, fetched via Panorama.

    A Panorama configuration export holds only the Panorama-side config -- device
    groups, templates, shared -- not the rules configured locally on each managed
    firewall. Those are read here with ``show config running`` proxied to the
    firewall by serial, so the result is a firewall ``<config>`` document just
    like a member of a scheduled Panorama backup archive.
    """
    result = operational(
        session,
        panorama,
        key,
        "<show><config><running></running></config></show>",
        config,
        target=serial,
    )
    cfg = result.find("config")
    if cfg is None:
        raise FetchError(f"{panorama}: no running config returned for device {serial}")
    return etree.tostring(cfg)


def list_connected_devices(
    session: Any, device: str, key: str, config: ConnectionConfig
) -> list[tuple[str, str | None, list[str]]]:
    """Return ``(serial, hostname, [vsys])`` for each firewall connected to Panorama.

    Used both to know which firewalls to query for hit counts and which device
    configs to pull. Parsed defensively: the serial is the only field required.
    """
    result = operational(
        session, device, key, "<show><devices><connected></connected></devices></show>", config
    )
    devices: list[tuple[str, str | None, list[str]]] = []
    for entry in result.findall(".//devices/entry"):
        serial = entry.get("name") or entry.findtext("serial")
        if not serial:
            continue
        hostname = entry.findtext("hostname") or None
        vsys = [v.get("name") for v in entry.findall("vsys/entry") if v.get("name")]
        devices.append((serial.strip(), hostname, vsys))
    return devices


def xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("'", "&apos;")
        .replace('"', "&quot;")
    )


def fetch_certificate(host: str, port: int = 443, timeout: int = 30) -> tuple[str, str]:
    """Return ``(PEM, SHA-256 fingerprint)`` of a device's TLS server certificate.

    Fetched **without** verification -- the whole point is to obtain the
    certificate that verification is currently rejecting. This is trust on first
    use: the fingerprint must be checked against the device out of band before
    the certificate is trusted as a ``ca_bundle``.
    """
    try:
        pem = ssl.get_server_certificate((host, port), timeout=timeout)
    except (OSError, ssl.SSLError) as exc:
        raise FetchError(f"could not fetch a certificate from {host}:{port}: {exc}") from exc

    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()
    fingerprint = ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))
    return pem, fingerprint
