"""Optional live configuration fetch.

Two properties matter more than the details:

* it must never run unless explicitly enabled, and
* it must only ever read -- the export endpoint cannot change a device.

Everything here runs against fakes; no test in this file touches a network.
"""

from __future__ import annotations

import base64
import hashlib
import ssl
from datetime import date

import pytest
from pydantic import ValidationError

from panorama_team_review import fetch, panos_api
from panorama_team_review.config import (
    ConnectionConfig,
    FetchConfig,
    HitCountConfig,
    InputConfig,
)
from panorama_team_review.errors import EnrichmentError, FetchError

CONFIG_XML = b'<config version="10.2.0"><devices/></config>'
KEYGEN_XML = b'<response status="success"><result><key>GENERATED-KEY</key></result></response>'


class FakeResponse:
    def __init__(self, content: bytes, status_code: int = 200) -> None:
        self.content = content
        self.status_code = status_code


class FakeSession:
    """Records what it was asked to send, so tests can assert read-only intent.

    ``by_type`` lets a test return different bodies for different request types
    (e.g. a keygen response then a configuration export).
    """

    def __init__(
        self,
        content: bytes = CONFIG_XML,
        status_code: int = 200,
        by_type: dict[str, bytes] | None = None,
    ) -> None:
        self._content = content
        self._status = status_code
        self._by_type = by_type or {}
        self.requests: list[dict] = []

    def post(self, url, data=None, timeout=None, verify=None):
        self.requests.append({"url": url, "data": data, "timeout": timeout, "verify": verify})
        content = self._by_type.get((data or {}).get("type"), self._content)
        return FakeResponse(content, self._status)


# ---------------------------------------------------------------------------
# The off switch
# ---------------------------------------------------------------------------


def test_disabled_by_default():
    assert FetchConfig().enabled is False
    assert InputConfig().fetch.enabled is False


def test_reuses_the_hitcount_connection():
    """The connection is shared, not duplicated."""
    assert issubclass(HitCountConfig, ConnectionConfig)


def test_filename_template_rejects_unknown_placeholder():
    with pytest.raises(ValidationError, match="unknown placeholder"):
        FetchConfig(filename_template="{device}_{nope}.xml")


def test_filename_template_rejects_empty():
    with pytest.raises(ValidationError, match="must not be empty"):
        FetchConfig(filename_template="   ")


# ---------------------------------------------------------------------------
# Read-only export
# ---------------------------------------------------------------------------


def test_export_returns_the_config_document():
    session = FakeSession()
    content = panos_api.export_configuration(session, "fw.example.com", "key", ConnectionConfig())
    assert content == CONFIG_XML


def test_export_only_ever_requests_the_configuration():
    """Defence in depth: the module cannot ask for anything but the config."""
    session = FakeSession()
    panos_api.export_configuration(session, "fw.example.com", "key", ConnectionConfig())
    sent = session.requests[-1]["data"]
    assert sent["type"] == "export"
    assert sent["category"] == "configuration"


def test_export_error_envelope_is_reported():
    body = b'<response status="error"><msg>Invalid credentials</msg></response>'
    with pytest.raises(FetchError, match="Invalid credentials"):
        panos_api.export_configuration(FakeSession(content=body), "fw", "k", ConnectionConfig())


def test_export_rejects_a_non_config_document():
    session = FakeSession(content=b"<result><foo/></result>")
    with pytest.raises(FetchError, match="did not return a configuration document"):
        panos_api.export_configuration(session, "fw", "k", ConnectionConfig())


def test_export_malformed_xml_is_reported():
    session = FakeSession(content=b"<config status=success")
    with pytest.raises(FetchError, match="malformed configuration XML"):
        panos_api.export_configuration(session, "fw", "k", ConnectionConfig())


def test_export_http_error_is_reported():
    with pytest.raises(EnrichmentError, match="HTTP 403"):
        panos_api.export_configuration(
            FakeSession(status_code=403), "fw", "k", ConnectionConfig()
        )


# ---------------------------------------------------------------------------
# Fetching into a directory
# ---------------------------------------------------------------------------


def test_fetch_writes_one_file_per_device(tmp_path, monkeypatch):
    monkeypatch.setenv("PAN_API_KEY", "secret")
    session = FakeSession()
    monkeypatch.setattr(panos_api, "open_session", lambda conn: session)

    conn = ConnectionConfig(devices=["fw1.example.com", "fw2.example.com"])
    written, _ = fetch.fetch_backups(
        FetchConfig(enabled=True), conn, tmp_path, today=date(2026, 8, 4)
    )

    assert sorted(p.name for p in written) == [
        "fw1.example.com_2026-08-04.xml",
        "fw2.example.com_2026-08-04.xml",
    ]
    assert written[0].read_bytes() == CONFIG_XML


def test_fetch_requires_devices(tmp_path):
    with pytest.raises(FetchError, match="no devices"):
        fetch.fetch_backups(FetchConfig(enabled=True), ConnectionConfig(), tmp_path)


def test_one_bad_device_does_not_deny_the_others(tmp_path, monkeypatch):
    monkeypatch.setenv("PAN_API_KEY", "secret")
    monkeypatch.setattr(panos_api, "open_session", lambda conn: object())

    def fake_export(session, device, key, conn):
        if device == "bad.example.com":
            raise FetchError("connection refused")
        return CONFIG_XML

    monkeypatch.setattr(panos_api, "export_configuration", fake_export)

    conn = ConnectionConfig(devices=["good.example.com", "bad.example.com"])
    written, notes = fetch.fetch_backups(FetchConfig(enabled=True), conn, tmp_path)

    assert [p.name.split("_")[0] for p in written] == ["good.example.com"]
    assert any("fetch failures" in note for note in notes)


def test_all_devices_failing_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("PAN_API_KEY", "secret")
    monkeypatch.setattr(panos_api, "open_session", lambda conn: object())

    def fake_export(*args, **kwargs):
        raise FetchError("connection refused")

    monkeypatch.setattr(panos_api, "export_configuration", fake_export)

    conn = ConnectionConfig(devices=["a.example.com", "b.example.com"])
    with pytest.raises(FetchError):
        fetch.fetch_backups(FetchConfig(enabled=True), conn, tmp_path)


# ---------------------------------------------------------------------------
# Authentication: API key or username + password
# ---------------------------------------------------------------------------


def test_authenticate_uses_an_explicit_key(monkeypatch):
    monkeypatch.setenv("PAN_API_KEY", "explicit-key")
    key = panos_api.authenticate(FakeSession(), "fw.example.com", ConnectionConfig())
    assert key == "explicit-key"


def test_authenticate_keygens_from_username_and_password(monkeypatch):
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    monkeypatch.setenv("PAN_PASSWORD", "s3cret")
    session = FakeSession(by_type={"keygen": KEYGEN_XML})

    key = panos_api.authenticate(
        session, "fw.example.com", ConnectionConfig(username="readonly-api")
    )

    assert key == "GENERATED-KEY"
    sent = session.requests[-1]["data"]
    assert sent["type"] == "keygen"
    assert sent["user"] == "readonly-api"
    assert sent["password"] == "s3cret"


def test_authenticate_without_any_credentials_is_actionable(monkeypatch):
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    with pytest.raises(EnrichmentError, match="no credentials"):
        panos_api.authenticate(FakeSession(), "fw.example.com", ConnectionConfig())


def test_authenticate_username_without_password_is_actionable(monkeypatch):
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    monkeypatch.delenv("PAN_PASSWORD", raising=False)
    with pytest.raises(EnrichmentError, match="no password"):
        panos_api.authenticate(
            FakeSession(), "fw.example.com", ConnectionConfig(username="readonly-api")
        )


def test_keygen_rejected_credentials_are_reported(monkeypatch):
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    monkeypatch.setenv("PAN_PASSWORD", "wrong")
    body = b'<response status="error"><msg>Invalid credentials</msg></response>'
    session = FakeSession(by_type={"keygen": body})
    with pytest.raises(EnrichmentError, match="rejected the credentials"):
        panos_api.authenticate(
            session, "fw.example.com", ConnectionConfig(username="readonly-api")
        )


def test_password_can_come_from_a_file(tmp_path, monkeypatch):
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    monkeypatch.delenv("PAN_PASSWORD", raising=False)
    password_file = tmp_path / "api.pass"
    password_file.write_text("file-pass\n", encoding="utf-8")
    session = FakeSession(by_type={"keygen": KEYGEN_XML})

    panos_api.authenticate(
        session,
        "fw.example.com",
        ConnectionConfig(username="readonly-api", password_file=password_file),
    )
    assert session.requests[-1]["data"]["password"] == "file-pass"


def test_missing_credentials_detects_each_source(monkeypatch):
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    assert panos_api.missing_credentials(ConnectionConfig()) is not None
    monkeypatch.setenv("PAN_API_KEY", "k")
    assert panos_api.missing_credentials(ConnectionConfig()) is None
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    assert panos_api.missing_credentials(ConnectionConfig(username="readonly-api")) is None


def test_fetch_with_username_and_password(tmp_path, monkeypatch):
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    monkeypatch.setenv("PAN_PASSWORD", "s3cret")
    session = FakeSession(by_type={"keygen": KEYGEN_XML, "export": CONFIG_XML})
    monkeypatch.setattr(panos_api, "open_session", lambda conn: session)

    conn = ConnectionConfig(devices=["fw.example.com"], username="readonly-api")
    written, _ = fetch.fetch_backups(
        FetchConfig(enabled=True), conn, tmp_path, today=date(2026, 8, 4)
    )

    assert [p.read_bytes() for p in written] == [CONFIG_XML]
    assert [r["data"]["type"] for r in session.requests] == ["keygen", "export"]


def test_fetch_requires_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    conn = ConnectionConfig(devices=["fw.example.com"])
    with pytest.raises(FetchError, match="no credentials"):
        fetch.fetch_backups(FetchConfig(enabled=True), conn, tmp_path)


def test_fetch_reports_progress(tmp_path, monkeypatch):
    monkeypatch.setenv("PAN_API_KEY", "secret")
    monkeypatch.setattr(panos_api, "open_session", lambda conn: object())
    monkeypatch.setattr(panos_api, "export_configuration", lambda *a, **k: FIREWALL_XML)

    messages: list[str] = []
    conn = ConnectionConfig(devices=["fw.example.com"])
    fetch.fetch_backups(FetchConfig(enabled=True), conn, tmp_path, progress=messages.append)

    assert any("fetching configuration" in m for m in messages)


# ---------------------------------------------------------------------------
# Panorama: bundle the Panorama config and each managed firewall's config
# ---------------------------------------------------------------------------

PANORAMA_XML = (
    b'<config><devices><entry name="localhost.localdomain"><device-group>'
    b'<entry name="DG"/></device-group></entry></devices></config>'
)
FIREWALL_XML = b'<config><devices><entry name="localhost.localdomain"><vsys/></entry></devices></config>'


def test_panorama_fetch_bundles_device_configs(tmp_path, monkeypatch):
    import tarfile

    monkeypatch.setenv("PAN_API_KEY", "secret")
    monkeypatch.setattr(panos_api, "open_session", lambda conn: object())
    monkeypatch.setattr(panos_api, "export_configuration", lambda *a, **k: PANORAMA_XML)
    monkeypatch.setattr(
        panos_api, "list_connected_devices",
        lambda *a, **k: [("001901000123", "fwfra1", ["vsys1"])],
    )
    monkeypatch.setattr(
        panos_api, "export_managed_configuration", lambda s, p, key, serial, c: FIREWALL_XML
    )

    conn = ConnectionConfig(devices=["panorama.example.com"])
    written, _ = fetch.fetch_backups(
        FetchConfig(enabled=True), conn, tmp_path, today=date(2026, 8, 4)
    )

    assert len(written) == 1
    assert written[0].suffix == ".tgz"
    with tarfile.open(written[0]) as archive:
        names = archive.getnames()
    assert "panorama.example.com.xml" in names
    # The trailing serial lets the parser recover it from the member name.
    assert any(name.endswith("_001901000123.xml") for name in names)


def test_panorama_fetch_survives_one_unreachable_device(tmp_path, monkeypatch):
    import tarfile

    monkeypatch.setenv("PAN_API_KEY", "secret")
    monkeypatch.setattr(panos_api, "open_session", lambda conn: object())
    monkeypatch.setattr(panos_api, "export_configuration", lambda *a, **k: PANORAMA_XML)
    monkeypatch.setattr(
        panos_api, "list_connected_devices",
        lambda *a, **k: [("S1", "fw1", ["vsys1"]), ("S2", "fw2", ["vsys1"])],
    )

    def flaky(session, panorama, key, serial, config):
        if serial == "S2":
            raise FetchError("device unreachable")
        return FIREWALL_XML

    monkeypatch.setattr(panos_api, "export_managed_configuration", flaky)

    conn = ConnectionConfig(devices=["panorama.example.com"])
    written, notes = fetch.fetch_backups(
        FetchConfig(enabled=True), conn, tmp_path, today=date(2026, 8, 4)
    )

    with tarfile.open(written[0]) as archive:
        names = archive.getnames()
    assert any(name.endswith("_S1.xml") for name in names)
    assert not any(name.endswith("_S2.xml") for name in names)
    assert any("could not fetch device S2" in note for note in notes)



# ---------------------------------------------------------------------------
# Certificate fetch (fetch-cert)
# ---------------------------------------------------------------------------


def test_fetch_certificate_returns_pem_and_fingerprint(monkeypatch):
    raw = b"stand-in-for-a-DER-certificate"
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + base64.encodebytes(raw).decode("ascii")
        + "-----END CERTIFICATE-----\n"
    )
    monkeypatch.setattr(ssl, "get_server_certificate", lambda addr, timeout=None: pem)

    returned, fingerprint = panos_api.fetch_certificate("fw.example.com")

    assert returned == pem
    assert fingerprint.replace(":", "") == hashlib.sha256(raw).hexdigest().upper()


def test_fetch_certificate_reports_connection_errors(monkeypatch):
    def boom(addr, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr(ssl, "get_server_certificate", boom)
    with pytest.raises(FetchError, match="could not fetch a certificate"):
        panos_api.fetch_certificate("fw.example.com")
