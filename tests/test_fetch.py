"""Optional live configuration fetch.

Two properties matter more than the details:

* it must never run unless explicitly enabled, and
* it must only ever read -- the export endpoint cannot change a device.

Everything here runs against fakes; no test in this file touches a network.
"""

from __future__ import annotations

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


class FakeResponse:
    def __init__(self, content: bytes, status_code: int = 200) -> None:
        self.content = content
        self.status_code = status_code


class FakeSession:
    """Records what it was asked to send, so tests can assert read-only intent."""

    def __init__(self, content: bytes = CONFIG_XML, status_code: int = 200) -> None:
        self._content = content
        self._status = status_code
        self.requests: list[dict] = []

    def post(self, url, data=None, timeout=None, verify=None):
        self.requests.append({"url": url, "data": data, "timeout": timeout, "verify": verify})
        return FakeResponse(self._content, self._status)


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
