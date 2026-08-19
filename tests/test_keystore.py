"""The short-lived API-key session behind ``pan-review login``.

Two properties carry the feature: the password must never reach the disk, and
the key that does must stop working on its own. Everything here runs against
fakes; no test in this file touches a network.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from panorama_team_review import keystore, panos_api
from panorama_team_review.cli import EXIT_CONFIG, EXIT_OK, main
from panorama_team_review.config import ConnectionConfig
from panorama_team_review.errors import EnrichmentError

KEYGEN_XML = b'<response status="success"><result><key>GENERATED-KEY</key></result></response>'


class FakeResponse:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.status_code = 200


class FakeSession:
    def __init__(self, content: bytes = KEYGEN_XML) -> None:
        self._content = content
        self.requests: list[dict] = []

    def post(self, url, data=None, timeout=None, verify=None):
        self.requests.append({"url": url, "data": data})
        return FakeResponse(self._content)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def no_ambient_key(monkeypatch):
    """An explicit key wins over the session, so it must not leak in from the environment."""
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    monkeypatch.delenv("PAN_PASSWORD", raising=False)


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


def test_a_stored_session_is_read_back():
    keystore.store("readonly-api", {"fw.example.com": "KEY-1"})
    session = keystore.load()

    assert session is not None
    assert session.username == "readonly-api"
    assert session.key_for("fw.example.com", None) == "KEY-1"


def test_the_session_file_is_private():
    keystore.store("readonly-api", {"fw.example.com": "KEY-1"})
    path = keystore.session_path()

    assert path.stat().st_mode & 0o077 == 0
    assert path.parent.stat().st_mode & 0o077 == 0


def test_a_session_readable_by_others_is_refused():
    keystore.store("readonly-api", {"fw.example.com": "KEY-1"})
    path = keystore.session_path()
    os.chmod(path, 0o644)

    with pytest.raises(EnrichmentError, match="readable by other users"):
        keystore.load()


def test_an_expired_session_is_ignored_and_removed():
    keystore.store("readonly-api", {"fw.example.com": "KEY-1"})
    path = keystore.session_path()
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["expires_at"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    path.write_text(json.dumps(raw), encoding="utf-8")

    assert keystore.load() is None
    assert not path.exists()


def test_no_session_is_not_an_error():
    assert keystore.load() is None
    assert keystore.key_for("fw.example.com", None) is None
    assert keystore.clear() is False


def test_a_corrupt_session_is_treated_as_absent():
    path = keystore.session_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not json", encoding="utf-8")
    os.chmod(path, 0o600)

    assert keystore.load() is None


def test_clear_removes_the_session():
    keystore.store("readonly-api", {"fw.example.com": "KEY-1"})
    assert keystore.clear() is True
    assert keystore.load() is None


def test_a_session_for_another_user_is_not_used():
    keystore.store("colleague", {"fw.example.com": "KEY-1"})
    session = keystore.load()

    assert session is not None
    assert session.key_for("fw.example.com", "readonly-api") is None
    assert session.key_for("fw.example.com", "colleague") == "KEY-1"


def test_a_session_is_only_used_for_the_devices_it_covers():
    keystore.store("readonly-api", {"a.example.com": "KEY-A"})

    assert keystore.key_for("a.example.com", None) == "KEY-A"
    assert keystore.key_for("b.example.com", None) is None


# ---------------------------------------------------------------------------
# How authentication uses it
# ---------------------------------------------------------------------------


def test_authenticate_uses_a_stored_key_without_a_password():
    keystore.store("readonly-api", {"fw.example.com": "STORED-KEY"})
    session = FakeSession()

    key = panos_api.authenticate(session, "fw.example.com", ConnectionConfig())

    assert key == "STORED-KEY"
    assert session.requests == []  # no keygen: the exchange already happened


def test_an_explicit_key_still_wins_over_a_stored_one(monkeypatch):
    keystore.store("readonly-api", {"fw.example.com": "STORED-KEY"})
    monkeypatch.setenv("PAN_API_KEY", "explicit-key")

    assert panos_api.authenticate(FakeSession(), "fw.example.com", ConnectionConfig()) == "explicit-key"


def test_a_stored_key_satisfies_the_credential_check():
    assert panos_api.missing_credentials(ConnectionConfig()) is not None
    keystore.store("readonly-api", {"fw.example.com": "STORED-KEY"})
    assert panos_api.missing_credentials(ConnectionConfig()) is None


def test_the_credential_message_points_at_login():
    assert "pan-review login" in (panos_api.missing_credentials(ConnectionConfig()) or "")


def test_a_stored_key_for_a_different_user_falls_through_to_keygen(monkeypatch):
    keystore.store("colleague", {"fw.example.com": "COLLEAGUE-KEY"})
    monkeypatch.setenv("PAN_PASSWORD", "s3cret")
    session = FakeSession()

    key = panos_api.authenticate(
        session, "fw.example.com", ConnectionConfig(username="readonly-api")
    )

    assert key == "GENERATED-KEY"
    assert session.requests[-1]["data"]["type"] == "keygen"


# ---------------------------------------------------------------------------
# The commands
# ---------------------------------------------------------------------------


def _config_file(tmp_path: Path, devices: list[str]) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(
        "hitcounts:\n  devices: [" + ", ".join(devices) + "]\n", encoding="utf-8"
    )
    return path


def test_login_stores_a_key_and_never_the_password(runner, monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(panos_api, "open_session", lambda config: session)

    result = runner.invoke(main, ["login", "fw.example.com"], input="s3cret\n")

    assert result.exit_code == EXIT_OK, result.output
    stored = keystore.load()
    assert stored is not None
    assert stored.keys == {"fw.example.com": "GENERATED-KEY"}
    assert "s3cret" not in keystore.session_path().read_text(encoding="utf-8")
    assert "s3cret" not in result.output
    assert session.requests[-1]["data"]["type"] == "keygen"


def test_login_covers_every_configured_device(runner, monkeypatch, tmp_path):
    monkeypatch.setattr(panos_api, "open_session", lambda config: FakeSession())
    config = _config_file(tmp_path, ["a.example.com", "b.example.com"])

    result = runner.invoke(main, ["-c", str(config), "login"], input="s3cret\n")

    assert result.exit_code == EXIT_OK, result.output
    stored = keystore.load()
    assert stored is not None
    assert sorted(stored.keys) == ["a.example.com", "b.example.com"]


def test_login_without_any_device_is_actionable(runner):
    result = runner.invoke(main, ["login"], input="s3cret\n")

    assert result.exit_code == EXIT_CONFIG
    assert "no devices given" in result.output


def test_login_hours_bounds_the_session(runner, monkeypatch):
    monkeypatch.setattr(panos_api, "open_session", lambda config: FakeSession())

    result = runner.invoke(
        main, ["login", "--hours", "1", "fw.example.com"], input="s3cret\n"
    )

    assert result.exit_code == EXIT_OK, result.output
    stored = keystore.load()
    assert stored is not None
    assert stored.remaining <= timedelta(hours=1)


def test_login_refuses_an_absurd_duration(runner):
    result = runner.invoke(
        main, ["login", "--hours", "999", "fw.example.com"], input="s3cret\n"
    )
    assert result.exit_code != EXIT_OK


def test_logout_removes_the_session(runner):
    keystore.store("readonly-api", {"fw.example.com": "KEY-1"})

    result = runner.invoke(main, ["logout"])

    assert result.exit_code == EXIT_OK
    assert keystore.load() is None
    assert "removed" in result.output


def test_logout_without_a_session_says_so(runner):
    result = runner.invoke(main, ["logout"])

    assert result.exit_code == EXIT_OK
    assert "no stored session" in result.output
