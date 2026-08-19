"""A short-lived API key on this machine, for interactive testing.

A scheduled run authenticates as a dedicated read-only service account whose
API key sits in a file or the environment, and that is the right arrangement
for it.  Working *on* the inventory or the configuration is a different
situation: a person at a terminal, running the tool against a real device over
and over, often with no account but their own -- whose password, in the worst
case, is the one that opens every other door in the organisation.  Writing that
into a file or an environment variable to try something out is not a reasonable
price for a test run.

``pan-review login`` asks for the password once, exchanges it for an API key
through the device's read-only ``keygen`` call, and keeps only the key.  What
lands on the machine is therefore not the password but a credential that
carries exactly the account's read-only rights, that the device can revoke on
its own, and that this module stops honouring after a few hours.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .errors import EnrichmentError

# Long enough for a working day of editing the inventory, short enough that a
# forgotten session does not become a permanent credential.
DEFAULT_TTL_HOURS = 8
MAX_TTL_HOURS = 24

_DIR_NAME = "panorama-team-review"
_FILE_NAME = "session.json"
_FILE_MODE = 0o600
_DIR_MODE = 0o700


@dataclass(frozen=True)
class Session:
    """The keys held for one administrator, and when they stop being used."""

    username: str
    keys: dict[str, str]
    expires_at: datetime

    @property
    def remaining(self) -> timedelta:
        return self.expires_at - _now()

    def key_for(self, device: str, username: str | None) -> str | None:
        """The key for ``device``, or ``None``.

        A configured username that differs from the one the session was created
        with means the session belongs to a different account: silently using it
        would authenticate as somebody else and report their view of the estate.
        """
        if username and username != self.username:
            return None
        return self.keys.get(device)


def session_path() -> Path:
    """Where the session file lives.

    ``$XDG_RUNTIME_DIR`` is preferred because it is a private tmpfs the system
    wipes at logout: the key never reaches a disk and cannot outlive the login
    that created it.  Without one -- macOS, Windows, some SSH sessions -- this
    falls back to the XDG state directory, which *does* persist, which is why
    the file carries its own expiry as well.
    """
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and Path(runtime).is_dir():
        return Path(runtime) / _DIR_NAME / _FILE_NAME
    state = os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state"
    return Path(state) / _DIR_NAME / _FILE_NAME


def store(username: str, keys: dict[str, str], ttl_hours: int = DEFAULT_TTL_HOURS) -> Session:
    """Write ``keys`` as the current session and return it.

    Created private and replaced atomically, so the key is never briefly
    world-readable and a crash mid-write cannot leave a half-file that the next
    run would read as "no session" while the old one was already gone.
    """
    session = Session(
        username=username,
        keys=dict(keys),
        expires_at=_now() + timedelta(hours=ttl_hours),
    )
    path = session_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, _DIR_MODE)

    payload = json.dumps(
        {
            "username": session.username,
            "expires_at": session.expires_at.isoformat(),
            "keys": session.keys,
        },
        indent=2,
    )
    temporary = path.with_name(path.name + ".tmp")
    temporary.unlink(missing_ok=True)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(payload)
    os.replace(temporary, path)
    return session


def load() -> Session | None:
    """The current session, or ``None`` if there is none or it has expired.

    An expired file is removed on the way past: the session is a cache, and a
    stale one left lying around is a credential nobody is watching any more.
    """
    path = session_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        # Unreadable or corrupt: treat it as absent rather than as a failure --
        # the caller still has the environment and the configured files to try,
        # and ``pan-review login`` overwrites it.
        return None

    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise EnrichmentError(
            f"refusing to use the session key in {path}: it is readable by other users. "
            "Delete it with 'pan-review logout' and log in again."
        )

    if not isinstance(raw, dict):
        return None
    expires_at = _parse_time(raw.get("expires_at"))
    username = raw.get("username")
    keys = raw.get("keys")
    if expires_at is None or not isinstance(username, str) or not isinstance(keys, dict):
        return None
    if expires_at <= _now():
        clear()
        return None
    return Session(username=username, keys={str(k): str(v) for k, v in keys.items()}, expires_at=expires_at)


def key_for(device: str, username: str | None) -> str | None:
    """The stored key for ``device``, or ``None`` if there is no usable session."""
    session = load()
    return session.key_for(device, username) if session else None


def clear() -> bool:
    """Delete the session file. ``True`` if there was one."""
    try:
        session_path().unlink()
    except FileNotFoundError:
        return False
    except OSError:
        return False
    return True


def describe_remaining(remaining: timedelta) -> str:
    """``2h 40m`` -- how much of the session is left, for a human."""
    minutes = max(0, int(remaining.total_seconds() // 60))
    return f"{minutes // 60}h {minutes % 60:02d}m"


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    # A file written before a timezone was recorded would compare as naive.
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
