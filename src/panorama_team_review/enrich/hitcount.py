"""Optional rule hit-count collection -- the only network-facing code here.

Why this module exists at all: hit counters are runtime state.  A PAN-OS or
Panorama configuration export contains the policy, never the counters, so
"is this rule still used?" -- the single most useful question in a cleanup
review -- cannot be answered from a backup.

Design constraints, all of them deliberate:

* **Disabled by default.**  The tool's contract is that it works offline; this
  module runs only when ``hitcounts.enabled`` is set.
* **Read-only.**  Only ``show`` operational commands are issued, and the
  command is checked against that before it goes out.  An API key restricted to
  a read-only admin role is strongly recommended regardless.
* **Credentials never live in the config file.**  The key comes from an
  environment variable or a file, so the configuration stays shareable.
* **Results are cached as sidecar JSON.**  A later offline run reuses them
  without touching the network, which is what makes a nightly collector plus
  hourly offline reports possible.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from lxml import etree

from .. import panos_api
from ..config import HitCountConfig
from ..errors import EnrichmentError
from ..model import HitCount, SecurityRule, Snapshot

# Transport is shared with the configuration-fetch feature. These aliases keep
# the call sites below readable and the read-only guarantee in a single place.
_operational = panos_api.operational
_session = panos_api.open_session
_api_key = panos_api.resolve_api_key
_xml_escape = panos_api.xml_escape


def enrich_snapshot(
    snapshot: Snapshot, config: HitCountConfig, offline_only: bool = False
) -> list[str]:
    """Attach hit counts to a snapshot's rules. Returns human-readable notes.

    Never raises on collection failure: a report without usage data is still
    useful, while a cron job that aborts because one firewall was unreachable
    produces nothing at all.
    """
    notes: list[str] = []
    if not config.enabled:
        return notes

    counters: dict[str, HitCount] = {}

    cached, cache_notes = _load_cache(config)
    counters.update(cached)
    notes.extend(cache_notes)

    if not offline_only and _cache_is_stale(config, counters):
        try:
            collected = collect(config)
            counters.update(collected)
            notes.append(f"collected hit counts for {len(collected)} rules from the API")
            _write_cache(config, counters)
        except EnrichmentError as exc:
            notes.append(f"hit-count collection failed, continuing without it: {exc}")

    if not counters:
        return notes

    matched = _apply(snapshot.rules, counters)
    notes.append(f"applied hit counts to {matched} of {len(snapshot.rules)} rules")
    return notes


def _apply(rules: list[SecurityRule], counters: dict[str, HitCount]) -> int:
    """Match counters onto rules.

    Rule names are unique only per rulebase, so the qualified key is tried
    first and the bare name only as a fallback -- and then only when it is
    unambiguous, since attaching the wrong counter to a rule would produce a
    confidently wrong "unused" verdict.
    """
    bare_names: dict[str, int] = {}
    for key in counters:
        bare = key.rsplit("|", 1)[-1]
        bare_names[bare] = bare_names.get(bare, 0) + 1

    matched = 0
    for rule in rules:
        qualified = _rule_key(rule)
        hit = counters.get(qualified)
        if hit is None and bare_names.get(rule.name, 0) == 1:
            hit = next(
                (value for key, value in counters.items() if key.rsplit("|", 1)[-1] == rule.name),
                None,
            )
        if hit is not None:
            rule.hits = hit
            matched += 1
    return matched


def _rule_key(rule: SecurityRule) -> str:
    scope = rule.location.device_group or rule.location.vsys or "shared"
    rulebase = rule.location.rulebase.value if rule.location.rulebase else "local"
    return f"{scope}|{rulebase}|{rule.name}"


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def collect(config: HitCountConfig) -> dict[str, HitCount]:
    """Query every configured device for its rule hit counters."""
    session = _session(config)
    key = _api_key(config)

    counters: dict[str, HitCount] = {}
    failures: list[str] = []

    for device in config.devices:
        try:
            counters.update(_collect_device(session, device, key, config))
        except Exception as exc:  # noqa: BLE001 - reported, never fatal
            failures.append(f"{device}: {exc}")

    if failures and not counters:
        raise EnrichmentError("; ".join(failures))
    return counters


def _collect_device(
    session: Any, device: str, key: str, config: HitCountConfig
) -> dict[str, HitCount]:
    counters: dict[str, HitCount] = {}
    collected_at = datetime.now()

    for vsys in _list_vsys(session, device, key, config):
        for rulebase in config.rulebases:
            command = (
                "<show><rule-hit-count><vsys><vsys-name>"
                f"<entry name='{_xml_escape(vsys)}'><rule-base>"
                f"<entry name='{_xml_escape(rulebase)}'><rules><all/></rules>"
                "</entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>"
            )
            root = _operational(session, device, key, command, config)
            counters.update(
                _parse_hit_counts(root, scope=vsys, rulebase="local",
                                  source=f"api:{device}", collected_at=collected_at)
            )

    for device_group, base in _list_device_groups(session, device, key, config):
        command = (
            "<show><rule-hit-count><device-group><entry "
            f"name='{_xml_escape(device_group)}'><{base}-rulebase>"
            "<entry name='security'><rules><all/></rules></entry>"
            f"</{base}-rulebase></entry></device-group></rule-hit-count></show>"
        )
        try:
            root = _operational(session, device, key, command, config)
        except EnrichmentError:
            continue
        counters.update(
            _parse_hit_counts(root, scope=device_group, rulebase=base,
                              source=f"api:{device}", collected_at=collected_at)
        )

    return counters


def _list_vsys(session: Any, device: str, key: str, config: HitCountConfig) -> list[str]:
    try:
        root = _operational(session, device, key, "<show><system><info></info></system></show>", config)
    except EnrichmentError:
        return ["vsys1"]
    model = root.findtext(".//model") or ""
    if "Panorama" in model or "M-" in model:
        return []
    try:
        root = _operational(session, device, key, "<show><vsys></vsys></show>", config)
    except EnrichmentError:
        return ["vsys1"]
    names = [entry.get("name") for entry in root.iter("entry") if entry.get("name")]
    return names or ["vsys1"]


def _list_device_groups(
    session: Any, device: str, key: str, config: HitCountConfig
) -> list[tuple[str, str]]:
    """Return (device_group, 'pre'|'post') pairs to query on a Panorama."""
    try:
        root = _operational(
            session, device, key, "<show><devicegroups></devicegroups></show>", config
        )
    except EnrichmentError:
        return []
    names = [
        entry.get("name")
        for entry in root.findall(".//devicegroups/entry")
        if entry.get("name")
    ]
    return [(name, base) for name in names for base in ("pre", "post")]


def _parse_hit_counts(
    result: etree._Element, scope: str, rulebase: str, source: str, collected_at: datetime
) -> dict[str, HitCount]:
    counters: dict[str, HitCount] = {}
    for rules in result.iter("rules"):
        for entry in rules.findall("entry"):
            name = entry.get("name")
            if not name:
                continue
            counters[f"{scope}|{rulebase}|{name}"] = HitCount(
                hit_count=_int(entry.findtext("hit-count")),
                last_hit=_timestamp(entry.findtext("last-hit-timestamp")),
                first_hit=_timestamp(entry.findtext("first-hit-timestamp")),
                last_reset=_timestamp(entry.findtext("last-reset-timestamp")),
                rule_creation=_timestamp(entry.findtext("rule-creation-timestamp")),
                rule_modification=_timestamp(entry.findtext("rule-modification-timestamp")),
                collected_at=collected_at,
                source=source,
            )
    return counters


def _int(value: str | None) -> int:
    try:
        return int((value or "0").strip())
    except ValueError:
        return 0


def _timestamp(value: str | None) -> datetime | None:
    """PAN-OS reports these as Unix epoch seconds; 0 means 'never'."""
    raw = (value or "").strip()
    if not raw or raw == "0":
        return None
    try:
        return datetime.fromtimestamp(int(raw))
    except (ValueError, OSError, OverflowError):
        return None


# ---------------------------------------------------------------------------
# Sidecar cache
# ---------------------------------------------------------------------------


def _cache_path(config: HitCountConfig) -> Path | None:
    if config.cache_dir is None:
        return None
    return config.cache_dir / "hitcounts.json"


def _load_cache(config: HitCountConfig) -> tuple[dict[str, HitCount], list[str]]:
    path = _cache_path(config)
    if path is None or not path.is_file():
        return {}, []

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {}, [f"hit-count cache at {path} is unreadable, ignoring it: {exc}"]

    counters = {key: HitCount.model_validate(value) for key, value in raw.get("counters", {}).items()}
    collected = raw.get("collected_at")
    note = f"loaded {len(counters)} cached hit counts collected {collected}" if counters else ""
    return counters, [note] if note else []


def _cache_is_stale(config: HitCountConfig, counters: dict[str, HitCount]) -> bool:
    if not counters:
        return True
    newest = max((c.collected_at for c in counters.values() if c.collected_at), default=None)
    if newest is None:
        return True
    return datetime.now() - newest > timedelta(hours=config.cache_max_age_hours)


def _write_cache(config: HitCountConfig, counters: dict[str, HitCount]) -> None:
    path = _cache_path(config)
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "collected_at": datetime.now().isoformat(),
        "counters": {key: value.model_dump(mode="json") for key, value in counters.items()},
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
