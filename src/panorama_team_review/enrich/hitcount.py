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
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from lxml import etree

from .. import panos_api
from ..config import HitCountConfig
from ..errors import EnrichmentError
from ..model import DeviceHit, HitCount, SecurityRule, Snapshot

# Transport is shared with the configuration-fetch feature. These aliases keep
# the call sites below readable and the read-only guarantee in a single place.
_operational = panos_api.operational
_session = panos_api.open_session
_api_key = panos_api.resolve_api_key
_xml_escape = panos_api.xml_escape

# Counters collected per managed firewall (through Panorama) are keyed by serial
# and rule name with this prefix, so `_apply` can tell them apart from a direct
# firewall's ``scope|rulebase|name`` keys and aggregate them per device group.
_DEVICE_KEY_PREFIX = "device\x1f"
_SEP = "\x1f"

# Bumped when the on-disk counter keying changes, so an older cache is ignored
# and rebuilt rather than silently mixed with the current format.
_CACHE_VERSION = 2


def enrich_snapshot(
    snapshot: Snapshot,
    config: HitCountConfig,
    offline_only: bool = False,
    progress: Callable[[str], None] | None = None,
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
            collected = collect(config, progress)
            counters.update(collected)
            notes.append(f"collected hit counts for {len(collected)} rules from the API")
            _write_cache(config, counters)
        except EnrichmentError as exc:
            notes.append(f"hit-count collection failed, continuing without it: {exc}")

    if not counters:
        return notes

    matched = _apply(snapshot.rules, counters, snapshot)
    notes.append(f"applied hit counts to {matched} of {len(snapshot.rules)} rules")
    return notes


def _apply(
    rules: list[SecurityRule],
    counters: dict[str, HitCount],
    snapshot: Snapshot | None = None,
) -> int:
    """Match counters onto rules.

    Two kinds of counter can be present:

    * **Direct** ``scope|rulebase|name`` keys, from talking to a firewall
      directly. Matched by the qualified key, then by an unambiguous bare name.
    * **Per-device** keys (``device\\x1f{serial}\\x1f{name}``), from talking to
      Panorama and proxying to each managed firewall. A device-group rule is the
      *sum* of its firewalls' counters -- with the per-firewall breakdown kept
      on the result -- and a firewall-local rule takes that one firewall's
      counter. This needs the snapshot to know which firewalls a device group
      reaches (including child device groups) and how serials map to hostnames.

    Attaching the wrong counter yields a confidently wrong "unused" verdict, so
    every fallback is guarded against ambiguity.
    """
    raw, direct = _split_counters(counters)
    bare_names: dict[str, int] = {}
    for key in direct:
        bare = key.rsplit("|", 1)[-1]
        bare_names[bare] = bare_names.get(bare, 0) + 1

    serial_host = {d.serial: (d.hostname or d.serial) for d in snapshot.devices} if snapshot else {}
    dg_serials = _dg_subtree_serials(snapshot.device_groups) if snapshot else {}
    all_serials = {d.serial for d in snapshot.devices} if snapshot else set()

    matched = 0
    for rule in rules:
        hit: HitCount | None = None
        loc = rule.location
        if raw and snapshot is not None and loc.device_group:
            hit = _aggregate(raw, dg_serials.get(loc.device_group, set()), rule.name, serial_host)
        elif raw and snapshot is not None and loc.device:
            serial = _serial_for_device(snapshot, loc.device)
            if serial is not None:
                hit = _aggregate(raw, {serial}, rule.name, serial_host)
        elif raw and snapshot is not None and loc.shared:
            # A shared pre/post rule is pushed to every managed firewall, so its
            # counters live under each one's serial rather than any device
            # group -- the device-group branch above never sees it. Sum across
            # every firewall, the same way a device-group rule sums its subtree.
            hit = _aggregate(raw, all_serials, rule.name, serial_host)

        if hit is None:
            hit = direct.get(_rule_key(rule))
            if hit is None and bare_names.get(rule.name, 0) == 1:
                hit = next(
                    (v for k, v in direct.items() if k.rsplit("|", 1)[-1] == rule.name), None
                )

        if hit is not None:
            rule.hits = hit
            matched += 1
    return matched


def _split_counters(
    counters: dict[str, HitCount],
) -> tuple[dict[tuple[str, str], HitCount], dict[str, HitCount]]:
    """Separate per-device counters (keyed by serial) from direct ones."""
    raw: dict[tuple[str, str], HitCount] = {}
    direct: dict[str, HitCount] = {}
    for key, hit in counters.items():
        if key.startswith(_DEVICE_KEY_PREFIX):
            parts = key.split(_SEP)
            if len(parts) == 3:
                raw[(parts[1], parts[2])] = hit
        else:
            direct[key] = hit
    return raw, direct


def _dg_subtree_serials(device_groups: dict) -> dict[str, set[str]]:
    """For each device group, the serials of every firewall it reaches.

    A pre/post rule in a parent device group is pushed to firewalls in its child
    device groups too, so the reachable set is the whole subtree, not just the
    group's direct members.
    """
    children: dict[str, list[str]] = defaultdict(list)
    for name, group in device_groups.items():
        if group.parent:
            children[group.parent].append(name)

    result: dict[str, set[str]] = {}
    for root in device_groups:
        serials: set[str] = set()
        seen: set[str] = set()
        stack = [root]
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            group = device_groups.get(name)
            if group is None:
                continue
            serials.update(group.devices)
            stack.extend(children.get(name, []))
        result[root] = serials
    return result


def _serial_for_device(snapshot: Snapshot, device_id: str) -> str | None:
    for device in snapshot.devices:
        if device.hostname == device_id or device.serial == device_id:
            return device.serial
    return None


def _aggregate(
    raw: dict[tuple[str, str], HitCount],
    serials: set[str],
    name: str,
    serial_host: dict[str, str],
) -> HitCount | None:
    """Sum one rule's counters across the given firewalls, keeping the breakdown."""
    contributions = [(serial, raw[(serial, name)]) for serial in serials if (serial, name) in raw]
    if not contributions:
        return None

    per_device = [
        DeviceHit(
            device=serial_host.get(serial, serial),
            hit_count=hit.hit_count,
            last_hit=hit.last_hit,
            source=hit.source,
        )
        for serial, hit in contributions
    ]
    # Newest first; firewalls that never matched sort last.
    per_device.sort(key=lambda d: (d.last_hit is not None, d.last_hit), reverse=True)

    return HitCount(
        hit_count=sum(hit.hit_count for _, hit in contributions),
        last_hit=max((h.last_hit for _, h in contributions if h.last_hit), default=None),
        first_hit=min((h.first_hit for _, h in contributions if h.first_hit), default=None),
        last_reset=max((h.last_reset for _, h in contributions if h.last_reset), default=None),
        collected_at=max((h.collected_at for _, h in contributions if h.collected_at), default=None),
        source=f"api: {len(contributions)} firewall(s)",
        per_device=per_device,
    )


def _rule_key(rule: SecurityRule) -> str:
    scope = rule.location.device_group or rule.location.vsys or "shared"
    rulebase = rule.location.rulebase.value if rule.location.rulebase else "local"
    return f"{scope}|{rulebase}|{rule.name}"


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def collect(
    config: HitCountConfig, progress: Callable[[str], None] | None = None
) -> dict[str, HitCount]:
    """Query every configured device for its rule hit counters.

    ``progress`` receives short status lines so an interactive run is not silent
    while the (potentially slow) network calls happen.
    """
    session = _session(config)
    if missing := panos_api.missing_credentials(config):
        raise EnrichmentError(missing)

    counters: dict[str, HitCount] = {}
    failures: list[str] = []

    for device in config.devices:
        _emit(progress, f"{device}: collecting hit counts…")
        try:
            key = panos_api.authenticate(session, device, config)
            counters.update(_collect_device(session, device, key, config, progress))
        except Exception as exc:  # noqa: BLE001 - reported, never fatal
            failures.append(f"{device}: {exc}")

    if failures and not counters:
        raise EnrichmentError("; ".join(failures))
    return counters


def _collect_device(
    session: Any,
    device: str,
    key: str,
    config: HitCountConfig,
    progress: Callable[[str], None] | None = None,
) -> dict[str, HitCount]:
    """Collect from one configured endpoint.

    A firewall is queried directly. A Panorama holds no runtime counters of its
    own -- they live on the managed firewalls -- so each connected firewall is
    queried *through* Panorama with the ``target`` parameter, and the results
    are keyed by serial for ``_apply`` to aggregate per device group.
    """
    if _is_panorama(session, device, key, config):
        return _collect_via_panorama(session, device, key, config, progress)
    return _collect_firewall(session, device, key, config)


def _collect_firewall(
    session: Any, device: str, key: str, config: HitCountConfig
) -> dict[str, HitCount]:
    counters: dict[str, HitCount] = {}
    collected_at = datetime.now()
    for vsys in _list_vsys(session, device, key, config):
        for rulebase in config.rulebases:
            root = _operational(session, device, key, _rule_hit_command(vsys, rulebase), config)
            counters.update(
                _parse_hit_counts(
                    root, scope=vsys, rulebase="local",
                    source=f"api:{device}", collected_at=collected_at,
                )
            )
    return counters


def _collect_via_panorama(
    session: Any,
    device: str,
    key: str,
    config: HitCountConfig,
    progress: Callable[[str], None] | None = None,
) -> dict[str, HitCount]:
    counters: dict[str, HitCount] = {}
    collected_at = datetime.now()
    managed = _list_managed_devices(session, device, key, config)
    for index, (serial, vsys_list) in enumerate(managed, start=1):
        _emit(progress, f"{device}: hit counts from {serial} ({index}/{len(managed)})…")
        for vsys in vsys_list or ["vsys1"]:
            for rulebase in config.rulebases:
                try:
                    root = _operational(
                        session, device, key, _rule_hit_command(vsys, rulebase),
                        config, target=serial,
                    )
                except EnrichmentError:
                    continue
                for name, hit in _iter_rule_hits(root, collected_at, f"api:{device}").items():
                    ckey = f"{_DEVICE_KEY_PREFIX}{serial}{_SEP}{name}"
                    existing = counters.get(ckey)
                    counters[ckey] = _merge_hits(existing, hit) if existing else hit
    return counters


def _emit(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _rule_hit_command(vsys: str, rulebase: str) -> str:
    return (
        "<show><rule-hit-count><vsys><vsys-name>"
        f"<entry name='{_xml_escape(vsys)}'><rule-base>"
        f"<entry name='{_xml_escape(rulebase)}'><rules><all/></rules>"
        "</entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>"
    )


def _merge_hits(a: HitCount, b: HitCount) -> HitCount:
    """Combine two counters for the same firewall and rule (e.g. across vsys)."""
    return HitCount(
        hit_count=a.hit_count + b.hit_count,
        last_hit=max((t for t in (a.last_hit, b.last_hit) if t), default=None),
        first_hit=min((t for t in (a.first_hit, b.first_hit) if t), default=None),
        last_reset=max((t for t in (a.last_reset, b.last_reset) if t), default=None),
        collected_at=max((t for t in (a.collected_at, b.collected_at) if t), default=None),
        source=a.source or b.source,
    )


def _is_panorama(session: Any, device: str, key: str, config: HitCountConfig) -> bool:
    try:
        root = _operational(
            session, device, key, "<show><system><info></info></system></show>", config
        )
    except EnrichmentError:
        return False
    model = root.findtext(".//model") or ""
    return "Panorama" in model or model.startswith("M-")


def _list_vsys(session: Any, device: str, key: str, config: HitCountConfig) -> list[str]:
    try:
        root = _operational(session, device, key, "<show><vsys></vsys></show>", config)
    except EnrichmentError:
        return ["vsys1"]
    names = [entry.get("name") for entry in root.iter("entry") if entry.get("name")]
    return names or ["vsys1"]


def _list_managed_devices(
    session: Any, device: str, key: str, config: HitCountConfig
) -> list[tuple[str, list[str]]]:
    """Return ``(serial, [vsys])`` for each connected managed firewall."""
    try:
        connected = panos_api.list_connected_devices(session, device, key, config)
    except EnrichmentError:
        return []
    return [(serial, vsys) for serial, _hostname, vsys in connected]


def _parse_hit_counts(
    result: etree._Element, scope: str, rulebase: str, source: str, collected_at: datetime
) -> dict[str, HitCount]:
    return {
        f"{scope}|{rulebase}|{name}": hit
        for name, hit in _iter_rule_hits(result, collected_at, source).items()
    }


def _iter_rule_hits(
    result: etree._Element, collected_at: datetime, source: str
) -> dict[str, HitCount]:
    hits: dict[str, HitCount] = {}
    for rules in result.iter("rules"):
        for entry in rules.findall("entry"):
            name = entry.get("name")
            if not name:
                continue
            hits[name] = _hit_from_entry(entry, collected_at, source)
    return hits


def _hit_from_entry(entry: etree._Element, collected_at: datetime, source: str) -> HitCount:
    return HitCount(
        hit_count=_int(entry.findtext("hit-count")),
        last_hit=_timestamp(entry.findtext("last-hit-timestamp")),
        first_hit=_timestamp(entry.findtext("first-hit-timestamp")),
        last_reset=_timestamp(entry.findtext("last-reset-timestamp")),
        rule_creation=_timestamp(entry.findtext("rule-creation-timestamp")),
        rule_modification=_timestamp(entry.findtext("rule-modification-timestamp")),
        collected_at=collected_at,
        source=source,
    )



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

    if raw.get("version") != _CACHE_VERSION:
        return {}, [
            f"hit-count cache at {path} is from an older format, ignoring it "
            "(it will be rebuilt on the next collection)"
        ]

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
        "version": _CACHE_VERSION,
        "collected_at": datetime.now().isoformat(),
        "counters": {key: value.model_dump(mode="json") for key, value in counters.items()},
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
