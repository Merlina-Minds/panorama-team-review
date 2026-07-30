"""Turn a loaded PAN-OS or Panorama XML document into a ``Snapshot``.

The two hierarchies:

*Firewall* -- objects and one rulebase live under each vsys, plus a global
``shared`` scope::

    /config/shared/{address,address-group,service,...}
    /config/devices/entry/vsys/entry/{address,...,rulebase/{security,nat}}

*Panorama* -- objects live under ``shared`` and under each device group, and
rules are split into a pre- and a post-rulebase that bracket the firewall's own
rules at push time::

    /config/shared/{address,...,pre-rulebase,post-rulebase}
    /config/devices/entry/device-group/entry/{address,...,pre-rulebase,post-rulebase}
    /config/devices/entry/template/entry/config/... (zones)

Device-group inheritance is *not* flattened here.  The parser records where
each object was defined and the resolver walks the ancestry when looking a name
up, which keeps the snapshot faithful to the configuration as written.
"""

from __future__ import annotations

import re
from datetime import datetime

from lxml import etree

from ..model import (
    DeviceGroup,
    Location,
    ManagedDevice,
    Rulebase,
    Snapshot,
    SnapshotMeta,
)
from . import common as c
from .loader import LoadedConfig

SHARED = "shared"

# How Panorama names the member documents in a scheduled backup archive:
# hostname, underscore, serial. Serials are numeric and at least nine digits,
# which is what keeps this from biting a hostname that merely contains an
# underscore and a few digits.
_MEMBER_NAME = re.compile(r"^(?P<host>.+)_(?P<serial>\d{9,})$")


def parse(loaded: LoadedConfig, tool_version: str = "0.1.0") -> Snapshot:
    """Parse a loaded configuration, dispatching on its detected type."""
    kind = loaded.detect_type()
    root = loaded.root

    meta = SnapshotMeta(
        source_file=loaded.source_name,
        source_files=[loaded.source_name],
        source_type=kind,  # type: ignore[arg-type]
        file_mtime=loaded.mtime,
        parsed_at=datetime.now(),
        pan_os_version=root.get("version"),
        hostname=c.text(root, ".//devices/entry/deviceconfig/system/hostname") or None,
        tool_version=tool_version,
        config_hash=loaded.config_hash,
    )
    snapshot = Snapshot(meta=meta)

    if kind == "panorama":
        _parse_panorama(root, snapshot, loaded.source_name)
    else:
        _parse_firewall(root, snapshot, loaded.source_name)

    return snapshot


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------


def _parse_firewall(root: etree._Element, snap: Snapshot, source: str) -> None:
    # Every firewall has its own `shared` and `vsys` namespaces. Tagging them
    # with the device keeps them apart when several configurations from one
    # Panorama backup archive are merged.
    device_id, serial = _device_identity(root, source)

    # Register the device under its own name. The Panorama document knows the
    # serial's device group but not its hostname, and the member document knows
    # the hostname but not the group; recording both halves lets `merge` join
    # them, which is what turns 'fw-eu-01_<serial>' into 'fw-eu-01, site EU'
    # in a report.
    if serial:
        snap.devices.append(ManagedDevice(serial=serial, hostname=device_id))

    shared = root.find("shared")
    if shared is not None:
        loc = Location(source=source, kind="firewall", device=device_id, shared=True)
        _collect_objects(shared, loc, snap)

    for device in root.findall("devices/entry"):
        for vsys in device.findall("vsys/entry"):
            name = vsys.get("name") or "vsys1"
            loc = Location(source=source, kind="firewall", device=device_id, vsys=name)
            _collect_objects(vsys, loc, snap)
            snap.zones.update(c.parse_zones(vsys))

            rulebase = vsys.find("rulebase")
            if rulebase is not None:
                rb_loc = c.rulebase_location(loc, Rulebase.LOCAL)
                snap.rules.extend(c.parse_security_rules(rulebase, rb_loc))
                snap.nat_rules.extend(c.parse_nat_rules(rulebase, rb_loc))


def _device_identity(root: etree._Element, source: str) -> tuple[str, str | None]:
    """Name and serial of the firewall a local configuration belongs to.

    The hostname is preferred because it is what an operator recognises. Inside
    a Panorama backup archive the member name carries the hostname and serial
    (``fw-eu-02_<serial>.xml``), which is the fallback when the
    configuration itself has no hostname set -- and in practice it usually is,
    because a member document exported by Panorama carries no hostname of its
    own.

    The serial is split off rather than left in the name. It is what joins this
    document to the device-group membership recorded on the Panorama side, and
    an owner reading ``fw-eu-02/local, position 12`` learns something that
    ``fw-eu-02_<serial>:vsys1`` hides.
    """
    member = source.rsplit(":", 1)[-1]
    stem = member.rsplit("/", 1)[-1].removesuffix(".xml")
    match = _MEMBER_NAME.match(stem)
    serial = match.group("serial") if match else None

    hostname = c.text(root, ".//devices/entry/deviceconfig/system/hostname")
    if hostname:
        return hostname, serial
    if match:
        return match.group("host"), serial
    return stem or source, None


# ---------------------------------------------------------------------------
# Panorama
# ---------------------------------------------------------------------------


def _parse_panorama(root: etree._Element, snap: Snapshot, source: str) -> None:
    shared = root.find("shared")
    if shared is not None:
        loc = Location(source=source, kind="panorama", shared=True)
        _collect_objects(shared, loc, snap)
        _collect_panorama_rules(shared, loc, snap)

    for device in root.findall("devices/entry"):
        _parse_device_groups(device, snap, source)
        _parse_templates(device, snap)

    # The hierarchy has to be read before the links are validated, because on
    # most PAN-OS versions it does not live where the device groups do.
    _read_readonly_hierarchy(root, snap)
    _link_device_group_parents(snap)


def _parse_device_groups(device: etree._Element, snap: Snapshot, source: str) -> None:
    container = device.find("device-group")
    if container is None:
        return

    for entry in container.findall("entry"):
        name = entry.get("name")
        if not name:
            continue

        serials = c.entry_names(entry, "devices")
        snap.device_groups[name] = DeviceGroup(
            name=name,
            # Panorama stores the hierarchy on the child, pointing upwards.
            parent=c.text(entry, "parent-dg") or None,
            devices=serials,
            description=c.text(entry, "description"),
        )
        for serial in serials:
            snap.devices.append(ManagedDevice(serial=serial, device_group=name))

        loc = Location(source=source, kind="panorama", device_group=name)
        _collect_objects(entry, loc, snap)
        _collect_panorama_rules(entry, loc, snap)


def _collect_panorama_rules(scope: etree._Element, loc: Location, snap: Snapshot) -> None:
    """Read the pre- and post-rulebase of a shared or device-group scope."""
    for path, kind in (("pre-rulebase", Rulebase.PRE), ("post-rulebase", Rulebase.POST)):
        rulebase = scope.find(path)
        if rulebase is None:
            continue
        rb_loc = c.rulebase_location(loc, kind)
        snap.rules.extend(c.parse_security_rules(rulebase, rb_loc))
        snap.nat_rules.extend(c.parse_nat_rules(rulebase, rb_loc))


def _parse_templates(device: etree._Element, snap: Snapshot) -> None:
    """Pull zone definitions out of templates.

    Zones are configured in templates, not device groups, but rules reference
    them -- so a zone-based ownership rule needs this.
    """
    container = device.find("template")
    if container is None:
        return
    for entry in container.findall("entry"):
        for vsys in entry.findall("config/devices/entry/vsys/entry"):
            snap.zones.update(c.parse_zones(vsys))


def _link_device_group_parents(snap: Snapshot) -> None:
    """Resolve parent links that Panorama stores outside the device-group node.

    Older PAN-OS releases keep the hierarchy in ``/config/readonly/devices`` or
    in a ``dg-meta-data`` block rather than as ``<parent-dg>``.  Anything still
    without a parent is treated as a root device group, which is correct for a
    flat estate and harmless for a nested one that used ``<parent-dg>``.
    """
    for name, group in snap.device_groups.items():
        if group.parent and group.parent not in snap.device_groups:
            snap.parse_warnings.append(
                f"device group {name!r} references unknown parent {group.parent!r}; "
                "treating it as a root group"
            )
            group.parent = None


def _read_readonly_hierarchy(root: etree._Element, snap: Snapshot) -> None:
    """Read the device-group hierarchy out of the ``readonly`` block.

    This is where Panorama actually keeps it. The editable device-group nodes
    under ``/config/devices`` carry the objects and rules but, on the PAN-OS
    versions seen in the field, *not* the parent link; that is mirrored into
    ``/config/readonly/devices/entry/device-group/entry/parent-dg``.

    Getting this wrong is not cosmetic. Without the parent link, a rule in a
    child device group cannot see the objects defined in its parent, so every
    such reference resolves to nothing and the report silently understates what
    the rule permits -- on a nested estate, that is most of it.

    Both locations are read: some versions do populate the editable node, and a
    configuration that has it in both places must not end up inconsistent.
    """
    for entry in root.findall("readonly/devices/entry/device-group/entry"):
        name = entry.get("name")
        parent = c.text(entry, "parent-dg")
        if name and parent and name in snap.device_groups:
            snap.device_groups[name].parent = parent

    # Older exports used a dg-meta-data block instead.
    meta = root.find(".//readonly/dg-meta-data/dginfo")
    if meta is not None:
        for entry in meta.iter("entry"):
            name = entry.get("name")
            parent = entry.get("parent-dg") or c.text(entry, "parent-dg")
            if name in snap.device_groups and parent in snap.device_groups:
                snap.device_groups[name].parent = parent


# ---------------------------------------------------------------------------
# Object collection
# ---------------------------------------------------------------------------


def _collect_objects(scope: etree._Element, loc: Location, snap: Snapshot) -> None:
    snap.addresses.extend(c.parse_addresses(scope, loc))
    snap.address_groups.extend(c.parse_address_groups(scope, loc))
    snap.services.extend(c.parse_services(scope, loc))
    snap.service_groups.extend(c.parse_service_groups(scope, loc))
    snap.tags.extend(c.parse_tags(scope, loc))
    snap.external_lists.extend(c.parse_external_lists(scope, loc))


# ---------------------------------------------------------------------------
# Merging several documents from one backup archive
# ---------------------------------------------------------------------------


def merge(snapshots: list[Snapshot]) -> Snapshot:
    """Combine the snapshots from one multi-document backup archive.

    A Panorama scheduled backup contains the Panorama configuration plus one
    document per managed firewall.  Reporting on them separately would split a
    single rule path across files, so they are merged into one snapshot with
    ``Location.source`` keeping them distinguishable.
    """
    if not snapshots:
        raise ValueError("merge() requires at least one snapshot")
    if len(snapshots) == 1:
        return snapshots[0]

    # The Panorama document, if present, owns the merged identity: it holds the
    # device groups the firewall documents are members of.
    primary = next((s for s in snapshots if s.meta.source_type == "panorama"), snapshots[0])
    merged = Snapshot(meta=primary.meta.model_copy())

    for snap in snapshots:
        merged.device_groups.update(snap.device_groups)
        merged.devices.extend(snap.devices)
        merged.addresses.extend(snap.addresses)
        merged.address_groups.extend(snap.address_groups)
        merged.services.extend(snap.services)
        merged.service_groups.extend(snap.service_groups)
        merged.tags.extend(snap.tags)
        merged.external_lists.extend(snap.external_lists)
        merged.rules.extend(snap.rules)
        merged.nat_rules.extend(snap.nat_rules)
        merged.zones.update(snap.zones)
        merged.parse_warnings.extend(snap.parse_warnings)

    merged.devices = _join_devices(merged.devices)

    merged.meta.source_file = ", ".join(sorted({s.meta.source_file for s in snapshots}))
    merged.meta.source_files = sorted({s.meta.source_file for s in snapshots})
    return merged


def _join_devices(devices: list[ManagedDevice]) -> list[ManagedDevice]:
    """Combine the records for one firewall into a single entry.

    A managed firewall is described twice in a Panorama archive and each half
    is incomplete: the Panorama document knows which device group a serial
    belongs to, the member document knows the hostname. Keeping whichever was
    seen first -- what this used to do -- threw one half away, and which half
    depended on the order tar happened to store the members in.
    """
    joined: dict[str, ManagedDevice] = {}
    for device in devices:
        existing = joined.get(device.serial)
        if existing is None:
            joined[device.serial] = device.model_copy()
            continue
        for name in ("hostname", "ip_address", "device_group", "model", "sw_version"):
            if getattr(existing, name) is None:
                setattr(existing, name, getattr(device, name))
    return list(joined.values())
