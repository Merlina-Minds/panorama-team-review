"""Generate synthetic PAN-OS and Panorama configurations for tests and demos.

**This is the only source of test data in this repository.**  No customer
configuration, anonymised or otherwise, is ever committed -- see
``docs/PRIVACY.md``.  Everything produced here uses addresses from the
documentation ranges reserved by RFC 5737 and RFC 3849 plus RFC 1918 private
space, and ``example.com`` style names, so nothing can be traced to a real
estate even by coincidence.

Generation is deterministic given a seed, which is what lets tests assert on
exact output.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import date, timedelta

from lxml import etree

# Documentation-only address space. Never replace these with anything real.
DOC_NET_A = "192.0.2.0/24"      # RFC 5737 TEST-NET-1
DOC_NET_B = "198.51.100.0/24"   # RFC 5737 TEST-NET-2
DOC_NET_C = "203.0.113.0/24"    # RFC 5737 TEST-NET-3
DOC_NET_V6 = "2001:db8::/32"    # RFC 3849

INTERNAL_NETS = ["10.10.0.0/16", "10.20.0.0/16", "10.30.0.0/16", "172.16.0.0/16"]


@dataclass
class GeneratorOptions:
    """Knobs for shaping the generated estate."""

    seed: int = 20260728
    device_groups: int = 3
    rules_per_group: int = 12
    addresses_per_group: int = 15
    include_dynamic_groups: bool = True
    include_ipv6: bool = True
    include_expired_rules: bool = True
    include_broken_references: bool = True

    # Panorama mirrors the device-group hierarchy into a `readonly` block and,
    # on the versions seen in the field, keeps the parent links *only* there.
    # Defaulting to that shape means the fixture matches what real exports look
    # like; flip `hierarchy_in_readonly_only` to cover the other arrangement.
    include_readonly_hierarchy: bool = True
    hierarchy_in_readonly_only: bool = True
    pan_os_version: str = "11.1.0"
    hostname: str = "panorama.example.com"
    firewall_hostname: str = "fw-edge-01.example.com"


@dataclass
class _Builder:
    """Accumulates the pieces of one generated configuration."""

    options: GeneratorOptions
    rng: random.Random
    today: date = field(default_factory=lambda: date(2026, 7, 28))


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def generate_panorama(options: GeneratorOptions | None = None) -> str:
    """Return a Panorama configuration as an XML string."""
    options = options or GeneratorOptions()
    builder = _Builder(options, random.Random(options.seed))

    config = etree.Element("config", version=options.pan_os_version, urldb="paloaltonetworks")

    shared = etree.SubElement(config, "shared")
    _add_tags(shared, ["owner:platform", "owner:payments", "reviewed-2026", "temporary"])
    _add_addresses(shared, _shared_addresses())
    _add_address_group(shared, "grp-dns-servers", ["srv-dns-1", "srv-dns-2"])
    _add_services(shared, _shared_services())
    _add_service_group(shared, "svc-grp-web", ["svc-https", "svc-http-alt"])
    _add_shared_rules(shared, builder)

    devices = etree.SubElement(config, "devices")
    device = etree.SubElement(devices, "entry", name="localhost.localdomain")
    _add_system(device, options.hostname)

    device_groups = etree.SubElement(device, "device-group")
    names = _device_group_names(options.device_groups)
    parents: dict[str, str] = {}
    for index, name in enumerate(names):
        parent = names[0] if index > 0 and index % 2 == 0 else None
        if parent:
            parents[name] = parent
        _add_device_group(device_groups, name, parent, index, builder)

    _add_template(device, builder)
    _add_readonly(config, names, parents, options)

    return _serialise(config)


def generate_firewall(options: GeneratorOptions | None = None) -> str:
    """Return a standalone PAN-OS firewall configuration as an XML string."""
    options = options or GeneratorOptions()
    builder = _Builder(options, random.Random(options.seed + 1))

    config = etree.Element("config", version=options.pan_os_version, urldb="paloaltonetworks")

    shared = etree.SubElement(config, "shared")
    _add_tags(shared, ["owner:platform", "temporary"])
    _add_addresses(shared, _shared_addresses()[:3])
    _add_services(shared, _shared_services())

    devices = etree.SubElement(config, "devices")
    device = etree.SubElement(devices, "entry", name="localhost.localdomain")
    _add_system(device, options.firewall_hostname)

    vsys_container = etree.SubElement(device, "vsys")
    vsys = etree.SubElement(vsys_container, "entry", name="vsys1")

    _add_tags(vsys, ["owner:payments", "pci"])
    _add_addresses(vsys, _group_addresses("edge", builder, count=10, net_index=1))
    _add_address_group(vsys, "grp-edge-web", ["edge-host-01", "edge-host-02"])
    _add_zones(vsys, ["trust", "untrust", "dmz"])

    rulebase = etree.SubElement(vsys, "rulebase")
    security = etree.SubElement(rulebase, "security")
    rules = etree.SubElement(security, "rules")
    for index in range(options.rules_per_group):
        _add_rule(rules, f"fw-local-{index + 1:02d}", "edge", builder, index)

    nat = etree.SubElement(rulebase, "nat")
    nat_rules = etree.SubElement(nat, "rules")
    _add_nat_rule(nat_rules, "nat-outbound-01", builder)

    return _serialise(config)


def write_pair(directory, options: GeneratorOptions | None = None) -> dict[str, str]:
    """Write both configurations into ``directory``; returns name -> path."""
    from pathlib import Path

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    panorama = directory / "panorama-running-config.xml"
    firewall = directory / "firewall-running-config.xml"
    panorama.write_text(generate_panorama(options), encoding="utf-8")
    firewall.write_text(generate_firewall(options), encoding="utf-8")
    return {"panorama": str(panorama), "firewall": str(firewall)}


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------


def _serialise(root: etree._Element) -> str:
    return etree.tostring(root, pretty_print=True, encoding="unicode", xml_declaration=False)


def _device_group_names(count: int) -> list[str]:
    base = ["DG-Shared-Services", "DG-Production", "DG-Development", "DG-DMZ", "DG-Partner"]
    return base[:count] if count <= len(base) else base + [f"DG-Extra-{i}" for i in range(count - len(base))]


def _add_system(device: etree._Element, hostname: str) -> None:
    deviceconfig = etree.SubElement(device, "deviceconfig")
    system = etree.SubElement(deviceconfig, "system")
    etree.SubElement(system, "hostname").text = hostname
    etree.SubElement(system, "domain").text = "example.com"


def _add_tags(scope: etree._Element, names: list[str]) -> None:
    container = etree.SubElement(scope, "tag")
    for index, name in enumerate(names):
        entry = etree.SubElement(container, "entry", name=name)
        etree.SubElement(entry, "color").text = f"color{index % 16 + 1}"
        etree.SubElement(entry, "comments").text = f"Tag {name} used for grouping"


def _shared_addresses() -> list[tuple[str, str, str, str, list[str]]]:
    """(name, kind, value, description, tags)"""
    return [
        ("srv-dns-1", "ip-netmask", "10.10.1.10/32", "Primary DNS resolver", ["owner:platform"]),
        ("srv-dns-2", "ip-netmask", "10.10.1.11/32", "Secondary DNS resolver", ["owner:platform"]),
        ("net-management", "ip-netmask", "10.10.0.0/16", "Management network", ["owner:platform"]),
        ("net-internet-doc", "ip-netmask", DOC_NET_A, "Documentation range standing in for the internet", []),
        ("partner-range", "ip-range", "198.51.100.10-198.51.100.20", "Partner uplink addresses", []),
        ("update-service", "fqdn", "updates.example.com", "Vendor update service", []),
        ("net-v6-lab", "ip-netmask", DOC_NET_V6, "IPv6 documentation prefix", []),
    ]


def _shared_services() -> list[tuple[str, str, str, str]]:
    """(name, protocol, port, description)"""
    return [
        ("svc-https", "tcp", "443", "HTTPS"),
        ("svc-http-alt", "tcp", "8080,8443", "Alternate HTTP ports"),
        ("svc-ssh", "tcp", "22", "SSH administration"),
        ("svc-dns", "udp", "53", "DNS"),
        ("svc-postgres", "tcp", "5432", "PostgreSQL"),
        ("svc-app-range", "tcp", "9000-9100", "Application port range"),
    ]


def _add_addresses(scope: etree._Element, entries) -> None:
    container = scope.find("address")
    if container is None:
        container = etree.SubElement(scope, "address")
    for name, kind, value, description, tags in entries:
        entry = etree.SubElement(container, "entry", name=name)
        etree.SubElement(entry, kind).text = value
        etree.SubElement(entry, "description").text = description
        if tags:
            tag_node = etree.SubElement(entry, "tag")
            for tag in tags:
                etree.SubElement(tag_node, "member").text = tag


def _add_address_group(scope: etree._Element, name: str, members: list[str]) -> None:
    container = scope.find("address-group")
    if container is None:
        container = etree.SubElement(scope, "address-group")
    entry = etree.SubElement(container, "entry", name=name)
    static = etree.SubElement(entry, "static")
    for member in members:
        etree.SubElement(static, "member").text = member
    etree.SubElement(entry, "description").text = f"Static group {name}"


def _add_dynamic_group(scope: etree._Element, name: str, filter_expression: str) -> None:
    container = scope.find("address-group")
    if container is None:
        container = etree.SubElement(scope, "address-group")
    entry = etree.SubElement(container, "entry", name=name)
    dynamic = etree.SubElement(entry, "dynamic")
    etree.SubElement(dynamic, "filter").text = filter_expression
    etree.SubElement(entry, "description").text = f"Dynamic group matching {filter_expression}"


def _add_services(scope: etree._Element, entries) -> None:
    container = etree.SubElement(scope, "service")
    for name, protocol, port, description in entries:
        entry = etree.SubElement(container, "entry", name=name)
        protocol_node = etree.SubElement(entry, "protocol")
        proto_node = etree.SubElement(protocol_node, protocol)
        etree.SubElement(proto_node, "port").text = port
        etree.SubElement(entry, "description").text = description


def _add_service_group(scope: etree._Element, name: str, members: list[str]) -> None:
    container = etree.SubElement(scope, "service-group")
    entry = etree.SubElement(container, "entry", name=name)
    members_node = etree.SubElement(entry, "members")
    for member in members:
        etree.SubElement(members_node, "member").text = member


def _add_zones(scope: etree._Element, names: list[str]) -> None:
    container = etree.SubElement(scope, "zone")
    for index, name in enumerate(names):
        entry = etree.SubElement(container, "entry", name=name)
        network = etree.SubElement(entry, "network")
        layer3 = etree.SubElement(network, "layer3")
        etree.SubElement(layer3, "member").text = f"ethernet1/{index + 1}"


def _group_addresses(prefix: str, builder: _Builder, count: int, net_index: int = 0):
    """Host objects inside one of the internal networks.

    ``net_index`` rather than a random pick: a fixture whose addresses move
    when an unrelated part of the generator changes is worthless for tests, and
    a reader of the example inventory should be able to see which network
    belongs to which device group.
    """
    base = INTERNAL_NETS[net_index % len(INTERNAL_NETS)].split("/")[0].rsplit(".", 2)[0]
    entries = []
    for index in range(count):
        octet_c = (index // 250) + 1
        octet_d = (index % 250) + 5
        entries.append(
            (
                f"{prefix}-host-{index + 1:02d}",
                "ip-netmask",
                f"{base}.{octet_c}.{octet_d}/32",
                f"{prefix} application host {index + 1}",
                ["owner:payments"] if index % 4 == 0 else [],
            )
        )
    entries.append(
        (f"net-{prefix}", "ip-netmask", f"{base}.0.0/16", f"{prefix} network segment", [])
    )
    return entries


# ---------------------------------------------------------------------------
# Device groups and rules
# ---------------------------------------------------------------------------


def _add_device_group(
    container: etree._Element, name: str, parent: str | None, index: int, builder: _Builder
) -> None:
    entry = etree.SubElement(container, "entry", name=name)
    etree.SubElement(entry, "description").text = f"Device group {name}"
    if parent and not builder.options.hierarchy_in_readonly_only:
        etree.SubElement(entry, "parent-dg").text = parent

    prefix = name.replace("DG-", "").lower()
    _add_addresses(
        entry, _group_addresses(prefix, builder, builder.options.addresses_per_group, index)
    )
    _add_address_group(entry, f"grp-{prefix}-app", [f"{prefix}-host-01", f"{prefix}-host-02"])
    _add_address_group(entry, f"grp-{prefix}-nested", [f"grp-{prefix}-app", f"{prefix}-host-03"])

    if builder.options.include_dynamic_groups:
        _add_dynamic_group(entry, f"dag-{prefix}-owned", "'owner:payments'")

    if builder.options.include_broken_references and index == 1:
        # A group with a member that does not exist anywhere: exercises the
        # unresolved-object path, which real estates always have some of.
        _add_address_group(entry, f"grp-{prefix}-broken", [f"{prefix}-host-01", "edl-threat-feed"])

    devices_node = etree.SubElement(entry, "devices")
    etree.SubElement(devices_node, "entry", name=f"001901{index:06d}")

    for base in ("pre", "post"):
        rulebase = etree.SubElement(entry, f"{base}-rulebase")
        security = etree.SubElement(rulebase, "security")
        rules = etree.SubElement(security, "rules")
        count = builder.options.rules_per_group if base == "pre" else 2
        for rule_index in range(count):
            _add_rule(rules, f"{prefix}-{base}-{rule_index + 1:02d}", prefix, builder, rule_index)


def _add_shared_rules(shared: etree._Element, builder: _Builder) -> None:
    pre = etree.SubElement(shared, "pre-rulebase")
    security = etree.SubElement(pre, "security")
    rules = etree.SubElement(security, "rules")

    entry = etree.SubElement(rules, "entry", name="shared-allow-dns", uuid=_uuid(builder))
    _members(entry, "from", ["any"])
    _members(entry, "to", ["any"])
    _members(entry, "source", ["any"])
    _members(entry, "destination", ["grp-dns-servers"])
    _members(entry, "application", ["dns"])
    _members(entry, "service", ["svc-dns"])
    _members(entry, "category", ["any"])
    etree.SubElement(entry, "action").text = "allow"
    etree.SubElement(entry, "description").text = (
        "CHG0010001 permit DNS to central resolvers, requested by A. Example, "
        "created 04.02.2024"
    )
    _members(entry, "tag", ["owner:platform"])
    etree.SubElement(entry, "log-end").text = "yes"

    post = etree.SubElement(shared, "post-rulebase")
    security_post = etree.SubElement(post, "security")
    rules_post = etree.SubElement(security_post, "rules")
    deny = etree.SubElement(rules_post, "entry", name="shared-deny-all", uuid=_uuid(builder))
    _members(deny, "from", ["any"])
    _members(deny, "to", ["any"])
    _members(deny, "source", ["any"])
    _members(deny, "destination", ["any"])
    _members(deny, "application", ["any"])
    _members(deny, "service", ["any"])
    _members(deny, "category", ["any"])
    etree.SubElement(deny, "action").text = "deny"
    etree.SubElement(deny, "description").text = "Explicit catch-all deny"
    etree.SubElement(deny, "log-end").text = "yes"


# Rule shapes worth generating, each exercising a different reporting path.
_RULE_SHAPES = [
    "specific",       # named source and destination, named service
    "any_source",     # inbound from anywhere
    "any_dest",       # outbound to anywhere
    "any_any",        # the finding that matters most
    "group",          # via an address group
    "nested_group",   # via a nested group
    "no_service",     # application-only
    "expired",        # description carries a past expiry date
    "no_description", # nothing to trace it back to
    "disabled",       # inactive
    "dynamic",        # via a dynamic address group
]


def _add_rule(
    rules: etree._Element, name: str, prefix: str, builder: _Builder, index: int
) -> None:
    shape = _RULE_SHAPES[index % len(_RULE_SHAPES)]
    if shape == "expired" and not builder.options.include_expired_rules:
        shape = "specific"

    entry = etree.SubElement(rules, "entry", name=name, uuid=_uuid(builder))

    zones = ["trust", "untrust", "dmz", "internal"]
    from_zone = zones[index % len(zones)]
    to_zone = zones[(index + 1) % len(zones)]
    _members(entry, "from", [from_zone])
    _members(entry, "to", [to_zone])

    source, destination, service, application = _shape_fields(shape, prefix, builder)
    _members(entry, "source", source)
    _members(entry, "destination", destination)
    _members(entry, "source-user", ["any"])
    _members(entry, "application", application)
    _members(entry, "service", service)
    _members(entry, "category", ["any"])

    etree.SubElement(entry, "action").text = "allow"
    etree.SubElement(entry, "rule-type").text = "universal"

    description = _description(shape, builder, index)
    if description:
        etree.SubElement(entry, "description").text = description

    tags = _rule_tags(shape, index)
    if tags:
        _members(entry, "tag", tags)

    if shape == "disabled":
        etree.SubElement(entry, "disabled").text = "yes"

    etree.SubElement(entry, "log-start").text = "no"
    etree.SubElement(entry, "log-end").text = "no" if shape == "any_any" else "yes"

    profile = etree.SubElement(entry, "profile-setting")
    group = etree.SubElement(profile, "group")
    etree.SubElement(group, "member").text = "default-profiles"


def _shape_fields(shape: str, prefix: str, builder: _Builder):
    host_a = f"{prefix}-host-01"
    host_b = f"{prefix}-host-02"
    net = f"net-{prefix}"

    table = {
        "specific":       ([host_a], [host_b], ["svc-https"], ["ssl", "web-browsing"]),
        "any_source":     (["any"], [host_a], ["svc-https"], ["ssl"]),
        "any_dest":       ([net], ["any"], ["svc-https"], ["web-browsing"]),
        "any_any":        (["any"], ["any"], ["any"], ["any"]),
        "group":          ([f"grp-{prefix}-app"], ["grp-dns-servers"], ["svc-dns"], ["dns"]),
        "nested_group":   ([f"grp-{prefix}-nested"], [net], ["svc-grp-web"], ["any"]),
        "no_service":     ([host_a], [host_b], ["application-default"], ["ms-sql-db"]),
        "expired":        ([net], ["partner-range"], ["svc-ssh"], ["ssh"]),
        "no_description": ([host_b], ["net-internet-doc"], ["svc-http-alt"], ["any"]),
        "disabled":       ([host_a], ["update-service"], ["svc-https"], ["paloalto-updates"]),
        "dynamic":        ([f"dag-{prefix}-owned"], ["net-management"], ["svc-ssh"], ["ssh"]),
    }
    return table[shape]


def _description(shape: str, builder: _Builder, index: int) -> str:
    if shape == "no_description":
        return ""

    ticket = f"CHG{10000 + index * 7:07d}"
    created = builder.today - timedelta(days=200 + index * 13)
    requester = ["A. Example", "B. Sample", "C. Placeholder"][index % 3]

    if shape == "expired":
        expiry = builder.today - timedelta(days=45)
        return (
            f"{ticket} temporary partner access, requested by {requester}, "
            f"valid until {expiry.strftime('%d.%m.%Y')}"
        )
    if shape == "any_any":
        return f"{ticket} broad rule pending replacement, created {created.strftime('%d.%m.%Y')}"
    if index % 5 == 0:
        expiry = builder.today + timedelta(days=30)
        return (
            f"{ticket} project access, requested by {requester}, "
            f"expires {expiry.strftime('%d.%m.%Y')}"
        )
    if index % 4 == 0:
        return f"JIRA-{2000 + index} application access, created {created.strftime('%Y-%m-%d')}"
    return f"{ticket} standard access, requested by {requester}, created {created.strftime('%d.%m.%Y')}"


def _rule_tags(shape: str, index: int) -> list[str]:
    tags = []
    if index % 3 == 0:
        tags.append("owner:payments")
    elif index % 3 == 1:
        tags.append("owner:platform")
    if shape == "expired":
        tags.append("temporary")
    return tags


def _add_nat_rule(rules: etree._Element, name: str, builder: _Builder) -> None:
    entry = etree.SubElement(rules, "entry", name=name, uuid=_uuid(builder))
    _members(entry, "from", ["trust"])
    _members(entry, "to", ["untrust"])
    _members(entry, "source", ["net-edge"])
    _members(entry, "destination", ["any"])
    etree.SubElement(entry, "service").text = "any"
    source_translation = etree.SubElement(entry, "source-translation")
    dynamic = etree.SubElement(source_translation, "dynamic-ip-and-port")
    translated = etree.SubElement(dynamic, "translated-address")
    etree.SubElement(translated, "member").text = "partner-range"
    etree.SubElement(entry, "description").text = "CHG0010500 outbound NAT for edge segment"


def _add_readonly(
    config: etree._Element,
    names: list[str],
    parents: dict[str, str],
    options: GeneratorOptions,
) -> None:
    """Mirror the device-group hierarchy into the ``readonly`` block.

    Panorama keeps the parent links here rather than on the editable
    device-group nodes, and a fixture that omits it lets a parser look correct
    while never resolving inheritance -- which is exactly the bug this
    reproduces. ``hierarchy_in_readonly_only`` controls which of the two
    locations is populated, so both code paths stay covered.
    """
    if not options.include_readonly_hierarchy:
        return

    readonly = etree.SubElement(config, "readonly")
    devices = etree.SubElement(readonly, "devices")
    device = etree.SubElement(devices, "entry", name="localhost.localdomain")
    container = etree.SubElement(device, "device-group")

    for index, name in enumerate(names):
        entry = etree.SubElement(container, "entry", name=name)
        etree.SubElement(entry, "id").text = str(index + 2)
        if name in parents:
            etree.SubElement(entry, "parent-dg").text = parents[name]

    etree.SubElement(readonly, "max-internal-id").text = str(len(names) + 10)


def _add_template(device: etree._Element, builder: _Builder) -> None:
    templates = etree.SubElement(device, "template")
    entry = etree.SubElement(templates, "entry", name="TPL-Base")
    config = etree.SubElement(entry, "config")
    devices = etree.SubElement(config, "devices")
    device_entry = etree.SubElement(devices, "entry", name="localhost.localdomain")
    vsys_container = etree.SubElement(device_entry, "vsys")
    vsys = etree.SubElement(vsys_container, "entry", name="vsys1")
    _add_zones(vsys, ["trust", "untrust", "dmz", "internal"])


def _members(parent: etree._Element, tag: str, values: list[str]) -> None:
    container = etree.SubElement(parent, tag)
    for value in values:
        etree.SubElement(container, "member").text = value


def _uuid(builder: _Builder) -> str:
    hexdigits = "0123456789abcdef"
    parts = [8, 4, 4, 4, 12]
    return "-".join(
        "".join(builder.rng.choice(hexdigits) for _ in range(length)) for length in parts
    )
