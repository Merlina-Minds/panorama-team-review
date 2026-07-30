"""Object resolution: groups, ranges, dynamic filters and scope inheritance.

An error here silently changes what a report claims a rule permits, which is
the worst class of bug this tool can have.
"""

from __future__ import annotations

import pytest

from panorama_team_review.model import (
    AddressGroup,
    AddressKind,
    AddressObject,
    Location,
    ResolvedAddresses,
    ResolvedServices,
    ServiceGroup,
    ServiceObject,
    Snapshot,
    SnapshotMeta,
    UnresolvedReason,
)
from panorama_team_review.resolve.objects import (
    _range_to_networks,
    build_index,
    compile_tag_filter,
    resolve_addresses,
    resolve_services,
    resolve_snapshot,
)


def make_snapshot(**kwargs) -> Snapshot:
    from datetime import datetime

    meta = SnapshotMeta(source_file="test.xml", parsed_at=datetime(2026, 7, 28))
    return Snapshot(meta=meta, **kwargs)


def loc(scope: str = "shared", **kwargs) -> Location:
    if scope == "shared":
        return Location(source="test.xml", shared=True, **kwargs)
    return Location(source="test.xml", device_group=scope, **kwargs)


# ---------------------------------------------------------------------------
# Address objects
# ---------------------------------------------------------------------------


def test_resolves_simple_address_object():
    snap = make_snapshot(
        addresses=[
            AddressObject(name="web01", kind=AddressKind.IP_NETMASK,
                          value="10.1.1.5/32", location=loc())
        ]
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["web01"]), loc(), index)
    assert result.networks == ["10.1.1.5/32"]


def test_resolves_ip_range_to_minimal_cidrs():
    snap = make_snapshot(
        addresses=[
            AddressObject(name="pool", kind=AddressKind.IP_RANGE,
                          value="10.0.0.5-10.0.0.9", location=loc())
        ]
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["pool"]), loc(), index)
    # 5-9 is covered by 10.0.0.5/32, 10.0.0.6/31, 10.0.0.8/31
    assert result.networks == ["10.0.0.5/32", "10.0.0.6/31", "10.0.0.8/31"]


def test_fqdn_is_recorded_not_silently_dropped():
    """An FQDN cannot be resolved offline; hiding it would understate scope."""
    snap = make_snapshot(
        addresses=[
            AddressObject(name="updates", kind=AddressKind.FQDN,
                          value="updates.example.com", location=loc())
        ]
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["updates"]), loc(), index)
    assert result.fqdns == ["updates.example.com"]
    assert result.unresolved[0].reason is UnresolvedReason.FQDN


def test_unknown_object_is_flagged():
    index = build_index(make_snapshot())
    result = resolve_addresses(ResolvedAddresses(raw=["edl-threat-feed"]), loc(), index)
    assert result.networks == []
    assert result.unresolved[0].reason is UnresolvedReason.UNKNOWN_OBJECT
    assert result.unresolved[0].name == "edl-threat-feed"


def test_ip_wildcard_is_flagged_as_unresolvable():
    snap = make_snapshot(
        addresses=[
            AddressObject(name="wild", kind=AddressKind.IP_WILDCARD,
                          value="10.0.0.0/0.0.255.255", location=loc())  # allow-customer-data-check
        ]
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["wild"]), loc(), index)
    assert result.unresolved[0].reason is UnresolvedReason.WILDCARD


def test_literal_address_in_rule_field():
    """PAN-OS permits a bare address in some fields; it must still resolve."""
    index = build_index(make_snapshot())
    result = resolve_addresses(ResolvedAddresses(raw=["10.1.2.0/24"]), loc(), index)
    assert result.networks == ["10.1.2.0/24"]


def test_any_short_circuits():
    index = build_index(make_snapshot())
    result = resolve_addresses(ResolvedAddresses(is_any=True), loc(), index)
    assert result.is_any
    assert result.networks == []


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------


def test_static_group_flattens():
    snap = make_snapshot(
        addresses=[
            AddressObject(name="a", kind=AddressKind.IP_NETMASK, value="10.0.0.1/32", location=loc()),
            AddressObject(name="b", kind=AddressKind.IP_NETMASK, value="10.0.0.2/32", location=loc()),
        ],
        address_groups=[AddressGroup(name="grp", members=["a", "b"], location=loc())],
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["grp"]), loc(), index)
    assert result.networks == ["10.0.0.1/32", "10.0.0.2/32"]


def test_nested_groups_flatten():
    snap = make_snapshot(
        addresses=[
            AddressObject(name="a", kind=AddressKind.IP_NETMASK, value="10.0.0.1/32", location=loc()),
            AddressObject(name="b", kind=AddressKind.IP_NETMASK, value="10.0.0.2/32", location=loc()),
        ],
        address_groups=[
            AddressGroup(name="inner", members=["a"], location=loc()),
            AddressGroup(name="outer", members=["inner", "b"], location=loc()),
        ],
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["outer"]), loc(), index)
    assert result.networks == ["10.0.0.1/32", "10.0.0.2/32"]


def test_circular_group_does_not_hang():
    """Mutually referencing groups exist in real configurations."""
    snap = make_snapshot(
        addresses=[
            AddressObject(name="a", kind=AddressKind.IP_NETMASK, value="10.0.0.1/32", location=loc())
        ],
        address_groups=[
            AddressGroup(name="g1", members=["g2", "a"], location=loc()),
            AddressGroup(name="g2", members=["g1"], location=loc()),
        ],
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["g1"]), loc(), index)
    assert result.networks == ["10.0.0.1/32"]


def test_empty_group_resolves_to_nothing():
    snap = make_snapshot(address_groups=[AddressGroup(name="empty", location=loc())])
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["empty"]), loc(), index)
    assert result.networks == []
    assert result.unresolved == []


# ---------------------------------------------------------------------------
# Dynamic address groups
# ---------------------------------------------------------------------------


def test_dynamic_group_matches_tagged_objects():
    snap = make_snapshot(
        addresses=[
            AddressObject(name="a", kind=AddressKind.IP_NETMASK, value="10.0.0.1/32",
                          tags=["prod"], location=loc()),
            AddressObject(name="b", kind=AddressKind.IP_NETMASK, value="10.0.0.2/32",
                          tags=["dev"], location=loc()),
        ],
        address_groups=[
            AddressGroup(name="dag", dynamic_filter="'prod'", location=loc())
        ],
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["dag"]), loc(), index)
    assert result.networks == ["10.0.0.1/32"]


def test_dynamic_group_with_and_expression():
    snap = make_snapshot(
        addresses=[
            AddressObject(name="a", kind=AddressKind.IP_NETMASK, value="10.0.0.1/32",
                          tags=["prod", "web"], location=loc()),
            AddressObject(name="b", kind=AddressKind.IP_NETMASK, value="10.0.0.2/32",
                          tags=["prod"], location=loc()),
        ],
        address_groups=[
            AddressGroup(name="dag", dynamic_filter="'prod' and 'web'", location=loc())
        ],
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["dag"]), loc(), index)
    assert result.networks == ["10.0.0.1/32"]


@pytest.mark.parametrize(
    ("expression", "tags", "expected"),
    [
        ("'a'", {"a"}, True),
        ("'a'", {"b"}, False),
        ("'a' and 'b'", {"a", "b"}, True),
        ("'a' and 'b'", {"a"}, False),
        ("'a' or 'b'", {"b"}, True),
        ("'a' or 'b'", {"c"}, False),
        ("not 'a'", {"b"}, True),
        ("not 'a'", {"a"}, False),
        ("'a' and not 'b'", {"a"}, True),
        ("'a' and not 'b'", {"a", "b"}, False),
        ("('a' or 'b') and 'c'", {"a", "c"}, True),
        ("('a' or 'b') and 'c'", {"a"}, False),
        ("'a' or 'b' and 'c'", {"a"}, True),  # 'and' binds tighter than 'or'
        ("'a' or 'b' and 'c'", {"b"}, False),
        ('"quoted"', {"quoted"}, True),
        ("'tag with spaces'", {"tag with spaces"}, True),
    ],
)
def test_tag_filter_grammar(expression, tags, expected):
    predicate = compile_tag_filter(expression)
    assert predicate(tags) is expected


@pytest.mark.parametrize("expression", ["", "'a' and", "('a'", "and 'a'", "'a' 'b' )"])
def test_invalid_tag_filter_raises(expression):
    with pytest.raises(ValueError):
        compile_tag_filter(expression)


def test_unparsable_dynamic_filter_is_reported_not_raised():
    """A broken filter must degrade to a visible warning, not crash the run."""
    snap = make_snapshot(
        address_groups=[AddressGroup(name="dag", dynamic_filter="'a' and", location=loc())]
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["dag"]), loc(), index)
    assert result.unresolved[0].reason is UnresolvedReason.UNKNOWN_OBJECT
    assert "unparsable dynamic filter" in result.unresolved[0].detail


# ---------------------------------------------------------------------------
# Scope inheritance
# ---------------------------------------------------------------------------


def test_device_group_inherits_from_shared():
    snap = make_snapshot(
        addresses=[
            AddressObject(name="dns", kind=AddressKind.IP_NETMASK,
                          value="10.0.0.53/32", location=loc("shared"))
        ]
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["dns"]), loc("DG-Prod"), index)
    assert result.networks == ["10.0.0.53/32"]


def test_child_device_group_inherits_from_parent():
    from panorama_team_review.model import DeviceGroup

    snap = make_snapshot(
        device_groups={
            "Parent": DeviceGroup(name="Parent"),
            "Child": DeviceGroup(name="Child", parent="Parent"),
        },
        addresses=[
            AddressObject(name="shared-host", kind=AddressKind.IP_NETMASK,
                          value="10.9.9.9/32", location=loc("Parent"))
        ],
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["shared-host"]), loc("Child"), index)
    assert result.networks == ["10.9.9.9/32"]


def test_nearer_scope_shadows_parent():
    """PAN-OS resolves the nearest definition; the report must match."""
    from panorama_team_review.model import DeviceGroup

    snap = make_snapshot(
        device_groups={"Child": DeviceGroup(name="Child", parent=None)},
        addresses=[
            AddressObject(name="host", kind=AddressKind.IP_NETMASK,
                          value="10.0.0.1/32", location=loc("shared")),
            AddressObject(name="host", kind=AddressKind.IP_NETMASK,
                          value="10.0.0.2/32", location=loc("Child")),
        ],
    )
    index = build_index(snap)
    result = resolve_addresses(ResolvedAddresses(raw=["host"]), loc("Child"), index)
    assert result.networks == ["10.0.0.2/32"]


def test_scope_chain_always_ends_in_shared():
    from panorama_team_review.model import DeviceGroup

    snap = make_snapshot(
        device_groups={
            "Parent": DeviceGroup(name="Parent"),
            "Child": DeviceGroup(name="Child", parent="Parent"),
        }
    )
    index = build_index(snap)
    assert index.scope_chain(loc("Child")) == ["Child", "Parent", "shared"]


def test_scope_chain_survives_a_parent_cycle():
    from panorama_team_review.model import DeviceGroup

    snap = make_snapshot(
        device_groups={
            "A": DeviceGroup(name="A", parent="B"),
            "B": DeviceGroup(name="B", parent="A"),
        }
    )
    index = build_index(snap)
    chain = index.scope_chain(loc("A"))
    assert chain[-1] == "shared"
    assert len(chain) == 3


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


def test_service_object_resolves_to_proto_port():
    snap = make_snapshot(
        services=[ServiceObject(name="svc-https", protocol="tcp", port="443", location=loc())]
    )
    index = build_index(snap)
    result = resolve_services(ResolvedServices(raw=["svc-https"]), loc(), index)
    assert result.ports == ["tcp/443"]


def test_service_with_multiple_ports():
    snap = make_snapshot(
        services=[ServiceObject(name="svc", protocol="tcp", port="80,443,8080-8090", location=loc())]
    )
    index = build_index(snap)
    result = resolve_services(ResolvedServices(raw=["svc"]), loc(), index)
    assert result.ports == ["tcp/80", "tcp/443", "tcp/8080-8090"]


def test_service_group_flattens():
    snap = make_snapshot(
        services=[
            ServiceObject(name="a", protocol="tcp", port="443", location=loc()),
            ServiceObject(name="b", protocol="udp", port="53", location=loc()),
        ],
        service_groups=[ServiceGroup(name="grp", members=["a", "b"], location=loc())],
    )
    index = build_index(snap)
    result = resolve_services(ResolvedServices(raw=["grp"]), loc(), index)
    assert set(result.ports) == {"tcp/443", "udp/53"}


def test_predefined_services_are_known():
    """service-http and service-https have no definition in the config."""
    index = build_index(make_snapshot())
    result = resolve_services(ResolvedServices(raw=["service-https"]), loc(), index)
    assert result.ports == ["tcp/443"]


def test_unknown_service_is_flagged():
    index = build_index(make_snapshot())
    result = resolve_services(ResolvedServices(raw=["svc-nonexistent"]), loc(), index)
    assert result.unresolved[0].reason is UnresolvedReason.UNKNOWN_OBJECT


# ---------------------------------------------------------------------------
# Range conversion
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.0.0.0-10.0.0.255", ["10.0.0.0/24"]),
        ("10.0.0.1-10.0.0.1", ["10.0.0.1/32"]),
        ("10.0.0.0-10.0.1.255", ["10.0.0.0/23"]),
        ("10.0.0.5-10.0.0.4", []),          # reversed range
        ("not-an-address", []),
        ("10.0.0.1-2001:db8::1", []),       # mixed families
    ],
)
def test_range_conversion(value, expected):
    assert _range_to_networks(value) == expected


# ---------------------------------------------------------------------------
# Whole-snapshot resolution
# ---------------------------------------------------------------------------


def test_resolve_snapshot_populates_every_rule(panorama_snapshot):
    resolve_snapshot(panorama_snapshot)
    resolved = [
        rule for rule in panorama_snapshot.rules
        if rule.source.networks or rule.source.is_any
    ]
    assert len(resolved) == len(panorama_snapshot.rules)


def test_duplicate_object_names_produce_a_warning():
    snap = make_snapshot(
        addresses=[
            AddressObject(name="dup", kind=AddressKind.IP_NETMASK, value="10.0.0.1/32", location=loc()),
            AddressObject(name="dup", kind=AddressKind.IP_NETMASK, value="10.0.0.2/32", location=loc()),
        ]
    )
    index = build_index(snap)
    assert any("duplicate address object" in w for w in index.warnings)
