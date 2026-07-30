"""Flatten rule address and service fields into concrete networks and ports.

Three things make this non-trivial and all three matter for report accuracy:

1. **Scope inheritance.**  A rule in device group ``Child`` may reference an
   object defined in ``Parent`` or in ``shared``.  Lookups walk that chain,
   nearest scope first, exactly as PAN-OS does.
2. **Dynamic address groups.**  Their membership is a tag expression, not a
   list.  Evaluating it offline is what lets the report show real addresses
   instead of a group name.
3. **Honest failure.**  External dynamic lists, regions and FQDNs cannot be
   resolved from a backup.  They are recorded as ``Unresolved`` rather than
   dropped, because a silently omitted EDL understates exposure.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from ..model import (
    AddressGroup,
    AddressKind,
    AddressMember,
    AddressObject,
    ExternalList,
    Location,
    NamedObject,
    NatRule,
    ResolvedAddresses,
    ResolvedServices,
    SecurityRule,
    ServiceGroup,
    ServiceObject,
    Snapshot,
    Unresolved,
    UnresolvedReason,
)

MAX_GROUP_DEPTH = 32
SHARED = "shared"

# PAN-OS predefined services that have no object definition in the config.
PREDEFINED_SERVICES = {
    "service-http": ["tcp/80", "tcp/8080"],
    "service-https": ["tcp/443"],
}


@dataclass(slots=True)
class ObjectIndex:
    """Name lookup for every object kind, keyed by (scope, name).

    Scope is the device group name, the vsys name, or ``shared``.
    """

    addresses: dict[tuple[str, str], AddressObject] = field(default_factory=dict)
    address_groups: dict[tuple[str, str], AddressGroup] = field(default_factory=dict)
    services: dict[tuple[str, str], ServiceObject] = field(default_factory=dict)
    service_groups: dict[tuple[str, str], ServiceGroup] = field(default_factory=dict)
    external_lists: dict[tuple[str, str], ExternalList] = field(default_factory=dict)
    dg_parents: dict[str, str | None] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def scope_chain(self, location: Location) -> list[str]:
        """Scopes to search for a rule at ``location``, nearest first.

        Always ends in ``shared``, which is the estate-wide fallback scope in
        both firewall and Panorama configurations.
        """
        chain: list[str] = []

        if location.device_group:
            current: str | None = location.device_group
            seen: set[str] = set()
            while current and current not in seen:
                seen.add(current)
                chain.append(current)
                current = self.dg_parents.get(current)
            chain.append(SHARED)
            return chain

        # A firewall-local rule sees, in order: its own vsys, its own shared
        # scope, and finally the Panorama shared scope -- objects pushed from
        # Panorama are visible to every device. Both device-local scopes carry
        # the device qualifier so they cannot collide across firewalls.
        if location.device:
            if location.vsys:
                chain.append(f"{location.device}:{location.vsys}")
            chain.append(f"{location.device}:shared")
        elif location.vsys:
            chain.append(location.vsys)

        chain.append(SHARED)
        return chain

    def find_address(self, name: str, chain: list[str]) -> AddressObject | None:
        for scope in chain:
            obj = self.addresses.get((scope, name))
            if obj is not None:
                return obj
        return None

    def find_address_group(self, name: str, chain: list[str]) -> AddressGroup | None:
        for scope in chain:
            obj = self.address_groups.get((scope, name))
            if obj is not None:
                return obj
        return None

    def find_service(self, name: str, chain: list[str]) -> ServiceObject | None:
        for scope in chain:
            obj = self.services.get((scope, name))
            if obj is not None:
                return obj
        return None

    def find_service_group(self, name: str, chain: list[str]) -> ServiceGroup | None:
        for scope in chain:
            obj = self.service_groups.get((scope, name))
            if obj is not None:
                return obj
        return None

    def find_external_list(self, name: str, chain: list[str]) -> ExternalList | None:
        for scope in chain:
            obj = self.external_lists.get((scope, name))
            if obj is not None:
                return obj
        return None

    def addresses_in_scopes(self, chain: list[str]) -> list[AddressObject]:
        """Every address object visible from ``chain``, for dynamic group evaluation."""
        out: list[AddressObject] = []
        scopes = set(chain)
        for (scope, _), obj in self.addresses.items():
            if scope in scopes:
                out.append(obj)
        return out


def resolve_named_objects(snapshot: Snapshot, index: ObjectIndex) -> list[NamedObject]:
    """Resolve every address object and group in the configuration, once.

    Reports need this to answer the question an owner asks the moment they
    want a rule changed: *what is my network called in the firewall?* A change
    request has to cite an object name, and the names are not derivable from
    an address -- they are a naming convention the team never sees.

    Resolved once for the whole estate rather than per team: an object's
    expansion does not depend on who is reading it, and on a large
    configuration this is thousands of group expansions.
    """
    out: list[NamedObject] = []

    for kind, objects in (
        ("object", snapshot.addresses),
        ("group", snapshot.address_groups),
    ):
        for obj in objects:
            field_value = ResolvedAddresses(raw=[obj.name])
            resolved = resolve_addresses(field_value, obj.location, index)
            if not resolved.networks and not resolved.fqdns:
                continue
            out.append(
                NamedObject(
                    name=obj.name,
                    kind=kind,  # type: ignore[arg-type]
                    scope=obj.location.scope,
                    description=obj.description,
                    tags=list(obj.tags),
                    networks=resolved.networks,
                    fqdns=resolved.fqdns,
                )
            )

    out.sort(key=lambda item: (item.name.lower(), item.scope))
    return out


def build_index(snapshot: Snapshot) -> ObjectIndex:
    """Index a snapshot's objects by scope and name."""
    index = ObjectIndex()

    for name, group in snapshot.device_groups.items():
        index.dg_parents[name] = group.parent

    def fill(target: dict[tuple[str, str], Any], objects: Sequence[Any], kind: str) -> None:
        """Index one object kind, warning on a duplicate rather than overwriting.

        PAN-OS itself forbids two objects of the same kind and name in one
        scope, so a duplicate here means the backup is inconsistent. Keeping
        the first definition matches how the device resolved it.
        """
        for obj in objects:
            key = (obj.location.scope, obj.name)
            if key in target:
                index.warnings.append(
                    f"duplicate {kind} {obj.name!r} in scope {obj.location.scope!r}; "
                    "keeping the first definition"
                )
                continue
            target[key] = obj

    fill(index.addresses, snapshot.addresses, "address object")
    fill(index.address_groups, snapshot.address_groups, "address group")
    fill(index.services, snapshot.services, "service object")
    fill(index.service_groups, snapshot.service_groups, "service group")
    fill(index.external_lists, snapshot.external_lists, "external dynamic list")

    return index


# ---------------------------------------------------------------------------
# Address resolution
# ---------------------------------------------------------------------------


def resolve_addresses(
    field_value: ResolvedAddresses, location: Location, index: ObjectIndex
) -> ResolvedAddresses:
    """Flatten a source/destination field into networks, FQDNs and failures."""
    if field_value.is_any and not field_value.raw:
        return field_value

    chain = index.scope_chain(location)
    networks: set[str] = set()
    fqdns: set[str] = set()
    unresolved: list[Unresolved] = []
    members: list[AddressMember] = []

    for name in field_value.raw:
        # `visited` is per object rather than per field. Sharing it across the
        # field -- which is what the union alone needs -- would leave the
        # second group referencing a shared member empty, and a report would
        # then show that group as resolving to nothing.
        own_networks: set[str] = set()
        own_fqdns: set[str] = set()
        own_unresolved: list[Unresolved] = []
        _resolve_address_name(
            name, chain, index, own_networks, own_fqdns, own_unresolved, set(), depth=0
        )
        networks |= own_networks
        fqdns |= own_fqdns
        unresolved.extend(own_unresolved)
        members.append(
            AddressMember(
                name=name,
                networks=sorted(own_networks, key=_network_sort_key),
                fqdns=sorted(own_fqdns),
                unresolved=_dedupe_unresolved(own_unresolved),
            )
        )

    return field_value.model_copy(
        update={
            "networks": sorted(networks, key=_network_sort_key),
            "fqdns": sorted(fqdns),
            "unresolved": _dedupe_unresolved(unresolved),
            "members": members,
        }
    )


def _resolve_address_name(
    name: str,
    chain: list[str],
    index: ObjectIndex,
    networks: set[str],
    fqdns: set[str],
    unresolved: list[Unresolved],
    visited: set[str],
    depth: int,
) -> None:
    if depth > MAX_GROUP_DEPTH:
        unresolved.append(
            Unresolved(name=name, reason=UnresolvedReason.DEPTH_LIMIT,
                       detail=f"nesting deeper than {MAX_GROUP_DEPTH} levels")
        )
        return
    if name in visited:
        # Re-visiting a name inside one field is normal for overlapping groups;
        # only flag it when it is an actual cycle, detected below via the group
        # path.  Here we simply stop to avoid duplicated work.
        return
    visited.add(name)

    # A literal address is legal in some rule fields and in NAT translations.
    literal = _parse_literal(name)
    if literal is not None:
        networks.add(literal)
        return

    obj = index.find_address(name, chain)
    if obj is not None:
        _expand_address_object(obj, networks, fqdns, unresolved)
        return

    group = index.find_address_group(name, chain)
    if group is not None:
        _expand_address_group(group, chain, index, networks, fqdns, unresolved, visited, depth)
        return

    # An external dynamic list is defined in the configuration but its contents
    # are fetched by the device at runtime. Saying so is very different from
    # "unknown object", which reads like a misconfiguration.
    edl = index.find_external_list(name, chain)
    if edl is not None:
        unresolved.append(
            Unresolved(
                name=name,
                reason=UnresolvedReason.EXTERNAL_DYNAMIC_LIST,
                detail=f"external dynamic list ({edl.list_type or 'unknown type'}); "
                "its contents are fetched by the device and are not in the backup",
            )
        )
        return

    if _looks_like_region(name):
        unresolved.append(
            Unresolved(
                name=name,
                reason=UnresolvedReason.REGION,
                detail="built-in region; the address ranges are supplied by PAN-OS and are "
                "not part of the configuration",
            )
        )
        return

    unresolved.append(
        Unresolved(
            name=name,
            reason=UnresolvedReason.UNKNOWN_OBJECT,
            detail="not defined in this scope or any parent; either a predefined object or a "
            "reference to something removed from the configuration",
        )
    )


# ISO 3166-1 alpha-2 country codes are how PAN-OS names its built-in regions,
# and they carry no definition in the configuration. Two uppercase letters is
# the whole convention; a custom region object would be found by name above,
# so this only ever fires on the built-ins.
_REGION_RE = re.compile(r"^[A-Z]{2}$")


def _looks_like_region(name: str) -> bool:
    return bool(_REGION_RE.match(name))


def _expand_address_object(
    obj: AddressObject, networks: set[str], fqdns: set[str], unresolved: list[Unresolved]
) -> None:
    if obj.kind is AddressKind.FQDN:
        fqdns.add(obj.value)
        unresolved.append(
            Unresolved(name=obj.name, reason=UnresolvedReason.FQDN, detail=obj.value)
        )
        return
    if obj.kind is AddressKind.IP_WILDCARD:
        unresolved.append(
            Unresolved(name=obj.name, reason=UnresolvedReason.WILDCARD, detail=obj.value)
        )
        return
    if obj.kind is AddressKind.IP_RANGE:
        for net in _range_to_networks(obj.value):
            networks.add(net)
        return

    literal = _parse_literal(obj.value)
    if literal is not None:
        networks.add(literal)
    else:
        unresolved.append(
            Unresolved(
                name=obj.name,
                reason=UnresolvedReason.UNKNOWN_OBJECT,
                detail=f"unparsable value {obj.value!r}",
            )
        )


def _expand_address_group(
    group: AddressGroup,
    chain: list[str],
    index: ObjectIndex,
    networks: set[str],
    fqdns: set[str],
    unresolved: list[Unresolved],
    visited: set[str],
    depth: int,
) -> None:
    if group.is_dynamic:
        assert group.dynamic_filter is not None
        try:
            predicate = compile_tag_filter(group.dynamic_filter)
        except ValueError as exc:
            unresolved.append(
                Unresolved(
                    name=group.name,
                    reason=UnresolvedReason.UNKNOWN_OBJECT,
                    detail=f"unparsable dynamic filter {group.dynamic_filter!r}: {exc}",
                )
            )
            return
        for candidate in index.addresses_in_scopes(chain):
            if predicate(set(candidate.tags)):
                _expand_address_object(candidate, networks, fqdns, unresolved)
        return

    for member in group.members:
        _resolve_address_name(
            member, chain, index, networks, fqdns, unresolved, visited, depth + 1
        )


def _parse_literal(value: str) -> str | None:
    """Parse ``10.0.0.0/8``, ``10.0.0.1`` or an IPv6 form into canonical CIDR."""
    value = value.strip()
    if not value:
        return None
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def _range_to_networks(value: str) -> list[str]:
    """Convert ``10.0.0.5-10.0.0.9`` into the minimal set of covering CIDRs."""
    if "-" not in value:
        literal = _parse_literal(value)
        return [literal] if literal else []
    start_raw, _, end_raw = value.partition("-")
    try:
        start = ipaddress.ip_address(start_raw.strip())
        end = ipaddress.ip_address(end_raw.strip())
    except ValueError:
        return []
    if start.version != end.version or int(end) < int(start):
        return []
    return [str(net) for net in ipaddress.summarize_address_range(start, end)]


def _network_sort_key(cidr: str) -> tuple[int, int, int]:
    net = ipaddress.ip_network(cidr)
    return (net.version, int(net.network_address), net.prefixlen)


def _dedupe_unresolved(items: list[Unresolved]) -> list[Unresolved]:
    seen: set[tuple[str, str]] = set()
    out: list[Unresolved] = []
    for item in items:
        key = (item.name, item.reason.value)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# Dynamic address group tag filters
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<lparen>\()
      | (?P<rparen>\))
      | (?P<and>\band\b)
      | (?P<or>\bor\b)
      | (?P<not>\bnot\b)
      | '(?P<quoted>[^']*)'
      | "(?P<dquoted>[^"]*)"
      | (?P<bare>[^\s()'"]+)
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def compile_tag_filter(expression: str):
    """Compile a dynamic address group filter into a predicate over a tag set.

    Supports the PAN-OS grammar ``'tag' and ('other' or not 'third')``.  Returns
    a callable taking the set of an address object's tags.
    """
    tokens = _tokenise(expression)
    if not tokens:
        raise ValueError("empty filter expression")
    position = 0

    def peek() -> tuple[str, str] | None:
        return tokens[position] if position < len(tokens) else None

    def consume() -> tuple[str, str]:
        nonlocal position
        token = tokens[position]
        position += 1
        return token

    def parse_or():
        node = parse_and()
        while (token := peek()) and token[0] == "or":
            consume()
            right = parse_and()
            left = node
            node = lambda tags, a=left, b=right: a(tags) or b(tags)  # noqa: E731
        return node

    def parse_and():
        node = parse_not()
        while (token := peek()) and token[0] == "and":
            consume()
            right = parse_not()
            left = node
            node = lambda tags, a=left, b=right: a(tags) and b(tags)  # noqa: E731
        return node

    def parse_not():
        token = peek()
        if token and token[0] == "not":
            consume()
            inner = parse_not()
            return lambda tags, a=inner: not a(tags)
        return parse_atom()

    def parse_atom():
        token = peek()
        if token is None:
            raise ValueError("unexpected end of expression")
        kind, value = consume()
        if kind == "lparen":
            node = parse_or()
            closing = peek()
            if closing is None or closing[0] != "rparen":
                raise ValueError("unbalanced parenthesis")
            consume()
            return node
        if kind == "tag":
            return lambda tags, t=value: t in tags
        raise ValueError(f"unexpected token {value!r}")

    tree = parse_or()
    if position != len(tokens):
        raise ValueError(f"trailing input at token {position}")
    return tree


def _tokenise(expression: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(expression):
        match = _TOKEN_RE.match(expression, position)
        if not match or match.end() == position:
            if expression[position].isspace():
                position += 1
                continue
            raise ValueError(f"unexpected character {expression[position]!r} at offset {position}")
        position = match.end()
        groups = match.groupdict()
        if groups["lparen"]:
            tokens.append(("lparen", "("))
        elif groups["rparen"]:
            tokens.append(("rparen", ")"))
        elif groups["and"]:
            tokens.append(("and", "and"))
        elif groups["or"]:
            tokens.append(("or", "or"))
        elif groups["not"]:
            tokens.append(("not", "not"))
        elif groups["quoted"] is not None:
            tokens.append(("tag", groups["quoted"]))
        elif groups["dquoted"] is not None:
            tokens.append(("tag", groups["dquoted"]))
        elif groups["bare"]:
            tokens.append(("tag", groups["bare"]))
    return tokens


# ---------------------------------------------------------------------------
# Service resolution
# ---------------------------------------------------------------------------


def resolve_services(
    field_value: ResolvedServices, location: Location, index: ObjectIndex
) -> ResolvedServices:
    if field_value.is_any and not field_value.raw:
        return field_value

    chain = index.scope_chain(location)
    ports: set[str] = set()
    unresolved: list[Unresolved] = []
    visited: set[str] = set()

    for name in field_value.raw:
        _resolve_service_name(name, chain, index, ports, unresolved, visited, depth=0)

    return field_value.model_copy(
        update={"ports": sorted(ports, key=_port_sort_key), "unresolved": _dedupe_unresolved(unresolved)}
    )


def _resolve_service_name(
    name: str,
    chain: list[str],
    index: ObjectIndex,
    ports: set[str],
    unresolved: list[Unresolved],
    visited: set[str],
    depth: int,
) -> None:
    if depth > MAX_GROUP_DEPTH or name in visited:
        return
    visited.add(name)

    if name in PREDEFINED_SERVICES:
        ports.update(PREDEFINED_SERVICES[name])
        return

    obj = index.find_service(name, chain)
    if obj is not None:
        for port in _expand_port_spec(obj.port):
            ports.add(f"{obj.protocol}/{port}")
        if not obj.port:
            ports.add(f"{obj.protocol}/any")
        return

    group = index.find_service_group(name, chain)
    if group is not None:
        for member in group.members:
            _resolve_service_name(member, chain, index, ports, unresolved, visited, depth + 1)
        return

    unresolved.append(
        Unresolved(
            name=name,
            reason=UnresolvedReason.UNKNOWN_OBJECT,
            detail="service object not defined in this scope or any parent",
        )
    )


def _expand_port_spec(spec: str) -> list[str]:
    """Split ``80,443,8000-8100`` into individual port entries, ranges kept intact."""
    if not spec:
        return []
    return [part.strip() for part in spec.split(",") if part.strip()]


def _port_sort_key(entry: str) -> tuple[str, int, str]:
    proto, _, port = entry.partition("/")
    first = port.split("-")[0]
    return (proto, int(first) if first.isdigit() else 1 << 20, port)


# ---------------------------------------------------------------------------
# Whole-snapshot resolution
# ---------------------------------------------------------------------------


def resolve_snapshot(snapshot: Snapshot) -> ObjectIndex:
    """Resolve every rule in place and return the index used to do it."""
    index = build_index(snapshot)

    for rule in snapshot.rules:
        _resolve_security_rule(rule, index)
    for nat in snapshot.nat_rules:
        _resolve_nat_rule(nat, index)

    snapshot.parse_warnings.extend(index.warnings)
    return index


def _resolve_security_rule(rule: SecurityRule, index: ObjectIndex) -> None:
    rule.source = resolve_addresses(rule.source, rule.location, index)
    rule.destination = resolve_addresses(rule.destination, rule.location, index)
    rule.services = resolve_services(rule.services, rule.location, index)


def _resolve_nat_rule(nat: NatRule, index: ObjectIndex) -> None:
    nat.source = resolve_addresses(nat.source, nat.location, index)
    nat.destination = resolve_addresses(nat.destination, nat.location, index)
    if nat.translated_source is not None:
        nat.translated_source = resolve_addresses(nat.translated_source, nat.location, index)
    if nat.translated_destination is not None:
        nat.translated_destination = resolve_addresses(
            nat.translated_destination, nat.location, index
        )
