"""Shared PAN-OS XML reading helpers.

Firewall and Panorama configurations differ in *where* things live, not in what
they look like: an ``<address>`` container under a vsys and one under a device
group are structurally identical.  Everything that reads such a container lives
here, so ``panos.py`` only has to describe the two hierarchies.
"""

from __future__ import annotations

from lxml import etree

from ..model import (
    AddressGroup,
    AddressKind,
    AddressObject,
    ExternalList,
    Location,
    NatRule,
    ResolvedAddresses,
    ResolvedServices,
    RuleAction,
    Rulebase,
    SecurityRule,
    ServiceGroup,
    ServiceObject,
    Tag,
)


def text(elem: etree._Element | None, path: str, default: str = "") -> str:
    """Return the stripped text at ``path`` below ``elem``, or ``default``."""
    if elem is None:
        return default
    node = elem.find(path)
    if node is None or node.text is None:
        return default
    return node.text.strip()


def yes_no(elem: etree._Element | None, path: str, default: bool = False) -> bool:
    """PAN-OS booleans are the strings ``yes`` and ``no``."""
    raw = text(elem, path).lower()
    if raw in ("yes", "true"):
        return True
    if raw in ("no", "false"):
        return False
    return default


def members(elem: etree._Element | None, path: str) -> list[str]:
    """Read a ``<path><member>a</member><member>b</member></path>`` list."""
    if elem is None:
        return []
    container = elem.find(path)
    if container is None:
        return []
    return [m.text.strip() for m in container.findall("member") if m.text and m.text.strip()]


def entry_names(elem: etree._Element | None, path: str) -> list[str]:
    """Read the ``name`` attribute of every ``<entry>`` below ``path``."""
    if elem is None:
        return []
    container = elem.find(path)
    if container is None:
        return []
    return [e.get("name", "") for e in container.findall("entry") if e.get("name")]


def address_field(rule: etree._Element, field: str) -> ResolvedAddresses:
    """Build the unresolved shell of a source/destination field.

    Only the literal object names and the ``any`` / negate flags are known at
    parse time.  Flattening to networks needs the full object index and happens
    in ``resolve.objects``.
    """
    raw = members(rule, field)
    negate_tag = "negate-source" if field == "source" else "negate-destination"
    return ResolvedAddresses(
        raw=[r for r in raw if r.lower() != "any"],
        is_any=any(r.lower() == "any" for r in raw) or not raw,
        negated=yes_no(rule, negate_tag),
    )


def service_field(rule: etree._Element) -> ResolvedServices:
    raw = members(rule, "service")
    lowered = {r.lower() for r in raw}
    return ResolvedServices(
        raw=[r for r in raw if r.lower() not in ("any", "application-default")],
        is_any="any" in lowered or not raw,
        is_application_default="application-default" in lowered,
    )


# ---------------------------------------------------------------------------
# Object containers
# ---------------------------------------------------------------------------


def parse_addresses(scope: etree._Element, location: Location) -> list[AddressObject]:
    out: list[AddressObject] = []
    container = scope.find("address")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        kind, value = _address_value(entry)
        if kind is None:
            continue
        out.append(
            AddressObject(
                name=name,
                kind=kind,
                value=value,
                description=text(entry, "description"),
                tags=members(entry, "tag"),
                location=location,
            )
        )
    return out


def _address_value(entry: etree._Element) -> tuple[AddressKind | None, str]:
    for tag, kind in (
        ("ip-netmask", AddressKind.IP_NETMASK),
        ("ip-range", AddressKind.IP_RANGE),
        ("ip-wildcard", AddressKind.IP_WILDCARD),
        ("fqdn", AddressKind.FQDN),
    ):
        value = text(entry, tag)
        if value:
            return kind, value
    return None, ""


def parse_address_groups(scope: etree._Element, location: Location) -> list[AddressGroup]:
    out: list[AddressGroup] = []
    container = scope.find("address-group")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        dynamic_filter = text(entry, "dynamic/filter") or None
        out.append(
            AddressGroup(
                name=name,
                members=members(entry, "static"),
                dynamic_filter=dynamic_filter,
                description=text(entry, "description"),
                tags=members(entry, "tag"),
                location=location,
            )
        )
    return out


def parse_services(scope: etree._Element, location: Location) -> list[ServiceObject]:
    out: list[ServiceObject] = []
    container = scope.find("service")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        protocol: str = "other"
        port = source_port = ""
        for proto in ("tcp", "udp", "sctp"):
            node = entry.find(f"protocol/{proto}")
            if node is not None:
                protocol = proto
                port = text(node, "port")
                source_port = text(node, "source-port")
                break
        out.append(
            ServiceObject(
                name=name,
                protocol=protocol,  # type: ignore[arg-type]
                port=port,
                source_port=source_port,
                description=text(entry, "description"),
                tags=members(entry, "tag"),
                location=location,
            )
        )
    return out


def parse_service_groups(scope: etree._Element, location: Location) -> list[ServiceGroup]:
    out: list[ServiceGroup] = []
    container = scope.find("service-group")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        out.append(
            ServiceGroup(
                name=name,
                members=members(entry, "members"),
                tags=members(entry, "tag"),
                location=location,
            )
        )
    return out


def parse_tags(scope: etree._Element, location: Location) -> list[Tag]:
    out: list[Tag] = []
    container = scope.find("tag")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        out.append(
            Tag(
                name=name,
                color=text(entry, "color") or None,
                comments=text(entry, "comments"),
                location=location,
            )
        )
    return out


def parse_external_lists(scope: etree._Element, location: Location) -> list[ExternalList]:
    """Read ``<external-list>`` definitions.

    Only the metadata exists in a backup -- the addresses are fetched by the
    device from the URL at runtime. Recording the name is enough to report the
    reference honestly instead of as an unknown object.
    """
    out: list[ExternalList] = []
    container = scope.find("external-list")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        list_type = ""
        url = ""
        type_node = entry.find("type")
        if type_node is not None and len(type_node):
            list_type = etree.QName(type_node[0]).localname
            url = text(type_node[0], "url")
        out.append(
            ExternalList(
                name=name,
                list_type=list_type,
                url=url,
                description=text(entry, "description"),
                location=location,
            )
        )
    return out


def parse_zones(scope: etree._Element) -> dict[str, list[str]]:
    """Zone name -> member interfaces."""
    out: dict[str, list[str]] = {}
    container = scope.find("zone")
    if container is None:
        return out
    for entry in container.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        interfaces: list[str] = []
        for layer in ("layer3", "layer2", "virtual-wire", "tap"):
            interfaces.extend(members(entry, f"network/{layer}"))
        out[name] = interfaces
    return out


# ---------------------------------------------------------------------------
# Rulebases
# ---------------------------------------------------------------------------


def parse_security_rules(
    rulebase: etree._Element, location: Location, start_order: int = 0
) -> list[SecurityRule]:
    """Parse ``<security><rules>`` below ``rulebase``.

    Order is preserved and recorded: PAN-OS evaluates top to bottom, so a rule's
    position is part of its meaning and a report that reorders rules silently
    misleads its reader.
    """
    out: list[SecurityRule] = []
    rules = rulebase.find("security/rules")
    if rules is None:
        return out

    for index, entry in enumerate(rules.findall("entry"), start=start_order):
        name = entry.get("name")
        if not name:
            continue
        action_raw = text(entry, "action", "allow").lower()
        try:
            action = RuleAction(action_raw)
        except ValueError:
            action = RuleAction.DENY if action_raw != "allow" else RuleAction.ALLOW

        out.append(
            SecurityRule(
                name=name,
                uuid=entry.get("uuid"),
                location=location,
                order=index,
                disabled=yes_no(entry, "disabled"),
                action=action,
                rule_type=text(entry, "rule-type", "universal"),
                from_zones=members(entry, "from") or ["any"],
                to_zones=members(entry, "to") or ["any"],
                source=address_field(entry, "source"),
                destination=address_field(entry, "destination"),
                source_users=members(entry, "source-user") or ["any"],
                applications=members(entry, "application") or ["any"],
                services=service_field(entry),
                categories=members(entry, "category") or ["any"],
                description=text(entry, "description"),
                tags=members(entry, "tag"),
                group_tag=text(entry, "group-tag") or None,
                schedule=text(entry, "schedule") or None,
                log_start=yes_no(entry, "log-start"),
                log_end=yes_no(entry, "log-end", default=True),
                profile_group=next(iter(members(entry, "profile-setting/group")), None),
                target_devices=entry_names(entry, "target/devices"),
            )
        )
    return out


def parse_nat_rules(
    rulebase: etree._Element, location: Location, start_order: int = 0
) -> list[NatRule]:
    out: list[NatRule] = []
    rules = rulebase.find("nat/rules")
    if rules is None:
        return out

    for index, entry in enumerate(rules.findall("entry"), start=start_order):
        name = entry.get("name")
        if not name:
            continue

        translated_source = None
        for path in ("source-translation/dynamic-ip-and-port/translated-address",
                     "source-translation/dynamic-ip/translated-address",
                     "source-translation/static-ip/translated-address"):
            node = entry.find(path)
            if node is None:
                continue
            if node.text and node.text.strip():
                translated_source = ResolvedAddresses(raw=[node.text.strip()])
            else:
                names = [m.text.strip() for m in node.findall("member") if m.text]
                if names:
                    translated_source = ResolvedAddresses(raw=names)
            break

        dest_translation = text(entry, "destination-translation/translated-address")
        translated_destination = (
            ResolvedAddresses(raw=[dest_translation]) if dest_translation else None
        )

        out.append(
            NatRule(
                name=name,
                uuid=entry.get("uuid"),
                location=location,
                order=index,
                disabled=yes_no(entry, "disabled"),
                from_zones=members(entry, "from") or ["any"],
                to_zones=members(entry, "to") or ["any"],
                source=address_field(entry, "source"),
                destination=address_field(entry, "destination"),
                service=text(entry, "service", "any"),
                translated_source=translated_source,
                translated_destination=translated_destination,
                translated_port=text(entry, "destination-translation/translated-port") or None,
                description=text(entry, "description"),
                tags=members(entry, "tag"),
            )
        )
    return out


def rulebase_location(base: Location, kind: Rulebase) -> Location:
    return base.model_copy(update={"rulebase": kind})
