"""Derive a draft inventory from a configuration.

The inventory is the one input the firewall cannot supply: which network
belongs to which team. Writing it from scratch for an estate with thousands of
address objects is the step where adoption usually stalls.

Most of it, however, *is* derivable. A configuration already groups addresses
-- by device group, by zone, by tag -- and those groupings were created by
people who knew what belonged together. This module turns them into a starting
point.

What it cannot know is what the groups are *called* in the organisation and who
to send the report to. Those are left as explicit TODO markers rather than
guessed, because a plausible-looking wrong owner is worse than a blank.

The output is a draft. It is meant to be read, cut down and corrected.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Literal

from ..model import Snapshot
from ..resolve.objects import ObjectIndex, build_index

GroupBy = Literal["device-group", "zone", "tag", "usage"]

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class TeamDraft:
    """One candidate team, with the evidence that produced it."""

    suggested_id: str
    source: str = ""
    networks: list[str] = field(default_factory=list)
    rule_count: int = 0
    object_count: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def address_total(self) -> int:
        return sum(ipaddress.ip_network(n).num_addresses for n in self.networks)


@dataclass
class InventoryDraft:
    group_by: str
    teams: list[TeamDraft] = field(default_factory=list)
    uncovered_networks: list[tuple[str, int]] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def suggest_inventory(
    snapshot: Snapshot,
    group_by: GroupBy = "device-group",
    max_networks_per_team: int = 40,
    min_prefix_v4: int = 16,
) -> InventoryDraft:
    """Build a draft inventory by grouping the configuration's own addresses.

    ``min_prefix_v4`` bounds how far networks are rolled up: aggregating a set
    of /24s into a /8 would produce a tidy list that claims far more address
    space than the team owns, and every rule touching that space would then be
    attributed to them.
    """
    index = build_index(snapshot)
    draft = InventoryDraft(group_by=group_by)

    if group_by == "device-group":
        _by_device_group(snapshot, draft, max_networks_per_team, min_prefix_v4)
    elif group_by == "zone":
        _by_zone(snapshot, index, draft, max_networks_per_team, min_prefix_v4)
    elif group_by == "usage":
        _by_usage(snapshot, draft, max_networks_per_team, min_prefix_v4)
    else:
        _by_tag(snapshot, draft, max_networks_per_team, min_prefix_v4)

    _make_ids_unique(draft)
    _add_uncovered(snapshot, draft)
    draft.stats = {
        "candidate_teams": len(draft.teams),
        "networks_suggested": sum(len(t.networks) for t in draft.teams),
        "rules_total": len(snapshot.rules),
        "address_objects": len(snapshot.addresses),
    }
    return draft


# ---------------------------------------------------------------------------
# Grouping strategies
# ---------------------------------------------------------------------------


def _by_device_group(
    snapshot: Snapshot, draft: InventoryDraft, cap: int, min_prefix: int
) -> None:
    """Group by the device group an address object is defined in.

    The usual best signal: device groups are how an estate is already carved
    up, often along the same lines as team responsibility.
    """
    networks: dict[str, list[IPNetwork]] = defaultdict(list)
    objects: Counter[str] = Counter()

    for address in snapshot.addresses:
        scope = address.location.scope
        if scope == "shared":
            continue  # shared objects belong to everyone; see the notes below
        for net in _networks_of(address.value, address.kind.value):
            networks[scope].append(net)
        objects[scope] += 1

    rules = Counter(
        rule.location.device_group or rule.location.scope for rule in snapshot.rules
    )

    for scope in sorted(networks):
        nets = _aggregate(networks[scope], cap, min_prefix)
        draft.teams.append(
            TeamDraft(
                suggested_id=_slug(scope),
                source=f"device group {scope!r}",
                networks=[str(n) for n in nets],
                rule_count=rules.get(scope, 0),
                object_count=objects[scope],
                notes=_scope_notes(snapshot, scope),
            )
        )

    shared_count = sum(1 for a in snapshot.addresses if a.location.scope == "shared")
    if shared_count:
        draft.warnings.append(
            f"{shared_count} address objects are defined in 'shared' and were not "
            "assigned to any candidate. Shared objects are visible to every device "
            "group, so they cannot be attributed automatically -- decide per object."
        )


def _by_zone(
    snapshot: Snapshot, index: ObjectIndex, draft: InventoryDraft, cap: int, min_prefix: int
) -> None:
    """Group by the zones rules use.

    Weaker than device groups, but useful where zones are named after the
    systems behind them. A zone has no addresses of its own, so the networks
    are taken from the destination side of the rules that terminate in it --
    that is what "behind this zone" means.
    """
    networks: dict[str, list[IPNetwork]] = defaultdict(list)
    rules: Counter[str] = Counter()

    for rule in snapshot.rules:
        if rule.disabled:
            continue
        for zone in rule.to_zones:
            if zone == "any":
                continue
            rules[zone] += 1
            for cidr in rule.destination.networks:
                networks[zone].append(ipaddress.ip_network(cidr))

    for zone in sorted(networks):
        nets = _aggregate(networks[zone], cap, min_prefix)
        draft.teams.append(
            TeamDraft(
                suggested_id=_slug(zone),
                source=f"zone {zone!r}",
                networks=[str(n) for n in nets],
                rule_count=rules[zone],
                notes=[f"derived from the destinations of {rules[zone]} rules entering "
                       f"this zone; verify before use"],
            )
        )


def _by_usage(snapshot: Snapshot, draft: InventoryDraft, cap: int, min_prefix: int) -> None:
    """Group networks by which device group's rules actually use them.

    Necessary because most estates keep the bulk of their address objects in
    ``shared`` -- one real configuration has 82% of them there. Grouping by
    where an object is *defined* then attributes almost nothing, while the
    rules themselves make the association obvious: a network that only ever
    appears in one device group's rules almost certainly belongs to it.

    A network used by several device groups is left unassigned rather than
    given to the most frequent user. Shared infrastructure is exactly what
    looks like a tie here, and guessing an owner for it would put other teams'
    rules into someone's report.
    """
    usage: dict[str, Counter[str]] = defaultdict(Counter)

    for rule in snapshot.rules:
        scope = rule.location.device_group
        if not scope:
            continue
        for side in (rule.source, rule.destination):
            for cidr in side.networks:
                usage[cidr][scope] += 1

    exclusive: dict[str, list[IPNetwork]] = defaultdict(list)
    ambiguous = 0

    for cidr, users in usage.items():
        # A device group and its ancestors are one responsibility, not several.
        roots = {_root_of(snapshot, scope) for scope in users}
        if len(roots) == 1:
            exclusive[next(iter(roots))].append(ipaddress.ip_network(cidr))
        else:
            ambiguous += 1

    rules = Counter(
        _root_of(snapshot, rule.location.device_group)
        for rule in snapshot.rules
        if rule.location.device_group
    )

    for scope in sorted(exclusive):
        nets = _aggregate(exclusive[scope], cap, min_prefix)
        draft.teams.append(
            TeamDraft(
                suggested_id=_slug(scope),
                source=f"networks used only by device group {scope!r} (and its children)",
                networks=[str(n) for n in nets],
                rule_count=rules.get(scope, 0),
                notes=["derived from rule usage, not from where objects are defined"],
            )
        )

    if ambiguous:
        draft.warnings.append(
            f"{ambiguous} networks are used by rules in more than one device group and "
            "were left unassigned. That is usually shared infrastructure -- assign it "
            "deliberately, or to the team that operates it."
        )


def _root_of(snapshot: Snapshot, scope: str | None) -> str:
    """The top-most ancestor of a device group.

    Children of one device group normally sit under one responsibility, so
    rolling them up avoids splitting a team across DG-X, DG-X-PROD and
    DG-X-DEV.
    """
    if not scope:
        return "shared"
    seen: set[str] = set()
    current = scope
    while current not in seen:
        seen.add(current)
        group = snapshot.device_groups.get(current)
        if group is None or not group.parent:
            return current
        current = group.parent
    return scope


def _by_tag(snapshot: Snapshot, draft: InventoryDraft, cap: int, min_prefix: int) -> None:
    """Group by tags on address objects.

    The strongest signal when an estate tags consistently, and useless when it
    does not -- which the counts in the output make obvious either way.
    """
    networks: dict[str, list[IPNetwork]] = defaultdict(list)
    objects: Counter[str] = Counter()

    for address in snapshot.addresses:
        for tag in address.tags:
            for net in _networks_of(address.value, address.kind.value):
                networks[tag].append(net)
            objects[tag] += 1

    rule_tags = Counter(tag for rule in snapshot.rules for tag in rule.tags)

    for tag in sorted(networks):
        nets = _aggregate(networks[tag], cap, min_prefix)
        draft.teams.append(
            TeamDraft(
                suggested_id=_slug(tag),
                source=f"tag {tag!r}",
                networks=[str(n) for n in nets],
                rule_count=rule_tags.get(tag, 0),
                object_count=objects[tag],
                notes=[f"tag also appears on {rule_tags.get(tag, 0)} rules"],
            )
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _networks_of(value: str, kind: str) -> list[IPNetwork]:
    """Concrete networks for an address object, ignoring what cannot be one."""
    if kind in ("fqdn", "ip-wildcard"):
        return []
    if kind == "ip-range" and "-" in value:
        start, _, end = value.partition("-")
        try:
            return list(
                ipaddress.summarize_address_range(
                    ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())
                )
            )
        except (ValueError, TypeError):
            return []
    try:
        return [ipaddress.ip_network(value, strict=False)]
    except ValueError:
        return []


def _aggregate(networks: list[IPNetwork], cap: int, min_prefix: int) -> list[IPNetwork]:
    """Collapse a set of networks into a short, honest list.

    Collapsing is done first without widening -- adjacent networks merge only
    where they genuinely form a larger block. Only if the result is still too
    long to read are networks rolled up to a coarser prefix, and never past
    ``min_prefix``, because an over-wide asset silently claims rules that
    belong to someone else.
    """
    if not networks:
        return []

    # The two address families are collapsed separately: they are unrelated
    # spaces, and ipaddress refuses to mix them anyway.
    v4 = [n for n in networks if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in networks if isinstance(n, ipaddress.IPv6Network)]

    collapsed_v4 = list(ipaddress.collapse_addresses(v4))
    collapsed_v6 = list(ipaddress.collapse_addresses(v6))
    collapsed: list[IPNetwork] = [*collapsed_v4, *collapsed_v6]

    if len(collapsed) <= cap:
        return sorted(collapsed, key=_sort_key)

    for prefix in (24, 22, 20, 18, 16):
        if prefix < min_prefix:
            break
        widened = {
            net.supernet(new_prefix=prefix) if net.prefixlen > prefix else net
            for net in collapsed_v4
        }
        merged: list[IPNetwork] = [*ipaddress.collapse_addresses(widened), *collapsed_v6]
        if len(merged) <= cap:
            return sorted(merged, key=_sort_key)

    return sorted(collapsed, key=_sort_key)[:cap]


def _sort_key(net: IPNetwork) -> tuple[int, int, int]:
    return (net.version, int(net.network_address), net.prefixlen)


def _scope_notes(snapshot: Snapshot, scope: str) -> list[str]:
    notes = []
    group = snapshot.device_groups.get(scope)
    if group and group.parent:
        notes.append(f"child of device group {group.parent!r}")
    if group and group.devices:
        notes.append(f"{len(group.devices)} firewall(s) assigned")
    return notes


def _add_uncovered(snapshot: Snapshot, draft: InventoryDraft) -> None:
    """Networks that rules use but no candidate claims.

    This is the list that tells an operator what the draft is missing, which
    matters more than the part it got right.
    """
    claimed = [
        ipaddress.ip_network(cidr)
        for team in draft.teams
        for cidr in team.networks
    ]
    usage: Counter[str] = Counter()

    for rule in snapshot.rules:
        for side in (rule.source, rule.destination):
            for cidr in side.networks:
                net = ipaddress.ip_network(cidr)
                if _is_covered(net, claimed):
                    continue
                # Report at /24 granularity so the list stays readable.
                rollup = net.supernet(new_prefix=24) if net.version == 4 and net.prefixlen > 24 else net
                usage[str(rollup)] += 1

    draft.uncovered_networks = usage.most_common(30)


def _slug(value: str) -> str:
    cleaned = "".join(c.lower() if c.isalnum() else "-" for c in value)
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-") or "team"


def _make_ids_unique(draft: InventoryDraft) -> None:
    """Ensure no two candidates share an id.

    Slugging is lossy -- ``VPN``, ``vpn`` and ``VPN-1`` all reduce to ``vpn`` --
    and duplicate ids make the file fail to load, which turns a helpful draft
    into a puzzle the user has to debug before it is worth anything. The
    original name goes into the comment above each entry either way, so the
    numeric suffix costs nothing in readability.
    """
    seen: Counter[str] = Counter()
    for team in draft.teams:
        base = team.suggested_id
        seen[base] += 1
        if seen[base] > 1:
            team.suggested_id = f"{base}-{seen[base]}"


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_yaml(draft: InventoryDraft, source: str) -> str:
    """Render the draft as a commented inventory file.

    Written by hand rather than through a YAML dumper because the comments are
    the point: every entry needs to say where it came from and how far it can
    be trusted, and a dumper would strip exactly that.
    """
    lines: list[str] = [
        "# Draft inventory -- REVIEW BEFORE USE",
        "#",
        f"# Generated from: {source}",
        f"# Grouped by:     {draft.group_by}",
        "#",
        "# This is a starting point derived from how the configuration already",
        "# groups its address objects. It is NOT a finished inventory:",
        "#",
        "#   * Team ids and names come from the configuration, not from your",
        "#     organisation. Rename them to what people actually call themselves.",
        "#   * Contacts cannot be derived at all. Fill them in or the reports have",
        "#     nowhere to go.",
        "#   * Networks are aggregated. Check that each team really owns the whole",
        "#     range -- an over-wide entry silently claims other teams' rules.",
        "#   * Delete candidates that are not teams. Infrastructure groupings often",
        "#     show up here and do not belong in an owner report.",
        "#",
        f"# {draft.stats.get('candidate_teams', 0)} candidates covering "
        f"{draft.stats.get('networks_suggested', 0)} networks, from "
        f"{draft.stats.get('address_objects', 0)} address objects.",
    ]

    for warning in draft.warnings:
        lines.append("#")
        for chunk in _wrap(warning, 74):
            lines.append(f"# NOTE: {chunk}" if chunk == _wrap(warning, 74)[0] else f"#       {chunk}")

    lines.append("")
    lines.append("teams:")

    for team in draft.teams:
        lines.append("")
        lines.append(f"  # from {team.source}")
        parts = [f"{team.rule_count} rule{'' if team.rule_count == 1 else 's'}"]
        if team.object_count:
            parts.append(f"{team.object_count} address objects")
        if team.networks:
            parts.append(f"{team.address_total:,} addresses".replace(",", " "))
        lines.append("  # " + ", ".join(parts))
        for note in team.notes:
            lines.append(f"  # {note}")

        lines.append(f"  - id: {team.suggested_id}")
        lines.append(f"    name: TODO  # was: {team.source}")
        lines.append("    contact: TODO")

        if team.networks:
            lines.append("    assets:")
            for cidr in team.networks:
                lines.append(f"      - {cidr}")
        else:
            lines.append("    assets: []  # nothing derivable; add manually")

    if draft.uncovered_networks:
        lines.append("")
        lines.append("# ---------------------------------------------------------------------")
        lines.append("# Networks used by rules that no candidate above claims.")
        lines.append("# Read this list: it is what the draft is missing, which matters more")
        lines.append("# than the part it got right. Counts are rule references.")
        lines.append("#")
        for cidr, count in draft.uncovered_networks:
            lines.append(f"#   {cidr:<22} {count} rule reference(s)")

    lines.append("")
    return "\n".join(lines)


def _is_covered(network: IPNetwork, claimed: list[IPNetwork]) -> bool:
    """Whether ``network`` lies inside any of the claimed networks.

    Compared as integer ranges rather than with ``subnet_of``: that method
    rejects a mixed-family argument outright, so using it here would mean
    either narrowing both operands to the same concrete type at every call, or
    catching the exception. The range test says the same thing plainly.
    """
    start = int(network.network_address)
    end = int(network.broadcast_address)

    for candidate in claimed:
        if network.version != candidate.version:
            continue
        if int(candidate.network_address) <= start and end <= int(candidate.broadcast_address):
            return True
    return False


def compare_strategies(snapshot: Snapshot, **kwargs) -> list[dict]:
    """Run every grouping strategy and report how well each fits this estate.

    Which one works depends entirely on how the estate was built, and that is
    not knowable in advance: an estate that tags rigorously gets a good answer
    from ``tag`` and a useless one from ``device-group``; an estate that keeps
    everything in ``shared`` is the other way round. Rather than pick badly on
    the user's behalf, run all four and show the numbers that reveal the fit.

    The telling number is coverage -- how much of what the rules actually use
    ends up attributed. Candidate count matters too, in both directions: two
    candidates for a large estate means almost everything was ambiguous, and
    two hundred means the grouping is not about ownership at all.
    """
    rule_networks: set[str] = set()
    for rule in snapshot.rules:
        rule_networks.update(rule.source.networks)
        rule_networks.update(rule.destination.networks)

    strategies: list[GroupBy] = ["device-group", "usage", "zone", "tag"]
    results = []
    for strategy in strategies:
        draft = suggest_inventory(snapshot, group_by=strategy, **kwargs)
        claimed = [ipaddress.ip_network(c) for t in draft.teams for c in t.networks]
        covered = sum(
            1 for cidr in rule_networks if _is_covered(ipaddress.ip_network(cidr), claimed)
        )
        results.append(
            {
                "strategy": strategy,
                "candidates": len(draft.teams),
                "networks": sum(len(t.networks) for t in draft.teams),
                "coverage_percent": round(100 * covered / len(rule_networks))
                if rule_networks
                else 0,
                "warnings": len(draft.warnings),
            }
        )
    return results


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines
