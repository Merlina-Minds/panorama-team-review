"""Derive teams from naming conventions instead of listing them by hand.

Estates that provision networks automatically end up with object names that
already encode ownership -- an address group called ``aws-acme-shop-p-01``
names the account it belongs to, and it does so reliably, because a machine
generated it.

Maintaining a parallel inventory of those by hand guarantees drift: a new
account appears in the firewall the day it is created and in the inventory
whenever somebody remembers. Reading the convention directly removes that gap.
A new account shows up in the next report with no configuration change at all.

What this does *not* replace is the hand-written inventory. Derived teams cover
the regular, generated part of an estate; infrastructure, overarching teams and
anything that predates the convention still need explicit entries. Both sources
are merged, and an explicit entry always wins over a derived one -- the human
who wrote it knew something the pattern does not.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field

from ..config import DerivedTeamRule, OwnershipConfig
from ..model import Snapshot, Team
from .objects import ObjectIndex, resolve_addresses
from .objects import ResolvedAddresses as _ResolvedAddresses  # noqa: F401
from .ownership import ownership_tag_team


@dataclass
class DerivationResult:
    teams: list[Team] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    matched_by_rule: dict[str, int] = field(default_factory=dict)


def derive_teams(
    snapshot: Snapshot, index: ObjectIndex, config: OwnershipConfig
) -> DerivationResult:
    """Build teams from the configured naming conventions."""
    result = DerivationResult()
    if not config.derive_teams:
        return result

    # Team id -> (name, networks, labels, evidence)
    collected: dict[str, _Accumulator] = {}

    for rule in config.derive_teams:
        before = len(collected)
        matched = _apply_rule(rule, snapshot, index, collected, config)
        result.matched_by_rule[rule.id] = matched
        if matched == 0:
            result.notes.append(
                f"derive_teams rule {rule.id!r} matched nothing -- check the pattern "
                f"against the actual object names ({rule.source})"
            )
        else:
            result.notes.append(
                f"derive_teams rule {rule.id!r} matched {matched} {rule.source}(s), "
                f"producing {len(collected) - before} new team(s)"
            )

    for team_id, acc in sorted(collected.items()):
        if len(acc.networks) < acc.min_assets:
            continue
        networks = _collapse(acc.networks)
        result.teams.append(
            Team(
                id=team_id,
                name=acc.name or team_id,
                contact=acc.contact,
                description=acc.describe(),
                assets=[str(n) for n in networks],
                asset_labels=acc.labels_for(networks),
                tags=sorted(acc.tags),
            )
        )

    return result


@dataclass
class _Accumulator:
    """Everything gathered for one derived team while scanning."""

    team_id: str = ""
    name: str = ""
    contact: str | None = None
    min_assets: int = 1
    excluded: tuple = ()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)

    def add(self, net, label: str) -> None:
        """Record a network unless it is one that is never a team's property."""
        if any(_within(net, ex) for ex in self.excluded):
            return
        self.networks.append(net)
        self.labels.setdefault(str(net), label)

    def inherit_tags(self, tags: list[str], config: OwnershipConfig) -> None:
        """Take only a tag that names *this* team as its owner.

        A tag on an address object is a classification -- what the object is,
        and what dynamic groups it falls into. Taking all of them made every
        derived team claim every type tag its objects happened to carry, and
        the tag resolver then handed it whole classes of rule. On the estate
        this was found on, one tag sat on 137 address groups, 107 of the 110
        derived teams inherited it, and because the tag index keeps one team
        per tag, all 161 rules carrying it landed on whichever team sorted
        last -- as *its own rules*, to review.

        So: only tags shaped like the configured ownership convention, and
        only when they name this team. An estate with no such convention
        inherits nothing, which is the correct answer rather than a missing
        feature.
        """
        for tag in tags:
            named = ownership_tag_team(tag, config)
            if named and _same_tag(named, self.team_id, config):
                self.tags.add(tag)

    def describe(self) -> str:
        origin = ", ".join(sorted(self.sources)[:3])
        return f"Derived from {origin}" if origin else "Derived from naming convention"

    def labels_for(self, networks) -> dict[str, str]:
        """Keep only labels whose network survived collapsing."""
        kept = {str(n) for n in networks}
        return {cidr: label for cidr, label in self.labels.items() if cidr in kept}


def _apply_rule(
    rule: DerivedTeamRule,
    snapshot: Snapshot,
    index: ObjectIndex,
    collected: dict[str, _Accumulator],
    config: OwnershipConfig,
) -> int:
    pattern = re.compile(rule.pattern)
    exclude = re.compile(rule.exclude_pattern) if rule.exclude_pattern else None
    matched = 0

    if rule.source == "address-group":
        matched = _from_address_groups(
            rule, pattern, exclude, snapshot, index, collected, config
        )
    elif rule.source == "address-object":
        matched = _from_address_objects(rule, pattern, exclude, snapshot, collected, config)
    elif rule.source == "tag":
        matched = _from_tags(rule, pattern, exclude, snapshot, collected)

    return matched


def _from_address_groups(
    rule: DerivedTeamRule,
    pattern: re.Pattern[str],
    exclude: re.Pattern[str] | None,
    snapshot: Snapshot,
    index: ObjectIndex,
    collected: dict[str, _Accumulator],
    config: OwnershipConfig,
) -> int:
    """One team per matching address group; its assets are the group's members.

    The strongest signal in a generated estate: a group exists precisely
    because someone decided those addresses belong together.
    """
    matched = 0
    for group in snapshot.address_groups:
        if exclude and exclude.search(group.name):
            continue
        match = pattern.search(group.name)
        if not match:
            continue
        matched += 1

        resolved = resolve_addresses(
            _shell(group.name), group.location, index
        )
        acc = _accumulator(rule, match, collected)
        acc.sources.add(f"address group {group.name!r}")
        for cidr in resolved.networks:
            acc.add(ipaddress.ip_network(cidr), group.name)
        acc.inherit_tags(group.tags, config)
    return matched


def _from_address_objects(
    rule: DerivedTeamRule,
    pattern: re.Pattern[str],
    exclude: re.Pattern[str] | None,
    snapshot: Snapshot,
    collected: dict[str, _Accumulator],
    config: OwnershipConfig,
) -> int:
    """One team per capture; assets are the objects whose names matched."""
    matched = 0
    for address in snapshot.addresses:
        if exclude and exclude.search(address.name):
            continue
        match = pattern.search(address.name)
        if not match:
            continue
        matched += 1

        acc = _accumulator(rule, match, collected)
        acc.sources.add(f"address objects matching {rule.pattern!r}")
        for net in _networks_of(address):
            acc.add(net, address.description or address.name)
        acc.inherit_tags(address.tags, config)
    return matched


def _from_tags(
    rule: DerivedTeamRule,
    pattern: re.Pattern[str],
    exclude: re.Pattern[str] | None,
    snapshot: Snapshot,
    collected: dict[str, _Accumulator],
) -> int:
    """One team per matching tag; assets are every object carrying it."""
    by_tag: dict[str, list] = defaultdict(list)
    for address in snapshot.addresses:
        for tag in address.tags:
            by_tag[tag].append(address)

    matched = 0
    for tag, addresses in by_tag.items():
        if exclude and exclude.search(tag):
            continue
        match = pattern.search(tag)
        if not match:
            continue
        matched += 1

        acc = _accumulator(rule, match, collected)
        acc.sources.add(f"tag {tag!r}")
        acc.tags.add(tag)
        for address in addresses:
            for net in _networks_of(address):
                acc.add(net, address.name)
    return matched


def _accumulator(
    rule: DerivedTeamRule, match: re.Match[str], collected: dict[str, _Accumulator]
) -> _Accumulator:
    """Fetch or create the accumulator for the team this match names."""
    values = {k: (v or "") for k, v in match.groupdict().items()}
    team_id = _format(rule.team_id, values)
    acc = collected.get(team_id)
    if acc is None:
        acc = _Accumulator(
            team_id=team_id,
            name=_format(rule.team_name or rule.team_id, values) or team_id,
            contact=_format(rule.contact, values) if rule.contact else None,
            min_assets=rule.min_assets,
            excluded=tuple(
                ipaddress.ip_network(n, strict=False) for n in rule.exclude_networks
            ),
        )
        collected[team_id] = acc
    return acc


def _format(template: str | None, values: dict[str, str]) -> str:
    if not template:
        return ""
    try:
        return template.format(**values).strip()
    except (KeyError, IndexError):
        # Validated at config load time; a miss here means an optional group
        # did not participate in this particular match.
        return ""


def _networks_of(address) -> list:
    """Concrete networks of an address object, ignoring what cannot be one."""
    kind = address.kind.value
    if kind in ("fqdn", "ip-wildcard"):
        return []
    if kind == "ip-range" and "-" in address.value:
        start, _, end = address.value.partition("-")
        try:
            return list(
                ipaddress.summarize_address_range(
                    ipaddress.ip_address(start.strip()), ipaddress.ip_address(end.strip())
                )
            )
        except (ValueError, TypeError):
            return []
    try:
        return [ipaddress.ip_network(address.value, strict=False)]
    except ValueError:
        return []


def _within(net, container) -> bool:
    """Whether ``net`` lies inside ``container``, families compared safely."""
    if net.version != container.version:
        return False
    return (
        int(container.network_address) <= int(net.network_address)
        and int(net.broadcast_address) <= int(container.broadcast_address)
    )


def _collapse(networks: list):
    """Merge adjacent networks without ever widening beyond what was present.

    Deliberately no roll-up to a coarser prefix here: these assets come from
    named objects, so they are exact, and inventing coverage the configuration
    does not show would attribute other teams' rules.
    """
    v4 = [n for n in networks if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in networks if isinstance(n, ipaddress.IPv6Network)]
    out = [*ipaddress.collapse_addresses(v4), *ipaddress.collapse_addresses(v6)]
    return sorted(out, key=lambda n: (n.version, int(n.network_address), n.prefixlen))


def _shell(name: str):
    """A one-name address field, so the object resolver can flatten a group."""
    from ..model import ResolvedAddresses

    return ResolvedAddresses(raw=[name])


def merge_teams(explicit: list[Team], derived: list[Team]) -> tuple[list[Team], list[str]]:
    """Combine hand-written and derived teams.

    An explicit entry always wins: somebody wrote it deliberately, and a
    convention cannot know about the exception that made them do it. The
    derived team's networks are folded into the explicit one rather than
    dropped, since the convention may well have found assets the human missed.
    """
    notes: list[str] = []
    by_id = {team.id: team for team in explicit}

    for team in derived:
        existing = by_id.get(team.id)
        if existing is None:
            by_id[team.id] = team
            continue

        added = [cidr for cidr in team.assets if cidr not in existing.assets]
        if added:
            existing.assets.extend(added)
            for cidr in added:
                existing.asset_labels.setdefault(cidr, team.asset_labels.get(cidr, ""))
            notes.append(
                f"team {team.id!r} is defined in the inventory; {len(added)} network(s) "
                "found by a derive_teams rule were added to it"
            )
        else:
            notes.append(
                f"team {team.id!r} is defined in the inventory; the derived entry added "
                "nothing new"
            )

    return sorted(by_id.values(), key=lambda t: t.id), notes


def _same_tag(left: str, right: str, config: OwnershipConfig) -> bool:
    return left == right if config.tag_case_sensitive else left.lower() == right.lower()
