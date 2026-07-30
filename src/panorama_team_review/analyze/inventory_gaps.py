"""Check the object names against the team inventory.

Where an estate names its address objects after the account they belong to --
``net-prod-payments-database-10.20.12.0-24`` says *payments, production* as
plainly as a label can -- that statement is a second, independent record of
ownership. The inventory is the first. Where the two disagree, one of them is
wrong, and nothing else says so: the rules touching that network simply never
reach the team's report, and the report looks complete.

Two disagreements are worth reporting, and both were found on a real estate:

**A network the name assigns to a team the inventory does not give it.**
Usually the account's address group is missing a member. On the estate this was
written against, one account's group held a single /22 while the account
actually ran three networks in a second VPC, so nine rules about it reached
nobody -- and the obvious fix, reading the rule's ownership tag instead, would
have papered over it: the rules would have appeared without direction, without
matched networks, and the group would have stayed wrong for everything else
that uses it.

**A network two teams' names both claim.** Either a range was reassigned and
the old object outlived it, or two objects describe the same addresses. Either
way a rule touching that network is attributed to both accounts, and neither
attribution is more trustworthy than the other.

This checks names against the inventory. It never *uses* the names to
attribute a rule -- addresses do that, and they do it better, because a name
is a claim while an address is what the firewall actually matches on.
"""

from __future__ import annotations

import ipaddress
import re

from ..config import ObjectNamingRule
from ..model import AddressKind, InventoryGap, Snapshot, Team


def find_inventory_gaps(
    snapshot: Snapshot, teams: list[Team], rules: list[ObjectNamingRule]
) -> list[InventoryGap]:
    """Compare what the object names claim against what the inventory records."""
    if not rules:
        return []

    compiled = [(re.compile(rule.pattern, re.IGNORECASE), rule) for rule in rules]
    known = {team.id: _networks(team) for team in teams}

    claims = _collect_claims(snapshot, compiled, known)
    return _outside_team(claims, known) + _claimed_twice(claims)


class _Claim:
    """One object stating, by its name, which team it belongs to."""

    __slots__ = ("name", "team_id", "network")

    def __init__(self, name: str, team_id: str, network) -> None:
        self.name = name
        self.team_id = team_id
        self.network = network


def _collect_claims(snapshot, compiled, known) -> list[_Claim]:
    claims: list[_Claim] = []
    # An object of the same name can be defined in several scopes -- a device
    # group and `shared`, or two device groups -- and a merged Panorama archive
    # then holds each definition separately. That distinction matters to the
    # resolver and to nobody reading this list: one gap is one address group to
    # correct, however many places the object is written down in.
    seen: set[tuple[str, str]] = set()

    for address in snapshot.addresses:
        if address.kind is not AddressKind.IP_NETMASK:
            # Ranges, wildcards and FQDNs carry no single network to compare,
            # and a check that guesses at them would produce noise.
            continue
        try:
            network = ipaddress.ip_network(address.value, strict=False)
        except ValueError:
            continue

        for pattern, rule in compiled:
            match = pattern.search(address.name)
            if not match:
                continue
            team_id = _format(rule.team_id, match)
            # A name pointing at a team that does not exist is a different
            # problem -- an account with no inventory entry at all -- and the
            # unassigned-rules section already speaks to it. Reporting it here
            # as well would double-count the same gap.
            key = (address.name, str(network))
            if team_id and team_id in known and key not in seen:
                seen.add(key)
                claims.append(_Claim(address.name, team_id, network))
            break
    return claims


def _outside_team(claims: list[_Claim], known: dict[str, list]) -> list[InventoryGap]:
    gaps = []
    for claim in claims:
        assets = known[claim.team_id]
        if any(
            claim.network.version == asset.version and claim.network.subnet_of(asset)
            for asset in assets
        ):
            continue
        held = ", ".join(str(a) for a in assets[:4]) or "nothing"
        more = f" and {len(assets) - 4} more" if len(assets) > 4 else ""
        gaps.append(
            InventoryGap(
                kind="outside-team",
                team_id=claim.team_id,
                object_name=claim.name,
                network=str(claim.network),
                detail=(
                    f"the name assigns this object to {claim.team_id}, whose inventory "
                    f"holds {held}{more} -- so every rule touching {claim.network} is "
                    "missing from that team's report"
                ),
            )
        )
    return sorted(gaps, key=lambda g: (g.team_id, g.network))


def _claimed_twice(claims: list[_Claim]) -> list[InventoryGap]:
    by_network: dict[str, list[_Claim]] = {}
    for claim in claims:
        by_network.setdefault(str(claim.network), []).append(claim)

    gaps = []
    for network, sharing in sorted(by_network.items()):
        teams = {c.team_id: c for c in sharing}
        if len(teams) < 2:
            continue
        first, second = sorted(teams)[:2]
        gaps.append(
            InventoryGap(
                kind="claimed-twice",
                team_id=first,
                object_name=teams[first].name,
                network=network,
                other_team=second,
                other_object=teams[second].name,
                detail=(
                    f"two names claim {network}: one assigns it to {first}, the other to "
                    f"{second}. Either the range was reassigned and the older object "
                    "outlived it, or both describe the same addresses -- a rule touching "
                    "it is attributed to both, and neither is the more trustworthy"
                ),
            )
        )
    return gaps


def _networks(team: Team) -> list:
    out = []
    for cidr in team.assets:
        try:
            out.append(ipaddress.ip_network(cidr))
        except ValueError:
            continue
    return out


def _format(template: str, match: re.Match[str]) -> str:
    values = {key: (value or "") for key, value in match.groupdict().items()}
    try:
        return template.format(**values).strip().lower()
    except (KeyError, IndexError):
        # The config validator guarantees the groups exist; a miss here means
        # an optional group did not participate in this particular match.
        return ""
