"""Presentation helpers shared by all renderers.

Kept out of the model on purpose: how a rule is *displayed* is a property of
the report, not of the configuration, and the JSON output stays free of
formatting decisions so downstream consumers get raw values.
"""

from __future__ import annotations

import ipaddress
from datetime import date, datetime
from functools import cache
from typing import NamedTuple

from ..model import (
    AddressMember,
    IPNetwork,
    PolicyScope,
    ResolvedAddresses,
    ResolvedServices,
    RuleView,
    SecurityRule,
    Severity,
    TeamReport,
)


@cache
def _network(cidr: str) -> IPNetwork:
    """Parse a CIDR string, memoised.

    The same few thousand CIDRs recur across tens of thousands of rows -- and
    every team carries its own copy of each estate-wide rule -- so without this
    the combined workbook spent almost all its time re-parsing identical
    strings. One parse each turns that into a dict lookup.
    """
    return ipaddress.ip_network(cidr)

DIRECTION_LABELS = {
    "inbound": "Who reaches these networks",
    "outbound": "What these networks reach",
    "internal": "Between the team's own networks",
    "related": "Attributed without a direction",
}

# "Internal" was ambiguous in a firewall report, where it reads as "the
# internal network" rather than as "both ends are yours" -- which is what it
# means. The words say it instead.
DIRECTION_SHORT = {
    "inbound": "Inbound",
    "outbound": "Outbound",
    "internal": "Both ends yours",
    "related": "No direction",
}

COVERAGE_LABELS = {
    "own": "Your rule",
    "covered": "Covers you too",
}

SEVERITY_LABELS = {
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}


def addresses(field: ResolvedAddresses, limit: int = 25) -> str:
    """Render a source/destination field for a cell in a table."""
    if field.is_any:
        return "any (negated)" if field.negated else "any"

    parts: list[str] = list(field.networks)
    parts.extend(f"{name} (FQDN)" for name in field.fqdns)
    parts.extend(
        f"{item.name} [{item.reason.value}]"
        for item in field.unresolved
        if item.reason.value != "fqdn"
    )
    if not parts:
        parts = list(field.raw)

    text = _truncate_list(parts, limit)
    return f"NOT {text}" if field.negated else text


def object_names(field: ResolvedAddresses, limit: int = 10) -> str:
    """The object names as written in the rule, which is what a change request cites."""
    if field.is_any:
        return "any"
    return _truncate_list(field.raw, limit)


def services(field: ResolvedServices, limit: int = 25) -> str:
    if field.is_application_default and not field.raw:
        return "application-default"
    if field.is_any and not field.raw:
        return "any"

    parts = list(field.ports)
    parts.extend(f"{item.name} [unresolved]" for item in field.unresolved)
    if field.is_application_default:
        parts.append("application-default")
    if not parts:
        parts = list(field.raw)
    return _truncate_list(parts, limit)


def applications(rule: SecurityRule, limit: int = 12) -> str:
    return _truncate_list(rule.applications, limit)


def zones(values: list[str], limit: int = 8) -> str:
    return _truncate_list(values, limit)


def tickets(rule: SecurityRule) -> str:
    if not rule.metadata.tickets:
        return ""
    return ", ".join(ticket.id for ticket in rule.metadata.tickets)


def hit_summary(rule: SecurityRule) -> str:
    """One-cell summary of a rule's usage, or why usage is unknown.

    On Panorama this is the aggregate across the firewalls the rule is pushed to:
    the total hits and how long ago the most recent match was. The exact date is
    kept in the per-firewall breakdown (``hit_devices``) and the expanded row.
    """
    if rule.hits is None:
        return "not collected"
    if rule.hits.is_unused:
        return "never matched"
    last = f", last {relative_age(rule.hits.last_hit)}" if rule.hits.last_hit else ""
    return f"{rule.hits.hit_count:,} hits{last}".replace(",", " ")


def relative_age(when: datetime, today: date | None = None) -> str:
    """How long ago ``when`` was, in words -- 'today', '3 days ago', '2 years ago'.

    Coarse on purpose: a reader deciding whether a rule is still used wants "a
    few weeks" or "over a year", not a date to subtract in their head. The exact
    timestamp stays in the breakdown for anyone who needs it.
    """
    today = today or date.today()
    days = (today - when.date()).days
    if days <= 0:
        return "today"
    if days == 1:
        return "yesterday"
    if days < 14:
        return f"{days} days ago"
    if days < 60:
        return f"{days // 7} weeks ago"
    if days < 365:
        return f"{days // 30} months ago"
    years = days // 365
    return f"{years} year{'s' if years > 1 else ''} ago"


def hit_devices(rule: SecurityRule) -> str:
    """Per-firewall usage breakdown, newest match first; empty when not applicable.

    Used as a tooltip beside the aggregated summary, so a reader can see a rule
    is used on one firewall and idle on the four others it was pushed to.
    """
    if rule.hits is None or not rule.hits.per_device:
        return ""
    lines = []
    for device in rule.hits.per_device:
        count = f"{device.hit_count:,}".replace(",", " ")
        when = f"last {device.last_hit:%Y-%m-%d}" if device.last_hit else "never matched"
        lines.append(f"{device.device}: {count} hits, {when}")
    return "\n".join(lines)


def rule_status(rule: SecurityRule) -> str:
    if rule.disabled:
        return "disabled"
    return rule.action.value


def worst_severity(view: RuleView) -> Severity | None:
    if not view.findings:
        return None
    return max((f.severity for f in view.findings), key=lambda s: s.rank)


def team_severity_counts(report: TeamReport) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    for finding in report.findings:
        counts[finding.severity.value] += 1
    return counts


def _truncate_list(items: list[str], limit: int) -> str:
    if not items:
        return ""
    if len(items) <= limit:
        return ", ".join(items)
    remaining = len(items) - limit
    return ", ".join(items[:limit]) + f", … (+{remaining} more)"


def peers_text(view: RuleView, limit: int = 25) -> str:
    return _truncate_list(view.peers, limit)


def assets_text(view: RuleView, limit: int = 15) -> str:
    return _truncate_list(view.matched_assets, limit)


# ---------------------------------------------------------------------------
# Names first, addresses behind them
# ---------------------------------------------------------------------------
#
# A rule cell used to hold the resolved addresses, which is what the firewall
# matches on and what nobody outside the network team can read. `10.20.12.34,
# 10.20.12.66` says nothing; `grp-time-servers` says what the rule is for --
# and is also the string a change request has to cite. The addresses are still
# needed, so they move behind the name where they can be looked at on demand
# rather than read past forty times a page.


class Cell(NamedTuple):
    """One entry in an address cell: what to show, and what sits behind it."""

    label: str
    detail: str
    """Tooltip text. Empty when the label already *is* the address."""


def _member_cell(member: AddressMember, limit: int) -> Cell:
    parts = [*member.networks, *(f"{f} (FQDN)" for f in member.fqdns)]
    parts.extend(f"{item.name}: {item.reason.value}" for item in member.unresolved)

    if member.is_literal or not parts:
        # The rule named an address directly. Repeating it as its own tooltip
        # would be noise.
        return Cell(member.name, "")

    detail = "\n".join(parts[:limit])
    if len(parts) > limit:
        detail += f"\n… and {len(parts) - limit} more"
    return Cell(member.name, f"{len(parts)} entr{'y' if len(parts) == 1 else 'ies'}\n{detail}")


def address_cells(field: ResolvedAddresses, limit: int = 60) -> list[Cell]:
    """The objects a rule field names, each carrying its own addresses."""
    if field.is_any:
        return [Cell("any (negated)" if field.negated else "any", "")]
    if field.members:
        return [_member_cell(member, limit) for member in field.members]
    # A field resolved before this breakdown existed, or one with no named
    # objects at all: fall back to the addresses rather than showing nothing.
    return [Cell(value, "") for value in field.networks or field.raw]


def _own_side(view: RuleView) -> list[ResolvedAddresses]:
    """The rule field(s) the team's own networks were matched on."""
    rule = view.rule
    if view.direction == "outbound":
        return [rule.source]
    if view.direction == "inbound":
        return [rule.destination]
    if view.direction == "internal":
        return [rule.source, rule.destination]
    return []


def peer_cells(view: RuleView, limit: int = 60) -> list[Cell]:
    """The far side of the connection, named.

    For a rule with the team on both sides there is no far side, so both are
    shown -- that is what "both ends yours" means.
    """
    rule = view.rule
    if view.direction == "outbound":
        return address_cells(rule.destination, limit)
    if view.direction == "inbound":
        return address_cells(rule.source, limit)
    if view.direction == "internal":
        return [*address_cells(rule.source, limit), *address_cells(rule.destination, limit)]
    # No direction was established, so neither side is "the far side".
    return [Cell(value, "") for value in view.peers] or [Cell("any", "")]


def asset_cells(view: RuleView, labels: dict[str, str]) -> list[Cell]:
    """The object *the rule names* on the team's side of the connection.

    Not the inventory's name for the team's network, which is what this used to
    show and which was wrong in a way that mattered: the rule
    ``payments-prod-to-gitlab`` has the source
    ``net-payments-app-10.20.12.0-24``, and the cell announced
    ``grp-aws-payments-prod-01`` -- the address group the team happened
    to be derived from, a name that rule never mentions. A reader quoting it in
    a change request would be asking for a change to the wrong object, and
    nothing in the report would have contradicted them.

    So both address columns now name objects as the rule writes them, and the
    tooltip says which of the reader's networks the object covers. Where a rule
    names a group far larger than the team -- ``grp-all-internal-10.0.0.0-8``
    around a /21 -- that group is what appears, because that is what the rule
    says and what a change request has to argue with.
    """
    assets = [_network(cidr) for cidr in view.matched_assets]
    fields = _own_side(view)

    # Sizes here are small: at most a few dozen objects on a side and a few
    # dozen of the team's networks touched by any one rule, so the plain
    # nested scan costs less than building an index per cell would. Member
    # networks are parsed once per member rather than once per asset, so a
    # group that resolves to hundreds of networks is not re-parsed for each of
    # the team's assets.
    grouped: dict[str, tuple[list[str], list[str]]] = {}
    for field in fields:
        for member in field.members:
            member_networks = [_network(cidr) for cidr in member.networks]
            covered = [
                str(asset)
                for asset in assets
                if any(
                    network.version == asset.version and network.overlaps(asset)
                    for network in member_networks
                )
            ]
            if not covered:
                continue
            networks, seen = grouped.setdefault(member.name, ([], []))
            networks.extend(n for n in member.networks if n not in networks)
            seen.extend(c for c in covered if c not in seen)

    if grouped:
        return [
            Cell(name, _own_detail(covered, networks))
            for name, (networks, covered) in grouped.items()
        ]

    if any(field.is_any for field in fields):
        return [Cell("any", "")]

    # Attribution by zone, tag or device group: the rule names no object that
    # covers this team, so there is none to show. The team's own networks are
    # the honest answer, and the inventory's name for them goes in the tooltip
    # rather than the cell -- it is not a name this rule uses.
    return [
        Cell(cidr, f"Called {labels[cidr]} in the inventory" if cidr in labels else "")
        for cidr in view.matched_assets
    ] or [Cell("—", "")]


def _own_detail(covered: list[str], networks: list[str]) -> str:
    return "\n".join(
        [
            "Covers your " + _truncate_list(covered, 8),
            "Resolves to " + _truncate_list(networks, 20),
        ]
    )


def peer_team_cell(view: RuleView, limit: int = 3) -> Cell | None:
    """Who owns the far side, as a count once the list stops being a list.

    A rule reaching an estate-wide group answers with every team in the
    inventory. Spelled out, that wrapped over a dozen lines and pushed the rest
    of the row off the page. Past a handful the individual names carry nothing
    the count does not: "sixty teams" says *almost everybody*, which is the
    finding. The names stay in the tooltip for whoever does want to read them.
    """
    teams = view.peer_teams
    if not teams:
        return None
    if len(teams) <= limit:
        return Cell(", ".join(teams), "")
    return Cell(f"{len(teams)} teams", _truncate_list(teams, 60))


def peer_names(view: RuleView, limit: int = 8) -> str:
    """The far side as plain names, for the formats that cannot hold a tooltip."""
    return _truncate_list([cell.label for cell in peer_cells(view)], limit)


def asset_names(view: RuleView, labels: dict[str, str], limit: int = 8) -> str:
    return _truncate_list([cell.label for cell in asset_cells(view, labels)], limit)


def group_by_scope(
    views: list[RuleView], scopes: list[PolicyScope]
) -> list[tuple[PolicyScope, list[RuleView]]]:
    """Split already-sorted rules into the blocks the firewall evaluates.

    The blocks come back in evaluation order and empty ones are dropped, so a
    report shows only the parts of the policy a team actually appears in --
    while each block still states how many rules it holds in total, which is
    what tells an owner that rules they cannot see sit between the ones they
    can.

    A view whose scope is unknown to the bundle still gets a block of its own
    rather than being dropped: losing a rule from a firewall report is a worse
    failure than an unlabelled heading.
    """
    known = {scope.id: scope for scope in scopes}
    grouped: dict[str, list[RuleView]] = {}
    for view in views:
        grouped.setdefault(view.scope_id, []).append(view)

    def rank(scope_id: str) -> tuple[int, str]:
        scope = known.get(scope_id)
        return (scope.position, scope_id) if scope else (len(known), scope_id)

    return [
        (known.get(scope_id) or _placeholder_scope(scope_id), grouped[scope_id])
        for scope_id in sorted(grouped, key=rank)
    ]


def _placeholder_scope(scope_id: str) -> PolicyScope:
    return PolicyScope(
        id=scope_id,
        title=scope_id or "Unknown position",
        stage="local",
        applies_to="position in the policy could not be determined",
        position=0,
    )
