"""HTML output -- the format owners actually use.

Self-contained by design: one file, CSS and JavaScript inlined, no external
requests.  That matters because these reports get mailed around, dropped on
file shares and opened from USB sticks on management networks with no internet
access.  A report that needs a CDN is a report that renders blank.

The page carries a search box, severity filters and per-rule expandable
detail, which is the part a PDF cannot do and the reason this is the primary
format rather than an afterthought.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup, escape

from ..config import Config
from ..model import ReportBundle, ResolvedAddresses, ResolvedServices, RuleView, TeamReport
from . import format as fmt

TEMPLATE_DIR = Path(__file__).parent / "templates"


@lru_cache(maxsize=1)
def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html", "xml", "html.j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters.update(
        {
            "worst_severity": fmt.worst_severity,
            "assets_text": _assets_text,
            "peers_text": _peers_text,
            "services_text": _services_text,
            "object_names": _object_names,
            "addresses_text": _addresses_text,
            "hit_summary": fmt.hit_summary,
            "hit_devices": fmt.hit_devices,
            "tickets_text": fmt.tickets,
            "search_text": _search_text,
            "group_by_scope": fmt.group_by_scope,
            "direction_word": _direction_word,
            "asset_cells": _asset_cells,
            "peer_cells": _peer_cells,
            "address_cells": _address_field_cells,
            "peer_team_cell": _peer_team_cell,
            "highlight_networks": _highlight_networks,
            "highlight_objects": _highlight_objects,
            "asset_names": fmt.asset_names,
            "peer_names": fmt.peer_names,
        }
    )
    return env


@lru_cache(maxsize=4)
def _stylesheet(name: str) -> Markup:
    """Load a stylesheet as markup that autoescaping must leave alone.

    Autoescaping is on for everything else and must stay on: rule names,
    descriptions and object names come out of a configuration file this tool
    does not control, and injecting them raw would make a report an attack on
    whoever opens it. The stylesheet is ours, so it is the one exception --
    without this, quotes in `font-family: "Segoe UI"` and in `content: "Page "`
    become &#34; and the rules are silently discarded by the CSS parser.
    """
    return Markup((TEMPLATE_DIR / name).read_text(encoding="utf-8"))


# -- filters ----------------------------------------------------------------


def _assets_text(view: RuleView, limit: int = 15) -> str:
    return fmt.assets_text(view, limit)


def _peers_text(view: RuleView, limit: int = 25) -> str:
    return fmt.peers_text(view, limit)


def _services_text(field: ResolvedServices, limit: int = 25) -> str:
    return fmt.services(field, limit)


def _object_names(field: ResolvedAddresses, limit: int = 10) -> str:
    return fmt.object_names(field, limit)


def _addresses_text(field: ResolvedAddresses, limit: int = 40) -> str:
    return fmt.addresses(field, limit)


def _direction_word(direction: str) -> str:
    return fmt.DIRECTION_SHORT.get(direction, direction)


def _cells(entries: list[fmt.Cell], limit: int = 12) -> Markup:
    """Render address cells as names with their addresses behind a tooltip.

    Escaped here rather than by the template, because this is one of the few
    places that emits markup rather than text -- and the strings inside it come
    straight out of a configuration file this tool does not control. The
    `title` attribute is the whole point: it is the one tooltip mechanism that
    works in a file opened from disk with no JavaScript, which is how these
    reports are read.
    """
    if not entries:
        return Markup("")

    shown = entries[:limit]
    parts = []
    for entry in shown:
        label = escape(entry.label)
        if entry.detail:
            parts.append(
                Markup('<span class="named" title="{}">{}</span>').format(entry.detail, label)
            )
        else:
            parts.append(Markup('<span class="literal">{}</span>').format(label))

    rendered = Markup(", ").join(parts)
    if len(entries) > limit:
        rendered += Markup(' <span class="more">… and {} more</span>').format(
            len(entries) - limit
        )
    return rendered


def _asset_cells(view: RuleView, labels: dict[str, str]) -> Markup:
    return _cells(fmt.asset_cells(view, labels))


def _peer_cells(view: RuleView) -> Markup:
    return _cells(fmt.peer_cells(view))


def _address_field_cells(field: ResolvedAddresses) -> Markup:
    """One side of a rule, named, for tables that have no team perspective."""
    return _cells(fmt.address_cells(field))


def _peer_team_cell(view: RuleView) -> Markup:
    cell = fmt.peer_team_cell(view)
    return _cells([cell]) if cell else Markup("")


def _highlight_objects(field: ResolvedAddresses, highlight: list[str], limit: int = 20) -> Markup:
    """The object names, with the one that put this rule in the report bold.

    The same emphasis as on the resolved addresses below it, because the two
    lines answer the same question at different altitudes: *which* object
    reaches me, and *what* is in it. Marking only the address leaves the reader
    to work back up from a network to the group holding it.
    """
    if field.is_any:
        return Markup("any")

    wanted = set(highlight)

    def _matched(member) -> bool:
        return any(cidr in wanted for cidr in member.networks)

    # Matched objects lead, so the one that put this rule in the report is read
    # first and never falls past the truncation limit.
    ordered = [m for m in field.members if _matched(m)] + [
        m for m in field.members if not _matched(m)
    ]
    parts = []
    for member in ordered[:limit]:
        text = escape(member.name)
        parts.append(Markup("<strong>{}</strong>").format(text) if _matched(member) else text)

    if not parts:
        parts = [escape(name) for name in field.raw[:limit]]

    rendered = Markup(", ").join(parts)
    remaining = len(field.members or field.raw) - limit
    if remaining > 0:
        rendered += escape(f", … (+{remaining} more)")
    return rendered


def _highlight_networks(field: ResolvedAddresses, highlight: list[str]) -> Markup:
    """The resolved addresses, with the ones that put this rule in the report bold.

    Without it the reader is handed a list of forty networks and told that one
    of them is why they are looking at this rule, which is a puzzle rather than
    an explanation.
    """
    if field.is_any:
        return Markup("any")

    wanted = set(highlight)
    # The matched networks lead, so the one that put this rule in the report is
    # read first and is never the entry that falls past the truncation limit.
    ordered = [c for c in field.networks if c in wanted] + [
        c for c in field.networks if c not in wanted
    ]
    parts = []
    for cidr in ordered[:60]:
        text = escape(cidr)
        parts.append(Markup("<strong>{}</strong>").format(text) if cidr in wanted else text)
    for name in field.fqdns[:20]:
        parts.append(escape(f"{name} (FQDN)"))
    for item in field.unresolved[:20]:
        if item.reason.value != "fqdn":
            parts.append(escape(f"{item.name} [{item.reason.value}]"))

    rendered = Markup(", ").join(parts)
    remaining = len(field.networks) - 60
    if remaining > 0:
        rendered += escape(f", … (+{remaining} more)")
    return rendered or Markup(", ").join(escape(name) for name in field.raw)


def _search_text(view: RuleView) -> str:
    """Everything the client-side filter should match against, lowercased.

    Built server-side so the filter stays a plain substring test: fast enough
    for thousands of rows without an index, and predictable for the user.
    """
    rule = view.rule
    parts = [
        rule.name,
        rule.description,
        rule.location.label(),
        " ".join(rule.tags),
        " ".join(rule.applications),
        " ".join(rule.from_zones),
        " ".join(rule.to_zones),
        " ".join(rule.source.raw),
        " ".join(rule.destination.raw),
        " ".join(rule.source.networks),
        " ".join(rule.destination.networks),
        " ".join(rule.services.ports),
        " ".join(view.peers),
        " ".join(view.matched_assets),
        " ".join(ticket.id for ticket in rule.metadata.tickets),
        " ".join(finding.title for finding in view.findings),
        " ".join(finding.code for finding in view.findings),
    ]
    return " ".join(parts).lower()


# -- rendering --------------------------------------------------------------


def render_team(bundle: ReportBundle, report: TeamReport, config: Config) -> str:
    template = _environment().get_template("team_report.html.j2")
    return template.render(
        bundle=bundle,
        report=report,
        config=config,
        css=_stylesheet("base.css"),
        asset_counts=_asset_counts(report),
    )


def render_combined(bundle: ReportBundle, config: Config) -> str:
    template = _environment().get_template("combined_report.html.j2")
    return template.render(
        bundle=bundle,
        config=config,
        css=_stylesheet("base.css"),
    )


def write_team(bundle: ReportBundle, report: TeamReport, path: Path, config: Config) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_team(bundle, report, config), encoding="utf-8")
    return path


def write_combined(bundle: ReportBundle, path: Path, config: Config) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_combined(bundle, config), encoding="utf-8")
    return path


def _asset_counts(report: TeamReport) -> dict[str, dict[str, int]]:
    """Per-asset rule counts, so an owner can see which network draws traffic.

    Counts the team's own rules only. Counting the estate-wide ones as well
    would put a near-identical three-digit number against every network --
    every one of them is covered by the same central rules -- which tells the
    reader nothing about where their own traffic actually goes.
    """

    def count(views: list[RuleView]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for view in views:
            for asset in view.matched_assets:
                counts[asset] = counts.get(asset, 0) + 1
        return counts

    return {
        "inbound": count(report.own("inbound")),
        "outbound": count(report.own("outbound")),
        "internal": count(report.own("internal")),
    }
