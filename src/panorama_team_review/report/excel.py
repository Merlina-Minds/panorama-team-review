"""Excel output -- the working format of the review.

The design assumption is that a review is a conversation, not a document: the
owner receives the workbook, fills in the *Decision* and *Comment* columns, and
sends it back.  Those two columns are why this format exists at all, and they
are why every row carries the rule's location and object names -- that is what
a firewall change request has to cite to be actionable.

Sheets: Overview, one per direction for the team's own rules, one for the
estate-wide rules that merely cover them, Findings, Networks.

The team's own rules and the ones that only cover them are separate sheets on
purpose. Both belong in the workbook -- an owner needs to see the access they
already have -- but a Decision column next to a rule nobody asked them about
invites an answer to a question that was never posed, and the sheet that
matters gets diluted by three times its own length in rules that are not
theirs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import xlsxwriter

from .. import __version__
from ..config import Config
from ..model import Finding, ReportBundle, RuleView, TeamReport
from . import format as fmt

DECISIONS = ["", "keep", "remove", "modify", "unclear"]

# Column layout shared by every rule sheet.
#
# Block and Position come before the rule name because the rows are sorted by
# evaluation order: without them a reader who re-sorts the sheet -- which is
# the first thing anyone does with an autofilter -- has no way back to the
# order the firewall actually reads the rules in.
_RULE_COLUMNS: list[tuple[str, int]] = [
    ("Decision", 12),
    ("Comment", 34),
    ("Block", 22),
    ("Position", 9),
    ("Direction", 14),
    ("Rule", 34),
    ("Location", 22),
    ("Status", 10),
    ("Your networks", 30),
    ("Your networks (addresses)", 30),
    ("Peer (other side)", 38),
    ("Peer addresses", 38),
    ("Peer team", 16),
    ("Source objects", 26),
    ("Destination objects", 26),
    ("Service / ports", 24),
    ("Applications", 22),
    ("From zone", 14),
    ("To zone", 14),
    ("Ticket", 16),
    ("Expires", 12),
    ("Usage", 20),
    ("Findings", 34),
    ("Description", 50),
]


class _Formats:
    """Cell formats, created once per workbook."""

    def __init__(self, book: xlsxwriter.Workbook) -> None:
        self.title = book.add_format({"bold": True, "font_size": 16})
        self.subtitle = book.add_format({"font_size": 10, "font_color": "#555555"})
        self.header = book.add_format(
            {
                "bold": True,
                "bg_color": "#1F3864",
                "font_color": "white",
                "border": 1,
                "text_wrap": True,
                "valign": "vcenter",
            }
        )
        self.cell = book.add_format({"valign": "top", "text_wrap": True, "border": 1})
        self.cell_wrap = book.add_format({"valign": "top", "text_wrap": True, "border": 1})
        self.input = book.add_format(
            {"valign": "top", "border": 1, "bg_color": "#FFF7E6", "locked": False}
        )
        self.key = book.add_format({"bold": True, "valign": "top"})
        self.value = book.add_format({"valign": "top"})
        self.disabled = book.add_format(
            {"valign": "top", "text_wrap": True, "border": 1, "font_color": "#999999",
             "italic": True}
        )
        self.link = book.add_format(
            {"valign": "top", "border": 1, "font_color": "#0563C1", "underline": 1}
        )
        self.severity = {
            "high": book.add_format({"valign": "top", "border": 1, "bg_color": "#F8CBAD",
                                     "bold": True}),
            "medium": book.add_format({"valign": "top", "border": 1, "bg_color": "#FFE699"}),
            "low": book.add_format({"valign": "top", "border": 1, "bg_color": "#E2EFDA"}),
            "info": book.add_format({"valign": "top", "border": 1}),
        }
        self.section = book.add_format({"bold": True, "font_size": 12, "bg_color": "#D9E2F3"})


def write_team_workbook(
    bundle: ReportBundle, report: TeamReport, path: Path, config: Config
) -> Path:
    """Write one team's review workbook."""
    path.parent.mkdir(parents=True, exist_ok=True)
    book = xlsxwriter.Workbook(str(path), {"constant_memory": False, "default_date_format": "yyyy-mm-dd"})
    formats = _Formats(book)

    _write_overview(book, formats, bundle, report, config)

    for direction, title in (
        ("inbound", "Inbound"),
        ("outbound", "Outbound"),
        ("internal", "Both ends yours"),
        ("related", "No direction"),
    ):
        views = report.own(direction)
        if views or direction in ("inbound", "outbound"):
            _write_rule_sheet(
                book, formats, title, views, config, bundle, labels=report.team.asset_labels
            )

    # Split by direction here too: "who may reach me" and "what may my systems
    # reach" stay different questions even when the rule was written centrally.
    for direction, title in (
        ("inbound", "Also covers you - in"),
        ("outbound", "Also covers you - out"),
    ):
        views = report.covered(direction)
        if views:
            # No Decision column: the team is not being asked about these, and
            # an empty input cell next to a rule reads as a request for one.
            _write_rule_sheet(
                book, formats, title, views, config, bundle,
                decisions=False, labels=report.team.asset_labels,
            )

    other = report.covered("internal") + report.covered("related")
    if other:
        other.sort(key=lambda view: view.evaluation_rank)
        _write_rule_sheet(
            book, formats, "Also covers you - other", other, config, bundle,
            decisions=False, labels=report.team.asset_labels,
        )

    _write_findings_sheet(book, formats, report.findings)
    _write_assets_sheet(book, formats, report)
    _write_objects_sheet(book, formats, report)

    book.close()
    return path


def write_combined_workbook(bundle: ReportBundle, path: Path, config: Config) -> Path:
    """Write one workbook covering every team, for the firewall team's own use."""
    path.parent.mkdir(parents=True, exist_ok=True)
    book = xlsxwriter.Workbook(str(path))
    formats = _Formats(book)

    _write_combined_overview(book, formats, bundle, config)

    all_views: list[tuple[str, RuleView]] = [
        (report.team.name, view)
        for report in bundle.teams
        for view in report.all_views
    ]
    _write_combined_rule_sheet(book, formats, "All rules", all_views, config, bundle)

    if bundle.unassigned:
        _write_rule_sheet(
            book, formats, "Unassigned", bundle.unassigned, config, bundle
        )

    _write_findings_sheet(book, formats, bundle.global_findings, include_teams=True)
    _write_inventory_gaps_sheet(book, formats, bundle)
    _write_stats_sheet(book, formats, bundle)

    book.close()
    return path


# ---------------------------------------------------------------------------
# Overview sheets
# ---------------------------------------------------------------------------


def _write_overview(
    book: xlsxwriter.Workbook,
    formats: _Formats,
    bundle: ReportBundle,
    report: TeamReport,
    config: Config,
) -> None:
    sheet = book.add_worksheet("Overview")
    sheet.set_column(0, 0, 28)
    sheet.set_column(1, 1, 80)
    sheet.hide_gridlines(2)

    row = 0
    sheet.write(row, 0, config.report.title, formats.title)
    row += 1
    sheet.write(row, 0, f"Prepared for {report.team.name}", formats.subtitle)
    row += 2

    rows: list[tuple[str, Any]] = [
        ("Team", report.team.name),
        ("Team id", report.team.id),
        ("Contact", report.team.contact or "—"),
        ("", ""),
        ("Configuration source", bundle.meta.source_file),
        ("Configuration type", bundle.meta.source_type),
        (
            "Backup timestamp",
            bundle.meta.file_mtime.strftime("%Y-%m-%d %H:%M") if bundle.meta.file_mtime else "—",
        ),
        ("Report generated", bundle.generated_at.strftime("%Y-%m-%d %H:%M")),
        ("Tool version", __version__),
        ("", ""),
        ("Your rules (to decide on)", report.own_rule_count),
        ("  Inbound (who reaches you)", len(report.own("inbound"))),
        ("  Outbound (what you reach)", len(report.own("outbound"))),
        ("  Both ends yours", len(report.own("internal"))),
        ("  No direction", len(report.own("related"))),
        ("Rules that also cover you (nothing to do)", len(report.covered_views)),
        ("Cleanup candidates in your rules", len(report.findings)),
        ("Usage data (hit counts)", "included" if bundle.hitcount_available else "not collected"),
    ]
    for key, value in rows:
        if key:
            sheet.write(row, 0, key, formats.key)
            sheet.write(row, 1, value, formats.value)
        row += 1

    row += 1
    sheet.write(row, 0, "How to read this workbook", formats.section)
    row += 1
    for line in _explainer(config):
        sheet.write(row, 1, line, formats.value)
        row += 1

    if config.report.contact_text or config.report.change_request_url:
        row += 1
        sheet.write(row, 0, "Requesting a change", formats.section)
        row += 1
        if config.report.contact_text:
            sheet.write(row, 1, config.report.contact_text, formats.value)
            row += 1
        if config.report.change_request_url:
            sheet.write_url(row, 1, config.report.change_request_url, formats.value)
            row += 1


def _explainer(config: Config) -> list[str]:
    return [
        "This workbook holds two kinds of rule, and only the first is a question to you.",
        "",
        "YOUR RULES — written for your address space. One sheet per direction:",
        "  Inbound          — other systems may reach yours. Read these first.",
        "  Outbound         — your systems may reach elsewhere.",
        "  Both ends yours  — source and destination are both networks of yours.",
        "  No direction     — attributed to your team by tag, name or device group, "
        "which does not say which side you are on.",
        "",
        "ALSO COVERS YOU — estate-wide rules that happen to include you: ping, DNS, "
        "Active Directory. Nothing is being asked of you, which is why that sheet has no "
        "Decision column. It is there so you can see the access you already have — no need "
        "to request it — and object if one of your systems must not have it.",
        "",
        "Fill in the Decision column (keep / remove / modify / unclear) and use Comment "
        "for anything the firewall team needs to know. Return the workbook when done.",
        "",
        "Rows are sorted the way the firewall evaluates them; 'Block' and 'Position' say "
        "where a rule sits, and survive re-sorting the sheet. The first matching rule wins.",
        "",
        "'Peer (other side)' is the far end of the connection as the firewall sees it, "
        "after resolving address groups to actual networks.",
        "'Source objects' and 'Destination objects' give the object names as written in "
        "the configuration — cite these in a change request.",
    ]


def _write_combined_overview(
    book: xlsxwriter.Workbook, formats: _Formats, bundle: ReportBundle, config: Config
) -> None:
    sheet = book.add_worksheet("Overview")
    sheet.set_column(0, 0, 34)
    sheet.set_column(1, 6, 16)
    sheet.hide_gridlines(2)

    sheet.write(0, 0, config.report.title, formats.title)
    sheet.write(1, 0, "Overview across all teams", formats.subtitle)

    row = 3
    for key, value in (
        ("Configuration source", bundle.meta.backup_label),
        ("Configuration documents", bundle.meta.document_count),
        ("Report generated", bundle.generated_at.strftime("%Y-%m-%d %H:%M")),
        ("Rules analysed", bundle.stats.get("rules_analysed", 0)),
        ("Rules without an owner", bundle.stats.get("rules_unassigned", 0)),
        ("Findings", bundle.stats.get("findings_total", 0)),
    ):
        sheet.write(row, 0, key, formats.key)
        sheet.write(row, 1, value, formats.value)
        row += 1

    row += 1
    headers = [
        "Team", "Contact", "Inbound", "Outbound", "Both ends", "No direction",
        "Own total", "Also covers", "Findings",
    ]
    for column, header in enumerate(headers):
        sheet.write(row, column, header, formats.header)
    sheet.autofilter(row, 0, row + len(bundle.teams), len(headers) - 1)
    sheet.freeze_panes(row + 1, 0)
    row += 1

    for report in bundle.teams:
        sheet.write(row, 0, report.team.name, formats.cell)
        sheet.write(row, 1, report.team.contact or "", formats.cell)
        sheet.write(row, 2, len(report.own("inbound")), formats.cell)
        sheet.write(row, 3, len(report.own("outbound")), formats.cell)
        sheet.write(row, 4, len(report.own("internal")), formats.cell)
        sheet.write(row, 5, len(report.own("related")), formats.cell)
        sheet.write(row, 6, report.own_rule_count, formats.cell)
        sheet.write(row, 7, len(report.covered_views), formats.cell)
        sheet.write(row, 8, len(report.findings), formats.cell)
        row += 1


# ---------------------------------------------------------------------------
# Rule sheets
# ---------------------------------------------------------------------------


def _write_rule_sheet(
    book: xlsxwriter.Workbook,
    formats: _Formats,
    title: str,
    views: list[RuleView],
    config: Config,
    bundle: ReportBundle,
    decisions: bool = True,
    labels: dict[str, str] | None = None,
) -> None:
    sheet = book.add_worksheet(_safe_sheet_name(title))
    _setup_rule_sheet(sheet, formats, _RULE_COLUMNS, len(views))
    scopes = {scope.id: scope for scope in bundle.scopes}

    for index, view in enumerate(views, start=1):
        _write_rule_row(
            sheet, formats, index, view, config,
            team_name=None, scopes=scopes, report_labels=labels,
        )

    if decisions:
        _add_decision_validation(sheet, len(views), first_data_row=1, column=0)


def _write_combined_rule_sheet(
    book: xlsxwriter.Workbook,
    formats: _Formats,
    title: str,
    views: list[tuple[str, RuleView]],
    config: Config,
    bundle: ReportBundle,
) -> None:
    columns = [("Team", 22), *_RULE_COLUMNS]
    sheet = book.add_worksheet(_safe_sheet_name(title))
    _setup_rule_sheet(sheet, formats, columns, len(views))
    scopes = {scope.id: scope for scope in bundle.scopes}

    for index, (team_name, view) in enumerate(views, start=1):
        _write_rule_row(sheet, formats, index, view, config, team_name=team_name, scopes=scopes)

    _add_decision_validation(sheet, len(views), first_data_row=1, column=1)


def _setup_rule_sheet(sheet, formats: _Formats, columns, row_count: int) -> None:
    for index, (header, width) in enumerate(columns):
        sheet.set_column(index, index, width)
        sheet.write(0, index, header, formats.header)
    sheet.set_row(0, 30)
    sheet.freeze_panes(1, 0)
    if row_count:
        sheet.autofilter(0, 0, row_count, len(columns) - 1)


def _write_rule_row(
    sheet,
    formats: _Formats,
    row: int,
    view: RuleView,
    config: Config,
    team_name: str | None,
    scopes: dict[str, Any] | None = None,
    report_labels: dict[str, str] | None = None,
) -> None:
    rule = view.rule
    base = formats.disabled if rule.disabled else formats.cell
    limit = config.report.max_addresses_shown

    values: list[tuple[Any, Any]] = []
    if team_name is not None:
        values.append((team_name, base))

    findings_text = "; ".join(f"{f.severity.value.upper()}: {f.title}" for f in view.findings)
    worst = fmt.worst_severity(view)
    finding_format = formats.severity[worst.value] if worst else base
    report_labels = report_labels or {}
    scope = (scopes or {}).get(view.scope_id)
    block = f"{scope.position + 1}. {scope.title}" if scope else view.scope_id

    values.extend(
        [
            ("", formats.input),  # Decision -- filled in by the owner
            ("", formats.input),  # Comment
            (block, base),
            (rule.order + 1, base),
            (fmt.DIRECTION_SHORT[view.direction], base),
            (rule.name, base),
            (rule.location.label(), base),
            (fmt.rule_status(rule), base),
            # Name first, addresses beside it. A workbook has no tooltip, and
            # the name is the string a change request has to cite -- but the
            # addresses still have to be there, because that is what somebody
            # checks the rule against.
            (fmt.asset_names(view, report_labels, limit), base),
            (fmt.assets_text(view, limit), base),
            (fmt.peer_names(view, limit), base),
            (fmt.peers_text(view, limit), base),
            (", ".join(view.peer_teams), base),
            (fmt.object_names(rule.source), base),
            (fmt.object_names(rule.destination), base),
            (fmt.services(rule.services, limit), base),
            (fmt.applications(rule), base),
            (fmt.zones(rule.from_zones), base),
            (fmt.zones(rule.to_zones), base),
            (fmt.tickets(rule), base),
            (
                rule.metadata.expires_on.isoformat() if rule.metadata.expires_on else "",
                base,
            ),
            (fmt.hit_summary(rule), base),
            (findings_text, finding_format),
            (rule.description, base),
        ]
    )

    ticket_column = None
    for column, (value, cell_format) in enumerate(values):
        sheet.write(row, column, value, cell_format)
        if value == fmt.tickets(rule) and rule.metadata.tickets:
            ticket_column = column

    # Turn the first ticket into a clickable link where a URL template exists.
    if ticket_column is not None:
        first_with_url = next((t for t in rule.metadata.tickets if t.url), None)
        if first_with_url and first_with_url.url:
            sheet.write_url(
                row, ticket_column, first_with_url.url, formats.link, fmt.tickets(rule)
            )


def _add_decision_validation(sheet, row_count: int, first_data_row: int, column: int) -> None:
    """Constrain the Decision column to the known values."""
    if row_count <= 0:
        return
    sheet.data_validation(
        first_data_row, column, first_data_row + row_count - 1, column,
        {
            "validate": "list",
            "source": [d for d in DECISIONS if d],
            "input_title": "Decision",
            "input_message": "keep, remove, modify or unclear",
        },
    )


# ---------------------------------------------------------------------------
# Findings and assets
# ---------------------------------------------------------------------------


def _write_findings_sheet(
    book: xlsxwriter.Workbook,
    formats: _Formats,
    findings: list[Finding],
    include_teams: bool = False,
) -> None:
    sheet = book.add_worksheet("Findings")
    columns = [("Severity", 12), ("Check", 20), ("Title", 36), ("Rule", 32), ("Location", 22)]
    if include_teams:
        columns.append(("Teams", 24))
    columns.extend([("Detail", 60), ("Recommendation", 50)])

    for index, (header, width) in enumerate(columns):
        sheet.set_column(index, index, width)
        sheet.write(0, index, header, formats.header)
    sheet.set_row(0, 30)
    sheet.freeze_panes(1, 0)
    if findings:
        sheet.autofilter(0, 0, len(findings), len(columns) - 1)

    for row, finding in enumerate(findings, start=1):
        style = formats.severity[finding.severity.value]
        values = [
            fmt.SEVERITY_LABELS[finding.severity],
            finding.code,
            finding.title,
            finding.rule_name,
            finding.location,
        ]
        if include_teams:
            values.append(", ".join(finding.teams))
        values.extend([finding.detail, finding.recommendation])
        for column, value in enumerate(values):
            sheet.write(row, column, value, style if column == 0 else formats.cell)


def _write_assets_sheet(book: xlsxwriter.Workbook, formats: _Formats, report: TeamReport) -> None:
    sheet = book.add_worksheet("Your networks")
    columns = [("Network", 24), ("System", 40), ("Inbound rules", 14), ("Outbound rules", 14)]
    for index, (header, width) in enumerate(columns):
        sheet.set_column(index, index, width)
        sheet.write(0, index, header, formats.header)
    sheet.freeze_panes(1, 0)

    # The team's own rules only: every network is covered by the same
    # estate-wide rules, so including those would put near-identical numbers
    # against all of them and say nothing about where the traffic goes.
    inbound_counts = _count_by_asset(report.own("inbound"))
    outbound_counts = _count_by_asset(report.own("outbound"))
    for row, cidr in enumerate(report.team.assets, start=1):
        sheet.write(row, 0, cidr, formats.cell)
        sheet.write(row, 1, report.team.asset_labels.get(cidr, ""), formats.cell)
        sheet.write(row, 2, inbound_counts.get(cidr, 0), formats.cell)
        sheet.write(row, 3, outbound_counts.get(cidr, 0), formats.cell)


def _write_objects_sheet(
    book: xlsxwriter.Workbook, formats: _Formats, report: TeamReport
) -> None:
    """What the team's networks are called in the firewall.

    A change request has to cite an object name, and the naming convention is
    invisible from outside the network team: nobody guesses that their
    10.20.12.0/24 is called grp-aws-payments-prod-01.
    """
    if not report.objects:
        return

    sheet = book.add_worksheet("Objects and groups")
    columns = [
        ("Name", 44), ("Kind", 10), ("Defined in", 22),
        ("Resolves to", 52), ("Description", 40), ("Tags", 24),
    ]
    for index, (header, width) in enumerate(columns):
        sheet.set_column(index, index, width)
        sheet.write(0, index, header, formats.header)
    sheet.set_row(0, 24)
    sheet.freeze_panes(1, 0)
    sheet.autofilter(0, 0, len(report.objects), len(columns) - 1)

    for row, obj in enumerate(report.objects, start=1):
        values = [
            obj.name,
            obj.kind,
            obj.scope,
            ", ".join(obj.networks[:40]) + (
                f", … (+{len(obj.networks) - 40} more)" if len(obj.networks) > 40 else ""
            ),
            obj.description,
            ", ".join(obj.tags),
        ]
        for column, value in enumerate(values):
            sheet.write(row, column, value, formats.cell)


def _count_by_asset(views: list[RuleView]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for view in views:
        for asset in view.matched_assets:
            counts[asset] = counts.get(asset, 0) + 1
    return counts


def _write_inventory_gaps_sheet(
    book: xlsxwriter.Workbook, formats: _Formats, bundle: ReportBundle
) -> None:
    """Where the object names and the inventory disagree about who owns a network.

    A worklist rather than a report: each row is one address group to correct,
    and correcting it is what makes the affected team's rules appear.
    """
    if not bundle.inventory_gaps:
        return

    sheet = book.add_worksheet("Inventory gaps")
    columns = [
        ("Kind", 16), ("Team", 22), ("Object", 46), ("Network", 20),
        ("Also claimed by", 22), ("Their object", 46), ("What it means", 70),
    ]
    for index, (header, width) in enumerate(columns):
        sheet.set_column(index, index, width)
        sheet.write(0, index, header, formats.header)
    sheet.set_row(0, 30)
    sheet.freeze_panes(1, 0)
    sheet.autofilter(0, 0, len(bundle.inventory_gaps), len(columns) - 1)

    for row, gap in enumerate(bundle.inventory_gaps, start=1):
        values = [
            gap.kind, gap.team_id, gap.object_name, gap.network,
            gap.other_team or "", gap.other_object or "", gap.detail,
        ]
        for column, value in enumerate(values):
            sheet.write(row, column, value, formats.cell)


def _write_stats_sheet(book: xlsxwriter.Workbook, formats: _Formats, bundle: ReportBundle) -> None:
    sheet = book.add_worksheet("Statistics")
    sheet.set_column(0, 0, 34)
    sheet.set_column(1, 1, 14)
    sheet.write(0, 0, "Metric", formats.header)
    sheet.write(0, 1, "Value", formats.header)
    for row, (key, value) in enumerate(sorted(bundle.stats.items()), start=1):
        sheet.write(row, 0, key.replace("_", " "), formats.cell)
        sheet.write(row, 1, value, formats.cell)


def _safe_sheet_name(name: str) -> str:
    """Excel sheet names are limited to 31 characters and forbid []:*?/\\ ."""
    cleaned = "".join("-" if char in "[]:*?/\\" else char for char in name)
    return cleaned[:31] or "Sheet"
