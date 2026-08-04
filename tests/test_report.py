"""Report assembly and rendering, end to end over a generated configuration."""

from __future__ import annotations

import json
import zipfile
from datetime import date

import pytest

from panorama_team_review.config import Config, OutputConfig, ReportConfig
from panorama_team_review.model import AddressMember, ResolvedAddresses
from panorama_team_review.report import excel, html, json_report, pdf
from panorama_team_review.report import format as fmt
from panorama_team_review.report.build import build_report

TODAY = date(2026, 7, 28)


@pytest.fixture
def bundle(panorama_snapshot, teams, config):
    return build_report(panorama_snapshot, teams, config, today=TODAY)


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def test_every_team_gets_a_report(bundle, teams):
    """Even a team with no rules: 'nothing touches your systems' is an answer."""
    assert {report.team.id for report in bundle.teams} == {team.id for team in teams}


def test_hit_devices_lists_each_firewall_newest_first():
    from datetime import datetime

    from panorama_team_review.model import DeviceHit, HitCount, Location, SecurityRule

    rule = SecurityRule(name="r", location=Location(source="t", device_group="DG"))
    rule.hits = HitCount(
        hit_count=15,
        per_device=[
            DeviceHit(device="fw2", hit_count=5, last_hit=datetime(2026, 7, 20)),
            DeviceHit(device="fw1", hit_count=10, last_hit=None),
        ],
    )
    text = fmt.hit_devices(rule)
    assert "fw2: 5 hits, last 2026-07-20" in text
    assert "fw1: 10 hits, never matched" in text


def test_hit_devices_empty_without_a_breakdown():
    from panorama_team_review.model import Location, SecurityRule

    rule = SecurityRule(name="r", location=Location(source="t"))
    assert fmt.hit_devices(rule) == ""


def test_relative_age_reads_in_words():
    from datetime import datetime

    ref = date(2026, 8, 4)

    def age(y, m, d):
        return fmt.relative_age(datetime(y, m, d), today=ref)

    assert age(2026, 8, 4) == "today"
    assert age(2026, 8, 3) == "yesterday"
    assert age(2026, 8, 1) == "3 days ago"
    assert age(2026, 7, 21) == "2 weeks ago"
    assert age(2026, 6, 1) == "2 months ago"
    assert age(2025, 8, 4) == "1 year ago"
    assert age(2023, 8, 4) == "3 years ago"


def test_hit_summary_uses_relative_wording():
    from datetime import datetime

    from panorama_team_review.model import HitCount, Location, SecurityRule

    rule = SecurityRule(name="r", location=Location(source="t"))
    rule.hits = HitCount(hit_count=1234, last_hit=datetime.now())
    assert "last today" in fmt.hit_summary(rule)
    assert "1 234 hits" in fmt.hit_summary(rule)


def test_matched_networks_lead_the_resolved_list():
    """The network that put the rule in the report reads first, not buried."""
    from panorama_team_review.report.html import _highlight_networks

    field = ResolvedAddresses(
        raw=["prod-networks"],
        networks=["10.10.0.0/16", "10.138.146.0/24", "10.20.0.0/16"],
    )
    out = str(_highlight_networks(field, ["10.138.146.0/24"]))
    assert out.startswith("<strong>10.138.146.0/24</strong>")


def test_matched_objects_lead_the_object_list():
    from panorama_team_review.report.html import _highlight_objects

    field = ResolvedAddresses(
        raw=["wide", "mine"],
        members=[
            AddressMember(name="wide", networks=["10.0.0.0/8"]),
            AddressMember(name="mine", networks=["10.138.146.0/24"]),
        ],
    )
    out = str(_highlight_objects(field, ["10.138.146.0/24"]))
    assert out.startswith("<strong>mine</strong>")




def test_rules_are_distributed_by_direction(bundle):
    platform = next(r for r in bundle.teams if r.team.id == "platform")
    assert platform.inbound
    assert platform.outbound
    assert platform.rule_count == (
        len(platform.inbound) + len(platform.outbound)
        + len(platform.internal) + len(platform.related)
    )


def test_inbound_views_carry_their_matched_assets(bundle):
    platform = next(r for r in bundle.teams if r.team.id == "platform")
    for view in platform.inbound:
        assert view.matched_assets, f"{view.rule.name} has no matched asset"


def test_views_explain_why_the_rule_is_listed(bundle):
    """An owner must be able to correct a wrong attribution."""
    platform = next(r for r in bundle.teams if r.team.id == "platform")
    for view in platform.inbound:
        assert view.matches
        assert all(match.evidence for match in view.matches)


def test_findings_are_attached_to_the_right_team(bundle):
    for report in bundle.teams:
        for finding in report.findings:
            assert finding.teams == [report.team.id]


def test_unassigned_rules_are_collected(bundle):
    for view in bundle.unassigned:
        assert view.direction == "related"


def test_statistics_are_populated(bundle, panorama_snapshot):
    assert bundle.stats["rules_total"] == len(panorama_snapshot.rules)
    assert bundle.stats["teams"] == len(bundle.teams)
    assert bundle.stats["address_objects"] > 0
    assert "findings_total" in bundle.stats


def test_metadata_extraction_ran(bundle):
    with_tickets = [
        view for report in bundle.teams for view in report.all_views
        if view.rule.metadata.tickets
    ]
    assert with_tickets, "the generator writes ticket references into descriptions"


def test_hitcount_flag_is_false_without_enrichment(bundle):
    assert bundle.hitcount_available is False


def test_disabled_rules_can_be_excluded(panorama_snapshot, teams, tmp_path):
    config = Config(
        output=OutputConfig(directory=tmp_path, formats=["json"]),
        report=ReportConfig(include_disabled_rules=False),
    )
    bundle = build_report(panorama_snapshot, teams, config, today=TODAY)
    assert all(not view.rule.disabled for report in bundle.teams for view in report.all_views)


def test_unassigned_section_can_be_suppressed(panorama_snapshot, teams, tmp_path):
    config = Config(
        output=OutputConfig(directory=tmp_path, formats=["json"]),
        report=ReportConfig(show_unassigned_section=False),
    )
    bundle = build_report(panorama_snapshot, teams, config, today=TODAY)
    assert bundle.unassigned == []


def test_build_is_deterministic(panorama_file, teams, config):
    """Two runs over the same input must produce identical reports."""
    from panorama_team_review.parse import panos
    from panorama_team_review.parse.loader import load

    first = build_report(panos.parse(load(panorama_file)[0]), teams, config, today=TODAY)
    second = build_report(panos.parse(load(panorama_file)[0]), teams, config, today=TODAY)

    def shape(bundle):
        return [
            (report.team.id, [(view.rule.name, view.direction) for view in report.all_views])
            for report in bundle.teams
        ]

    assert shape(first) == shape(second)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def test_json_bundle_round_trips(bundle, tmp_path):
    path = json_report.write_bundle(bundle, tmp_path / "bundle.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["meta"]["source_type"] == "panorama"
    assert len(data["teams"]) == len(bundle.teams)
    assert "generated_at" in data


def test_json_team_slice_stands_alone(bundle, tmp_path):
    report = bundle.teams[0]
    path = json_report.write_team(bundle, report, tmp_path / "team.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["team"]["team"]["id"] == report.team.id
    assert "meta" in data and "generated_at" in data


def test_json_is_utf8_and_not_escaped(bundle, tmp_path):
    path = json_report.write_bundle(bundle, tmp_path / "b.json")
    assert "\\u" not in path.read_text(encoding="utf-8")[:5000]


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


def test_html_is_self_contained(bundle, config, tmp_path):
    """No external requests: these get opened on air-gapped management hosts."""
    report = bundle.teams[0]
    content = html.render_team(bundle, report, config)
    for marker in ("<link rel=\"stylesheet\"", "src=\"http", "href=\"http://", "@import"):
        assert marker not in content
    assert "<style>" in content and "<script>" in content


def test_html_contains_the_team_and_rules(bundle, config):
    report = next(r for r in bundle.teams if r.team.id == "platform")
    content = html.render_team(bundle, report, config)
    assert report.team.name in content
    for view in report.inbound[:3]:
        assert view.rule.name in content


def test_html_escapes_rule_content(panorama_snapshot, teams):
    """Rule names and descriptions come from a file this tool does not control.

    The check is whether a payload can produce a *tag* -- an escaped payload
    may legitimately appear as text or inside an attribute value, so a plain
    substring search would both miss real injections and flag safe output. The
    document is parsed and the resulting tags are inspected instead.
    """
    from html.parser import HTMLParser

    panorama_snapshot.rules[0].name = "<script>alert(1)</script>"
    panorama_snapshot.rules[0].description = '"><img src=x onerror=alert(1)>'
    panorama_snapshot.rules[0].tags = ["</td><td onclick=alert(2)>"]

    rebuilt = build_report(panorama_snapshot, teams, Config(), today=TODAY)
    content = html.render_team(rebuilt, rebuilt.teams[0], Config())

    class TagCollector(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags: list[tuple[str, dict]] = []

        def handle_starttag(self, tag, attrs):
            self.tags.append((tag, dict(attrs)))

    collector = TagCollector()
    collector.feed(content)

    # Exactly one script element: the report's own filter logic.
    assert sum(1 for tag, _ in collector.tags if tag == "script") == 1
    assert not [tag for tag, _ in collector.tags if tag == "img"]

    # No event handler attribute anywhere in the document.
    handlers = [
        (tag, name)
        for tag, attrs in collector.tags
        for name in attrs
        if name.startswith("on")
    ]
    assert handlers == []


def test_html_stylesheet_is_not_escaped(bundle, config):
    """Autoescaping must not mangle our own CSS -- it silently breaks rules."""
    content = html.render_team(bundle, bundle.teams[0], config)
    assert "&#34;" not in content
    assert 'font-family: -apple-system' in content


def test_html_states_that_usage_data_is_missing(bundle, config):
    content = html.render_team(bundle, bundle.teams[0], config)
    assert "Usage data not included" in content


def test_html_combined_lists_every_team(bundle, config):
    content = html.render_combined(bundle, config)
    for report in bundle.teams:
        assert report.team.name in content


def test_html_writes_a_file(bundle, config, tmp_path):
    path = html.write_team(bundle, bundle.teams[0], tmp_path / "r.html", config)
    assert path.stat().st_size > 5000


def test_covered_rules_show_their_usage(config):
    """Usage belongs in the 'also cover you' section too, not only own rules."""
    from datetime import datetime

    from panorama_team_review.model import (
        AddressKind,
        AddressObject,
        HitCount,
        Location,
        SecurityRule,
        Snapshot,
        SnapshotMeta,
        Team,
    )

    loc = Location(source="t.xml", shared=True)
    rule = SecurityRule(
        name="central-inbound",
        location=Location(source="t.xml", device_group="DG"),
        source=ResolvedAddresses(raw=["outside"]),
        destination=ResolvedAddresses(raw=["big"]),
    )
    rule.hits = HitCount(hit_count=99, last_hit=datetime.now())
    snap = Snapshot(
        meta=SnapshotMeta(source_file="t.xml", parsed_at=datetime(2026, 7, 28)),
        addresses=[
            AddressObject(name="big", kind=AddressKind.IP_NETMASK,
                          value="10.0.0.0/16", location=loc),
            AddressObject(name="outside", kind=AddressKind.IP_NETMASK,
                          value="192.168.0.0/24", location=loc),
        ],
        rules=[rule],
    )
    team = Team(id="small", name="Small", assets=["10.0.5.0/24"])
    bundle = build_report(snap, [team], config, today=TODAY)
    report = next(r for r in bundle.teams if r.team.id == "small")

    assert report.covered_views, "the rule should cover the small team"
    content = html.render_team(bundle, report, config)
    section = content.split("Rules that also cover your networks", 1)[1]
    assert "99 hits" in section
    assert "last today" in section


def test_html_puts_the_networks_before_the_rules(bundle, config):
    """The asset list is the premise the rest of the report rests on.

    Everything below follows from which networks are considered the team's, so
    a reader who spots a wrong entry there can stop rather than working
    through rules that were never theirs.
    """
    content = html.render_team(bundle, bundle.teams[0], config)
    assert content.index("Your networks") < content.index("Your rules")


def test_html_separates_own_rules_from_covering_ones(bundle, config):
    report = next(r for r in bundle.teams if r.team.id == "platform")
    content = html.render_team(bundle, report, config)
    assert "Your rules" in content
    if report.covered_views:
        assert "Rules that also cover your networks" in content
        assert "Nothing is being asked of you here" in content


def test_html_groups_rules_into_policy_blocks(bundle, config):
    report = next(r for r in bundle.teams if r.team.id == "platform")
    content = html.render_team(bundle, report, config)
    assert 'class="scope-row"' in content
    assert "rules in this block concern you" in content
    for scope in bundle.scopes:
        if any(v.scope_id == scope.id for v in report.all_views):
            assert scope.title in content


def test_html_names_the_configuration_only_for_a_single_document(bundle, config):
    """A Panorama archive holds a document per firewall; listing them says nothing."""
    single = html.render_team(bundle, bundle.teams[0], config)
    assert "Configuration:" in single

    bundle.meta.source_files = [f"backup.tgz:fw{n:02d}.xml" for n in range(20)]
    many = html.render_team(bundle, bundle.teams[0], config)
    assert "Configuration:" not in many
    assert "backup.tgz" in many, "the footer still names the backup for the audit trail"


def test_html_does_not_show_the_panos_version(bundle, config):
    """It differs across the firewalls one report covers, and decides nothing."""
    bundle.meta.pan_os_version = "11.1.0"
    content = html.render_team(bundle, bundle.teams[0], config)
    assert "PAN-OS" not in content


def test_html_covering_rules_carry_no_severity_badges(bundle, config):
    """No counters, no badges: the section must not read as a task list."""
    report = max(bundle.teams, key=lambda r: len(r.covered_views))
    if not report.covered_views:
        pytest.skip("no covering rules in this fixture")
    content = html.render_team(bundle, report, config)

    found = False
    for marker in ("covered-inbound", "covered-outbound", "covered-other"):
        anchor = f'data-section="{marker}"'
        if anchor not in content:
            continue
        found = True
        section = content[content.index(anchor):]
        section = section[: section.index("</section>")]
        assert "sev-" not in section
        assert "Findings" not in section
    assert found, "covering rules exist but no section was rendered for them"


def test_html_splits_covering_rules_by_direction(bundle, config):
    """'Who may reach me' and 'what may I reach' stay different questions."""
    report = max(bundle.teams, key=lambda r: len(r.covered_views))
    if not report.covered_views:
        pytest.skip("no covering rules in this fixture")
    content = html.render_team(bundle, report, config)
    for direction, marker in (
        ("inbound", "covered-inbound"),
        ("outbound", "covered-outbound"),
    ):
        if report.covered(direction):
            assert f'data-section="{marker}"' in content


def test_html_sections_collapse_and_link_back(bundle, config):
    content = html.render_team(bundle, bundle.teams[0], config)
    assert 'class="collapsible"' in content
    assert "button.collapse" in content or 'class="collapse"' in content
    assert 'href="#top"' in content
    assert '<a id="top">' in content


def test_html_addresses_are_named_with_the_networks_behind_them(panorama_snapshot, teams, config):
    """The name is what a change request cites; the addresses are the tooltip."""
    bundle = build_report(panorama_snapshot, teams, config, today=TODAY)
    report = next(r for r in bundle.teams if r.team.id == "platform")
    content = html.render_team(bundle, report, config)

    named = [v for v in report.all_views if any(m.networks for m in v.rule.source.members)]
    assert named, "the fixture uses address objects, not only literals"
    assert 'class="named" title=' in content

    member = next(m for m in named[0].rule.source.members if m.networks and not m.is_literal)
    assert member.name in content


def test_html_marks_blocking_rules(panorama_snapshot, teams, config):
    """A deny must not read like an allow at a glance."""
    denied = next(
        (r for r in panorama_snapshot.rules if not r.action.permits_traffic), None
    )
    if denied is None:
        pytest.skip("the fixture has no blocking rule")
    bundle = build_report(panorama_snapshot, teams, config, today=TODAY)
    for report in bundle.teams:
        if any(v.rule.name == denied.name for v in report.all_views):
            content = html.render_team(bundle, report, config)
            assert "action-block" in content
            return


def test_html_lists_the_objects_inside_the_teams_networks(bundle, config):
    report = next(r for r in bundle.teams if r.team.id == "platform")
    assert report.objects, "the fixture defines address objects inside 10.10.0.0/16"
    content = html.render_team(bundle, report, config)
    assert "Objects and groups inside your networks" in content
    assert report.objects[0].name in content


def test_html_highlights_the_network_that_explains_the_rule(panorama_snapshot, config):
    """The stated reason has to point at something visible in the address list.

    Built against a team owning a single host, which is the case where the
    explanation is hardest to follow: the rule names a /16 the reader does not
    recognise, and one entry in it is theirs.
    """
    from panorama_team_review.model import Team

    host_team = Team(id="one-host", name="One Host", assets=["10.10.1.7/32"])
    bundle = build_report(panorama_snapshot, [host_team], config, today=TODAY)
    report = bundle.teams[0]

    view = next((v for v in report.covered_views if v.highlight_networks), None)
    assert view is not None, "a rule naming 10.10.0.0/16 must cover a host inside it"

    content = html.render_team(bundle, report, config)
    assert f"<strong>{view.highlight_networks[0]}</strong>" in content
    assert "lies inside" in content


def test_html_does_not_label_a_date_as_unknown(panorama_snapshot, teams, config):
    """'Unknown date' reads as though the date were unreadable. It is not."""
    bundle = build_report(panorama_snapshot, teams, config, today=TODAY)
    for report in bundle.teams:
        content = html.render_team(bundle, report, config)
        assert "Unknown date" not in content


def test_html_ticket_links_are_rendered(panorama_snapshot, teams, tmp_path):
    from panorama_team_review.config import MetadataConfig, TicketPattern

    config = Config(
        metadata=MetadataConfig(
            ticket_patterns=[
                TicketPattern(
                    name="snow",
                    regex=r"\b(?P<id>CHG\d{7})\b",
                    url_template="https://tickets.example.com/{id}",
                )
            ]
        )
    )
    bundle = build_report(panorama_snapshot, teams, config, today=TODAY)
    content = html.render_team(bundle, bundle.teams[0], config)
    assert "https://tickets.example.com/CHG" in content


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------


def test_excel_workbook_has_the_expected_sheets(bundle, config, tmp_path):
    path = excel.write_team_workbook(bundle, bundle.teams[0], tmp_path / "r.xlsx", config)
    with zipfile.ZipFile(path) as archive:
        workbook = archive.read("xl/workbook.xml").decode("utf-8")
    for sheet in ("Overview", "Inbound", "Outbound", "Findings", "Your networks"):
        assert sheet in workbook


def test_excel_inbound_columns_lead_with_the_far_side():
    """Inbound rows read far-side-first, the same logical order as the HTML report."""
    default = [name for name, _ in excel._rule_columns(peers_first=False)]
    inbound = [name for name, _ in excel._rule_columns(peers_first=True)]
    assert default.index("Your networks") < default.index("Peer (other side)")
    assert inbound.index("Peer (other side)") < inbound.index("Your networks")
    # Only the own/peer block moves; every other column, Usage included, stays.
    assert default[: excel._OWN_BLOCK] == inbound[: excel._OWN_BLOCK]
    assert default[excel._OWN_BLOCK + 4 :] == inbound[excel._OWN_BLOCK + 4 :]


def test_excel_combined_workbook_is_written(bundle, config, tmp_path):
    path = excel.write_combined_workbook(bundle, tmp_path / "all.xlsx", config)
    assert path.stat().st_size > 5000
    with zipfile.ZipFile(path) as archive:
        assert "xl/workbook.xml" in archive.namelist()


def test_excel_is_a_valid_zip(bundle, config, tmp_path):
    path = excel.write_team_workbook(bundle, bundle.teams[0], tmp_path / "r.xlsx", config)
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None


def test_excel_sheet_names_are_sanitised():
    assert excel._safe_sheet_name("a" * 50) == "a" * 31
    assert "[" not in excel._safe_sheet_name("a[b]c")
    assert excel._safe_sheet_name("") == "Sheet"


def test_excel_handles_a_team_with_no_rules(bundle, config, tmp_path):
    empty = next((r for r in bundle.teams if r.rule_count == 0), None)
    if empty is None:
        pytest.skip("no empty team in this fixture")
    path = excel.write_team_workbook(bundle, empty, tmp_path / "empty.xlsx", config)
    assert path.exists()


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


def test_pdf_print_html_renders_without_weasyprint(bundle, config):
    """The template is testable even where the PDF toolchain is unavailable."""
    content = pdf.render_team_html(bundle, bundle.teams[0], config)
    assert bundle.teams[0].team.name in content
    assert "@page" in content


def test_pdf_print_stylesheet_is_not_escaped(bundle, config):
    content = pdf.render_team_html(bundle, bundle.teams[0], config)
    assert "&#34;" not in content
    assert 'counter(page)' in content


def test_pdf_inbound_table_leads_with_the_far_side(bundle, config):
    """Inbound rows read far-side-first, the same logical order as the HTML report."""
    report = next((r for r in bundle.teams if r.own("inbound")), None)
    assert report is not None, "the fixture needs a team with inbound rules"
    content = pdf.render_team_html(bundle, report, config)
    inbound = content.split("Inbound — who reaches your networks", 1)[1].split("Outbound —", 1)[0]
    assert inbound.index("Other side") < inbound.index("Your networks")


@pytest.mark.needs_pdf
def test_pdf_is_written(bundle, config, tmp_path):
    if not pdf.available():
        pytest.skip("weasyprint not available")
    path = pdf.write_team(bundle, bundle.teams[0], tmp_path / "r.pdf", config)
    assert path.read_bytes().startswith(b"%PDF")


@pytest.mark.needs_pdf
def test_pdf_combined_is_written(bundle, config, tmp_path):
    if not pdf.available():
        pytest.skip("weasyprint not available")
    path = pdf.write_combined(bundle, tmp_path / "all.pdf", config)
    assert path.read_bytes().startswith(b"%PDF")


def test_missing_weasyprint_gives_an_actionable_message(monkeypatch, bundle, config, tmp_path):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "weasyprint":
            raise ImportError("no module named weasyprint")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    from panorama_team_review.errors import RenderError

    with pytest.raises(RenderError, match="pip install"):
        pdf.write_team(bundle, bundle.teams[0], tmp_path / "r.pdf", config)


def _section_table(content: str, section: str) -> tuple[list[str], list[list[str]]]:
    """Column headings and cell text of one section's first rules."""
    import html as html_module
    import re

    block = content[content.index(f'data-section="{section}"'):]
    block = block[: block.index("</section>")]

    def strip(markup: str) -> str:
        return " ".join(html_module.unescape(re.sub(r"<[^>]+>", " ", markup)).split())

    head = block[: block.index("</thead>")]
    headers = [strip(cell) for cell in re.findall(r"<th[^>]*>(.*?)</th>", head, re.S)]
    rows = [
        [strip(cell) for cell in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]
        for row in re.findall(r'<tr class="rule-row.*?</tr>', block, re.S)
    ]
    return headers, rows


def test_html_reads_in_the_direction_of_travel(bundle, config):
    """Inbound puts the far side first, outbound puts your networks first.

    A row describing who reaches you should read left to right in the order
    the traffic moves; the alternative makes the reader reverse it on every
    line.

    Both the heading *and* the cell under it are checked. Swapping only the
    headings is worse than not swapping at all -- every inbound row then
    labels the team's own networks as the far side -- and a test that looks at
    the headings alone passes just as happily either way.
    """
    report = next(r for r in bundle.teams if r.team.id == "platform")
    content = html.render_team(bundle, report, config)

    for section, direction, expected in (
        ("own-inbound", "inbound", ["Other side", "Your networks"]),
        ("own-outbound", "outbound", ["Your networks", "Other side"]),
    ):
        views = report.own(direction)
        if not views:
            continue
        headers, rows = _section_table(content, section)
        pair = [h for h in headers if h in ("Your networks", "Other side")]
        assert pair == expected, f"{section} headings"

        own_column = headers.index("Your networks")
        peer_column = headers.index("Other side")
        view = views[0]
        own_field = view.rule.source if direction == "outbound" else view.rule.destination
        far_field = view.rule.destination if direction == "outbound" else view.rule.source

        assert any(member.name in rows[0][own_column] for member in own_field.members), (
            f"{section}: the cell under 'Your networks' names nothing from the rule's "
            f"{'source' if direction == 'outbound' else 'destination'}"
        )
        if far_field.members:
            assert any(member.name in rows[0][peer_column] for member in far_field.members), (
                f"{section}: the cell under 'Other side' names nothing from the far side"
            )


def test_html_keeps_the_line_breaks_of_a_description(panorama_snapshot, teams, config):
    """A change log run into one paragraph reads as a different history."""
    panorama_snapshot.rules[0].description = "CHG0041201 first line\nCHG0041202 second line"
    bundle = build_report(panorama_snapshot, teams, config, today=TODAY)
    for report in bundle.teams:
        if any(v.rule.name == panorama_snapshot.rules[0].name for v in report.all_views):
            content = html.render_team(bundle, report, config)
            assert 'class="pre"' in content
            assert "CHG0041201 first line\nCHG0041202 second line" in content
            return


def test_html_lists_one_network_name_once(bundle, config):
    """Several of a team's networks routinely share one inventory label."""
    report = next(r for r in bundle.teams if r.team.id == "platform")
    view = next((v for v in report.own_views if len(v.matched_assets) > 1), None)
    if view is None:
        pytest.skip("no rule matching more than one asset in this fixture")
    from panorama_team_review.report import format as fmt

    cells = fmt.asset_cells(view, dict.fromkeys(view.matched_assets, "shared-label"))
    assert [c.label for c in cells] == ["shared-label"]


def test_the_own_side_cell_names_an_object_the_rule_actually_uses(bundle):
    """The regression this column was rewritten for.

    It used to show the inventory's name for the team's network. On a derived
    inventory that is the address group the team was *created from*, and a rule
    naming a different object then had its cell announce a name the rule never
    mentions -- which a reader would quote in a change request against the
    wrong object, with nothing in the report to contradict them.
    """
    from panorama_team_review.report import format as fmt

    checked = 0
    for report in bundle.teams:
        for direction in ("inbound", "outbound"):
            for view in report.own(direction):
                field = view.rule.source if direction == "outbound" else view.rule.destination
                if field.is_any or not field.members:
                    continue
                names = {member.name for member in field.members}
                for cell in fmt.asset_cells(view, report.team.asset_labels):
                    # Either an object of the rule, or one of the team's own
                    # networks where the rule names no covering object at all.
                    assert cell.label in names or cell.label in view.matched_assets, (
                        f"{view.rule.name}: 'Your networks' shows {cell.label!r}, which the "
                        f"rule does not name (it names {sorted(names)})"
                    )
                    checked += 1
    assert checked, "the fixture has rules matched through address objects"


def test_the_own_side_cell_says_which_network_it_covers(bundle):
    """The object is usually wider than the reader's network; the tooltip says so."""
    from panorama_team_review.report import format as fmt

    for report in bundle.teams:
        for view in report.own("inbound"):
            if view.rule.destination.is_any or not view.matched_assets:
                continue
            cells = fmt.asset_cells(view, report.team.asset_labels)
            named = [c for c in cells if c.detail.startswith("Covers your")]
            if not named:
                continue
            assert any(asset in named[0].detail for asset in view.matched_assets)
            return


def test_the_table_wrapper_does_not_swallow_the_sticky_header():
    """A CSS assertion, because the failure is invisible in the markup.

    `position: sticky` attaches to the nearest scroll container. Giving the
    wrapper around a table `overflow-x: auto` makes it one -- and since the
    wrapper has no height limit it never scrolls vertically, so the header row
    sticks to something that cannot move and scrolls away with the table. The
    HTML is identical either way, so nothing else here can catch it.

    The capped lists are the deliberate exception: those scroll on their own,
    and their header sticks to the top of the box.
    """
    import re

    from panorama_team_review.report.html import TEMPLATE_DIR

    css = (TEMPLATE_DIR / "base.css").read_text(encoding="utf-8")
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)

    blocks = dict(re.findall(r"([^{}]+)\{([^}]*)\}", css))
    for selector, body in blocks.items():
        selector = " ".join(selector.split())
        if "table-scroll" not in selector or "capped" in selector:
            continue
        # `visible` is fine and is what the print stylesheet asks for; only the
        # values that create a scroll container do the damage.
        swallowing = re.findall(r"overflow[-xy]*\s*:\s*(auto|scroll|hidden)", body)
        assert not swallowing, (
            f"{selector} sets overflow: {swallowing[0]}; that makes it the scroll "
            "container and the sticky column header stops working"
        )

    header = next(body for sel, body in blocks.items() if sel.strip() == "thead th")
    assert "position: sticky" in header
    assert "--header-h" in header, "the header must clear the sticky page header"


def test_combined_report_can_expand_a_rule_without_an_owner(bundle, config):
    """The section that says the inventory is incomplete has to be readable.

    A rule listed there is one nobody could attribute; deciding *whose* it is
    means seeing the object names and what they resolve to, which is what the
    expanded detail holds.
    """
    if not bundle.unassigned:
        pytest.skip("every rule was attributed in this fixture")
    content = html.render_combined(bundle, config)
    section = content[content.index('id="s-unassigned"'):]
    section = section[: section.index("</section>")]
    assert 'class="toggle"' in section
    assert 'class="detail-row' in section
    assert "Source objects" in section, "the expanded panel must carry the object names"


def test_combined_report_offers_the_same_navigation(bundle, config):
    content = html.render_combined(bundle, config)
    assert '<a id="top">' in content
    assert 'class="jump"' in content
    assert 'href="#s-teams"' in content
    assert 'class="collapsible"' in content
    assert 'id="page-header"' in content, "the header must stick, as in a team report"


def test_the_overview_sorts_ahead_of_the_team_reports():
    """A hundred files share the date prefix; the overview must not be lost."""
    from panorama_team_review.config import OutputConfig

    output = OutputConfig()
    overview = output.combined_filename_template.format(date="2026-07-30")
    for team_id in ("adapters-p", "1e-rnd-prod", "Zebra", "_infra"):
        team = output.filename_template.format(
            date="2026-07-30", team_id=team_id, team_name=team_id
        )
        assert sorted([overview, team])[0] == overview, f"{team} sorts before the overview"


def test_a_long_peer_team_list_collapses_to_a_count():
    """An estate-wide rule answers with every team in the inventory.

    A hundred ids in one cell wrap over a dozen lines and push the rest of the
    row off the page, and say nothing the count does not.
    """
    from panorama_team_review.model import Location, RuleView, SecurityRule
    from panorama_team_review.report import format as fmt

    rule = SecurityRule(name="endpoints", location=Location(source="x"))
    few = RuleView(rule=rule, direction="outbound", peer_teams=["alpha", "beta"])
    many = RuleView(
        rule=rule, direction="outbound", peer_teams=[f"team-{i}" for i in range(60)]
    )

    assert fmt.peer_team_cell(few).label == "alpha, beta"
    assert fmt.peer_team_cell(few).detail == ""

    cell = fmt.peer_team_cell(many)
    assert cell.label == "60 teams"
    assert "team-0" in cell.detail, "the names stay available in the tooltip"
    assert len(cell.label) < 20

    assert fmt.peer_team_cell(RuleView(rule=rule, direction="outbound")) is None


# ---------------------------------------------------------------------------
# Object-name highlighting
# ---------------------------------------------------------------------------


def test_object_names_fall_back_to_the_raw_field_without_a_breakdown():
    """A rule whose objects never resolved must still name them.

    ``members`` is empty whenever resolution failed -- an external dynamic list,
    a group defined on a device whose configuration is not in the backup. The
    object name is then the only thing the report can offer, and dropping it
    would leave an empty cell where the rule's whole subject belongs.
    """
    field = ResolvedAddresses(raw=["grp-unresolved", "ext-list-partners"])
    rendered = html._highlight_objects(field, highlight=[])
    assert "grp-unresolved" in rendered
    assert "ext-list-partners" in rendered
    assert "<strong>" not in rendered


def test_object_names_bold_only_the_member_that_matched():
    field = ResolvedAddresses(
        raw=["grp-payments", "grp-other"],
        networks=["10.20.12.0/24", "10.99.0.0/16"],
        members=[
            AddressMember(name="grp-payments", networks=["10.20.12.0/24"]),
            AddressMember(name="grp-other", networks=["10.99.0.0/16"]),
        ],
    )
    rendered = html._highlight_objects(field, highlight=["10.20.12.0/24"])
    assert "<strong>grp-payments</strong>" in rendered
    assert "<strong>grp-other</strong>" not in rendered
    assert "grp-other" in rendered


def test_object_names_of_an_empty_field_render_to_nothing():
    """Neither members nor raw: an empty cell, not a crash or a stray marker."""
    assert html._highlight_objects(ResolvedAddresses(), highlight=[]) == ""
    assert html._highlight_objects(ResolvedAddresses(is_any=True), highlight=[]) == "any"
