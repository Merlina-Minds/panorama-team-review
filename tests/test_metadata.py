"""Ticket, date and requester extraction from rule descriptions.

These patterns are the tool's bridge between a firewall configuration and an
organisation's change process, and they are the part most likely to be
customised, so the configurable surface is tested rather than the defaults
alone.
"""

from __future__ import annotations

from datetime import date

import pytest

from panorama_team_review.config import DatePattern, MetadataConfig, TicketPattern
from panorama_team_review.enrich.metadata import MetadataExtractor


def extractor(**kwargs) -> MetadataExtractor:
    return MetadataExtractor(MetadataConfig(**kwargs))


# ---------------------------------------------------------------------------
# Tickets
# ---------------------------------------------------------------------------


def test_extracts_jira_style_ticket():
    result = extractor().extract("NETSEC-4711 open https for the shop", [])
    assert [t.id for t in result.tickets] == ["NETSEC-4711"]


def test_builds_ticket_url_from_template():
    config = MetadataConfig(
        ticket_patterns=[
            TicketPattern(
                name="jira",
                regex=r"\b(?P<id>[A-Z]+-\d+)\b",
                url_template="https://jira.example.com/browse/{id}",
            )
        ]
    )
    result = MetadataExtractor(config).extract("NETSEC-4711 access", [])
    assert result.tickets[0].url == "https://jira.example.com/browse/NETSEC-4711"


def test_ticket_without_url_template_still_extracts():
    config = MetadataConfig(
        ticket_patterns=[TicketPattern(name="plain", regex=r"\bCHG(?P<id>\d+)\b")]
    )
    result = MetadataExtractor(config).extract("CHG0012345 standard change", [])
    assert result.tickets[0].id == "0012345"
    assert result.tickets[0].url is None


def test_extracts_multiple_distinct_tickets():
    result = extractor().extract("NETSEC-1 supersedes NETSEC-2 for this rule", [])
    assert {t.id for t in result.tickets} == {"NETSEC-1", "NETSEC-2"}


def test_duplicate_ticket_is_reported_once():
    result = extractor().extract("NETSEC-1 see also NETSEC-1", [])
    assert len(result.tickets) == 1


def test_ticket_found_in_a_tag():
    config = MetadataConfig(
        ticket_patterns=[
            TicketPattern(name="jira", regex=r"\b(?P<id>[A-Z]+-\d+)\b", fields=["tag"])
        ]
    )
    result = MetadataExtractor(config).extract("", ["NETSEC-99"])
    assert result.tickets[0].id == "NETSEC-99"
    assert result.tickets[0].source_field == "tag"


def test_field_restriction_is_honoured():
    """A pattern limited to tags must not fire on the description."""
    config = MetadataConfig(
        ticket_patterns=[
            TicketPattern(name="jira", regex=r"\b(?P<id>[A-Z]+-\d+)\b", fields=["tag"])
        ]
    )
    assert MetadataExtractor(config).extract("NETSEC-99 in description", []).tickets == []


def test_url_template_referencing_an_unknown_group_is_rejected():
    """Caught at config load time, not at render time on a customer's report."""
    with pytest.raises(ValueError, match="url_template references"):
        TicketPattern(
            name="broken",
            regex=r"(?P<id>\d+)",
            url_template="https://example.com/{project}/{id}",
        )


def test_ticket_pattern_without_id_group_is_rejected():
    with pytest.raises(ValueError, match="named group"):
        TicketPattern(name="broken", regex=r"\d+")


def test_invalid_regex_is_rejected():
    with pytest.raises(ValueError, match="invalid regex"):
        TicketPattern(name="broken", regex=r"(?P<id>[unclosed")


# ---------------------------------------------------------------------------
# Dates
# ---------------------------------------------------------------------------


def test_extracts_expiry_from_valid_until():
    result = extractor().extract("CHG1 temporary access, valid until 31.12.2026", [])
    assert result.expires_on == date(2026, 12, 31)


def test_extracts_creation_date():
    result = extractor().extract("CHG1 access, created 04.02.2024", [])
    assert result.created_on == date(2024, 2, 4)


def test_distinguishes_creation_from_expiry_in_one_description():
    result = extractor().extract(
        "CHG1 created 01.03.2024, valid until 31.12.2026", []
    )
    assert result.created_on == date(2024, 3, 1)
    assert result.expires_on == date(2026, 12, 31)


def test_iso_dates_are_recognised():
    result = extractor().extract("Access expires 2026-12-31", [])
    assert result.expires_on == date(2026, 12, 31)


def test_single_digit_day_and_month():
    result = extractor().extract("valid until 1.3.2027", [])
    assert result.expires_on == date(2027, 3, 1)


def test_date_without_a_keyword_has_no_role():
    result = extractor().extract("Something happened 15.06.2025", [])
    assert result.expires_on is None
    assert result.created_on is None
    assert result.dates[0].role == "unknown"


def test_nearest_keyword_wins():
    """'created ... until X' -- the date belongs to 'until', not 'created'."""
    result = extractor().extract("created for the project, valid until 31.12.2026", [])
    assert result.expires_on == date(2026, 12, 31)


def test_keyword_outside_the_window_is_ignored():
    config = MetadataConfig(
        date_patterns=[
            DatePattern(
                name="dot", regex=r"\b\d{1,2}\.\d{1,2}\.\d{4}\b",
                date_format="%d.%m.%Y", keyword_window=10,
            )
        ]
    )
    long_gap = "expires " + "x" * 50 + " 31.12.2026"
    assert MetadataExtractor(config).extract(long_gap, []).expires_on is None


def test_custom_role_keywords_in_another_language():
    """Descriptions are written in whatever language the estate uses."""
    config = MetadataConfig(
        role_keywords={"expires": ["gültig bis", "bis"], "created": ["erstellt"]}
    )
    result = MetadataExtractor(config).extract("Zugang gültig bis 31.12.2026", [])
    assert result.expires_on == date(2026, 12, 31)


# ---------------------------------------------------------------------------
# Shared role keywords across date formats
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("valid until 2026-12-31", date(2026, 12, 31)),
        ("valid until 31.12.2026", date(2026, 12, 31)),
        ("expires 2026-12-31", date(2026, 12, 31)),
        ("temp until 2026-12-31", date(2026, 12, 31)),
    ],
)
def test_iso_and_dotted_dates_are_both_recognised(text, expected):
    """ISO is the common convention and must work out of the box."""
    assert extractor().extract(f"CHG0001 {text}", []).expires_on == expected


def test_role_keywords_apply_to_every_date_format():
    """One keyword list covers all formats.

    The words around a date do not change because the date is written
    differently. Requiring the list per pattern meant an estate using both
    formats had to maintain it twice, and silently recognised only the one
    whose list happened to be filled in.
    """
    config = MetadataConfig(role_keywords={"expires": ["gueltig bis"]})
    instance = MetadataExtractor(config)
    assert instance.extract("gueltig bis 2026-12-31", []).expires_on == date(2026, 12, 31)
    assert instance.extract("gueltig bis 31.12.2026", []).expires_on == date(2026, 12, 31)
    assert instance.extract("gueltig bis 31/12/2026", []).expires_on == date(2026, 12, 31)


def test_a_pattern_may_override_the_shared_keywords():
    config = MetadataConfig(
        role_keywords={"expires": ["until"]},
        date_patterns=[
            DatePattern(name="iso", regex=r"\b\d{4}-\d{2}-\d{2}\b", date_format="%Y-%m-%d"),
            DatePattern(
                name="dot-dmy", regex=r"\b\d{1,2}\.\d{1,2}\.\d{4}\b", date_format="%d.%m.%Y",
                role_keywords={"expires": ["bis"]},
            ),
        ],
    )
    instance = MetadataExtractor(config)
    # The ISO pattern uses the shared list, the dotted one its own.
    assert instance.extract("until 2026-12-31", []).expires_on == date(2026, 12, 31)
    assert instance.extract("bis 2026-12-31", []).expires_on is None
    assert instance.extract("bis 31.12.2026", []).expires_on == date(2026, 12, 31)
    assert instance.extract("until 31.12.2026", []).expires_on is None


def test_shipped_example_recognises_both_formats_in_german_and_english():
    """The configuration users start from must handle the common cases."""
    from pathlib import Path

    from panorama_team_review.config import load_config

    example = Path(__file__).resolve().parent.parent / "config" / "config.example.yaml"
    instance = MetadataExtractor(load_config(example).metadata)

    for text in ("valid until 2026-12-31", "gueltig bis 2026-12-31",
                 "gueltig bis 31.12.2026", "bis 2026-12-31"):
        assert instance.extract(f"CHG0001234 {text}", []).expires_on == date(2026, 12, 31), text

    for text in ("created 2024-03-01", "beantragt 2024-03-01", "erstellt 01.03.2024"):
        assert instance.extract(f"CHG0001234 {text}", []).created_on == date(2024, 3, 1), text


def test_impossible_date_is_ignored():
    assert extractor().extract("valid until 31.02.2026", []).expires_on is None


def test_earliest_expiry_wins_when_several_are_present():
    result = extractor().extract("valid until 31.12.2026, expires 01.06.2026", [])
    assert result.expires_on == date(2026, 6, 1)


# ---------------------------------------------------------------------------
# Requester
# ---------------------------------------------------------------------------


def test_extracts_requester():
    result = extractor().extract("CHG1 access, requested by A. Example", [])
    assert result.requester == "A. Example"


def test_requester_pattern_needs_its_named_group():
    with pytest.raises(ValueError, match="named group"):
        MetadataConfig(requester_patterns=[r"requested by (\w+)"])


def test_no_requester_yields_none():
    assert extractor().extract("CHG1 plain description", []).requester is None


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_empty_description_is_safe():
    result = extractor().extract("", [])
    assert result.tickets == [] and result.dates == [] and result.requester is None


def test_realistic_combined_description():
    """The shape these fields actually take in production."""
    text = (
        "CHG0041234 open 443 for payment gw, requested by A. Beck, "
        "valid until 31.12.2026"
    )
    config = MetadataConfig(
        ticket_patterns=[
            TicketPattern(
                name="snow",
                regex=r"\b(?P<id>CHG\d{7})\b",
                url_template="https://example.service-now.com/{id}",
            )
        ]
    )
    result = MetadataExtractor(config).extract(text, [])
    assert result.tickets[0].id == "CHG0041234"
    assert result.tickets[0].url == "https://example.service-now.com/CHG0041234"
    assert result.requester == "A. Beck"
    assert result.expires_on == date(2026, 12, 31)


# ---------------------------------------------------------------------------
# Change notes: dates whose meaning comes from position, not wording
# ---------------------------------------------------------------------------

CHANGE_PATTERNS = [
    r"\((?P<requester>[A-Za-z][\w.-]{1,29})\s*[:,]?\s*(?P<date>\d{4}-\d{2}-\d{2})\)",
    r"\b(?P<requester>[a-z][a-z0-9._-]{2,29})\s+(?P<date>\d{4}-\d{2}-\d{2})\b",
]


def _with_change_patterns():
    from panorama_team_review.config import MetadataConfig
    from panorama_team_review.enrich.metadata import MetadataExtractor

    return MetadataExtractor(MetadataConfig(change_patterns=CHANGE_PATTERNS))


def test_a_parenthesised_change_note_names_the_editor_and_the_date():
    """'CHG0041234 (a.beck: 2024-05-30)' -- who touched the rule, and when."""
    metadata = _with_change_patterns().extract("CHG0041234 (a.beck: 2024-05-30)", [])
    entry = next(d for d in metadata.dates if d.role == "changed")
    assert entry.value.isoformat() == "2024-05-30"
    assert entry.by == "a.beck"


def test_the_editor_is_not_reported_as_the_requester():
    """The administrator who made a change is rarely the person who wanted it.

    'CHG0041299 a.beck 2027-07-18' says a.beck edited the rule. Reporting that as
    "requested by a.beck" states something the description never said.
    """
    metadata = _with_change_patterns().extract("CHG0041299 a.beck 2027-07-18", [])
    assert metadata.requester is None
    assert metadata.latest_change.by == "a.beck"


def test_a_bare_change_note_is_recognised_too():
    metadata = _with_change_patterns().extract("CHG0041299 a.beck 2027-07-18", [])
    entry = next(d for d in metadata.dates if d.role == "changed")
    assert entry.value.isoformat() == "2027-07-18"
    assert entry.by == "a.beck"


def test_a_keyword_beats_a_positional_pattern():
    """The regression this ordering exists for.

    A pattern loose enough to catch a bare username also matches the word
    before any date, so run first it reads 'valid until 2026-12-31' as
    'changed by until' -- turning an expiry into an edit and silencing
    EXPIRED_RULE with it.
    """
    metadata = _with_change_patterns().extract("open 443, valid until 2026-12-31", [])
    roles = {d.role for d in metadata.dates}
    assert roles == {"expires"}
    assert metadata.requester != "until"


def test_created_and_expires_keywords_survive_change_patterns():
    metadata = _with_change_patterns().extract(
        "CHG0041234 created 2024-01-05, expires 2027-01-01", []
    )
    assert {d.role: d.value.isoformat() for d in metadata.dates} == {
        "created": "2024-01-05",
        "expires": "2027-01-01",
    }


def test_without_change_patterns_nothing_is_guessed():
    """These conventions are positional; a default guess would misread estates."""
    from panorama_team_review.config import MetadataConfig
    from panorama_team_review.enrich.metadata import MetadataExtractor

    metadata = MetadataExtractor(MetadataConfig()).extract("CHG0041234 (a.beck: 2024-05-30)", [])
    assert [d.role for d in metadata.dates] == ["unknown"]


def test_a_change_keyword_is_recognised_without_any_pattern():
    from panorama_team_review.config import MetadataConfig
    from panorama_team_review.enrich.metadata import MetadataExtractor

    metadata = MetadataExtractor(MetadataConfig()).extract("modified 2024-05-30", [])
    assert [d.role for d in metadata.dates] == ["changed"]


def test_the_latest_change_is_the_one_reported():
    metadata = _with_change_patterns().extract(
        "CHG0041201 (alice: 2024-01-05) CHG0041202 (bob: 2025-03-09)", []
    )
    assert metadata.changed_on.isoformat() == "2025-03-09"


# ---------------------------------------------------------------------------
# One entry per line
# ---------------------------------------------------------------------------


def test_a_keyword_does_not_reach_across_a_line_break():
    """A description is a change log, one entry per line.

    Reading the words above the date takes them from a different entry, and
    the date then means what *that* entry meant -- here, turning an ordinary
    edit into an expiry, which would drive EXPIRED_RULE against a rule that
    never had one.
    """
    from panorama_team_review.config import MetadataConfig
    from panorama_team_review.enrich.metadata import MetadataExtractor

    metadata = MetadataExtractor(MetadataConfig()).extract(
        "CHG0041201 valid until 2026-12-31\nCHG0041202 rebuilt 2025-01-01", []
    )
    roles = {d.value.isoformat(): d.role for d in metadata.dates}
    assert roles["2026-12-31"] == "expires"
    assert roles["2025-01-01"] != "expires"


def test_a_change_note_does_not_pair_a_name_with_the_next_lines_date():
    metadata = _with_change_patterns().extract(
        "CHG0041301 a.beck\nCHG0041302 c.rivas 2026-07-13", []
    )
    entry = next(d for d in metadata.dates if d.role == "changed")
    assert entry.by == "c.rivas"


def test_only_the_latest_change_is_reported():
    """A description holding a whole history yields one entry per change."""
    metadata = _with_change_patterns().extract(
        "CHG0041201 alice 2024-01-05\nCHG0041202 bob 2025-03-09\nCHG0041203 carol 2024-11-01", []
    )
    assert metadata.change_count == 3
    assert metadata.latest_change.value.isoformat() == "2025-03-09"
    assert metadata.latest_change.by == "bob"
