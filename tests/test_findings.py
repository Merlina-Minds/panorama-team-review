"""Analysis checks.

The governing principle under test: a check that cannot be sure stays silent.
A report that flags a correct rule teaches its readers to ignore the report.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta

from panorama_team_review.analyze.findings import (
    available_checks,
    run_checks,
    unknown_checks,
)
from panorama_team_review.config import AnalysisConfig
from panorama_team_review.model import (
    DateRef,
    HitCount,
    Location,
    ResolvedAddresses,
    ResolvedServices,
    RuleAction,
    RuleMetadata,
    SecurityRule,
    TicketRef,
    Unresolved,
    UnresolvedReason,
)

TODAY = date(2026, 7, 28)


def make_rule(**kwargs) -> SecurityRule:
    defaults = {
        "name": "r1",
        "location": Location(source="t.xml", device_group="DG"),
        "source": ResolvedAddresses(networks=["10.1.1.0/24"], raw=["src"]),
        "destination": ResolvedAddresses(networks=["10.2.2.0/24"], raw=["dst"]),
        "services": ResolvedServices(ports=["tcp/443"], raw=["svc-https"]),
        "applications": ["ssl"],
        "description": "CHG0001 access",
        "metadata": RuleMetadata(tickets=[TicketRef(system="snow", id="CHG0001")]),
        "log_end": True,
    }
    defaults.update(kwargs)
    return SecurityRule(**defaults)


def codes(rules, config=None) -> set[str]:
    config = config or AnalysisConfig()
    results = run_checks(rules, config, TODAY)
    return {finding.code for findings in results.values() for finding in findings}


# ---------------------------------------------------------------------------
# Overly broad rules
# ---------------------------------------------------------------------------


def test_any_any_is_flagged():
    rule = make_rule(
        source=ResolvedAddresses(is_any=True), destination=ResolvedAddresses(is_any=True)
    )
    assert "ANY_ANY" in codes([rule])


def test_any_any_deny_is_not_flagged():
    """A catch-all deny is the recommended final rule, not a problem."""
    rule = make_rule(
        source=ResolvedAddresses(is_any=True),
        destination=ResolvedAddresses(is_any=True),
        action=RuleAction.DENY,
    )
    assert "ANY_ANY" not in codes([rule])


def test_any_any_disabled_is_not_flagged():
    rule = make_rule(
        source=ResolvedAddresses(is_any=True),
        destination=ResolvedAddresses(is_any=True),
        disabled=True,
    )
    assert "ANY_ANY" not in codes([rule])


def test_any_destination_alone_is_flagged():
    rule = make_rule(destination=ResolvedAddresses(is_any=True))
    found = codes([rule])
    assert "ANY_DESTINATION" in found
    assert "ANY_ANY" not in found


def test_any_source_alone_is_flagged():
    rule = make_rule(source=ResolvedAddresses(is_any=True))
    assert "ANY_SOURCE" in codes([rule])


def test_any_service_with_app_id_is_not_flagged():
    """App-ID constrains traffic even with service 'any' -- the vendor pattern."""
    rule = make_rule(services=ResolvedServices(is_any=True), applications=["ssl"])
    assert "ANY_SERVICE" not in codes([rule])


def test_any_service_without_app_id_is_flagged():
    rule = make_rule(services=ResolvedServices(is_any=True), applications=["any"])
    assert "ANY_SERVICE" in codes([rule])


def test_broad_network_is_flagged():
    rule = make_rule(source=ResolvedAddresses(networks=["10.0.0.0/8"], raw=["big"]))
    assert "BROAD_NETWORK" in codes([rule])


def test_broad_network_threshold_is_configurable():
    rule = make_rule(source=ResolvedAddresses(networks=["10.1.0.0/16"], raw=["net"]))
    assert "BROAD_NETWORK" not in codes([rule], AnalysisConfig(broad_network_prefix_v4=16))
    assert "BROAD_NETWORK" in codes([rule], AnalysisConfig(broad_network_prefix_v4=17))


def test_ipv6_uses_its_own_threshold():
    rule = make_rule(source=ResolvedAddresses(networks=["2001:db8::/32"], raw=["v6"]))
    assert "BROAD_NETWORK" in codes([rule])


# ---------------------------------------------------------------------------
# Documentation and lifecycle
# ---------------------------------------------------------------------------


def test_missing_description_is_flagged():
    rule = make_rule(description="", metadata=RuleMetadata())
    assert "NO_DESCRIPTION" in codes([rule])


def test_missing_ticket_does_not_double_report_with_missing_description():
    """One cause, one finding: two entries for an empty description is noise."""
    rule = make_rule(description="", metadata=RuleMetadata())
    found = codes([rule])
    assert "NO_DESCRIPTION" in found
    assert "NO_TICKET" not in found


def test_description_without_ticket_is_flagged():
    rule = make_rule(description="opened for the project", metadata=RuleMetadata())
    assert "NO_TICKET" in codes([rule])


def test_ticket_requirement_can_be_disabled():
    rule = make_rule(description="no ticket here", metadata=RuleMetadata())
    assert "NO_TICKET" not in codes([rule], AnalysisConfig(require_ticket=False))


def test_expired_rule_is_flagged():
    expired = TODAY - timedelta(days=45)
    rule = make_rule(
        metadata=RuleMetadata(dates=[DateRef(role="expires", value=expired, raw="x")])
    )
    assert "EXPIRED_RULE" in codes([rule])


def test_expiring_soon_is_flagged():
    soon = TODAY + timedelta(days=20)
    rule = make_rule(metadata=RuleMetadata(dates=[DateRef(role="expires", value=soon, raw="x")]))
    found = codes([rule])
    assert "EXPIRING_SOON" in found
    assert "EXPIRED_RULE" not in found


def test_expiry_far_away_is_not_flagged():
    far = TODAY + timedelta(days=400)
    rule = make_rule(metadata=RuleMetadata(dates=[DateRef(role="expires", value=far, raw="x")]))
    assert "EXPIRING_SOON" not in codes([rule])


def test_disabled_rule_is_reported_as_info():
    rule = make_rule(disabled=True)
    assert "DISABLED_RULE" in codes([rule])


def test_unlogged_rule_is_flagged():
    rule = make_rule(log_end=False, log_start=False)
    assert "NO_LOGGING" in codes([rule])


def test_log_start_alone_counts_as_logged():
    rule = make_rule(log_end=False, log_start=True)
    assert "NO_LOGGING" not in codes([rule])


# ---------------------------------------------------------------------------
# Usage checks: silent without hit counts
# ---------------------------------------------------------------------------


def test_unused_check_is_silent_without_hit_counts():
    """The critical case: never guess that a rule is unused."""
    rule = make_rule(hits=None)
    assert "UNUSED_RULE" not in codes([rule])


def test_unused_rule_is_flagged_with_hit_counts():
    rule = make_rule(
        hits=HitCount(hit_count=0, collected_at=datetime(2026, 7, 28), source="api:fw.example.com")
    )
    assert "UNUSED_RULE" in codes([rule])


def test_used_rule_is_not_flagged_as_unused():
    rule = make_rule(
        hits=HitCount(hit_count=5000, last_hit=datetime(2026, 7, 27),
                      collected_at=datetime(2026, 7, 28), source="api:fw")
    )
    assert "UNUSED_RULE" not in codes([rule])


def test_stale_rule_is_flagged():
    rule = make_rule(
        hits=HitCount(hit_count=10, last_hit=datetime(2025, 1, 1),
                      collected_at=datetime(2026, 7, 28), source="api:fw")
    )
    assert "STALE_RULE" in codes([rule])


def test_recently_used_rule_is_not_stale():
    rule = make_rule(
        hits=HitCount(hit_count=10, last_hit=datetime(2026, 7, 1),
                      collected_at=datetime(2026, 7, 28), source="api:fw")
    )
    assert "STALE_RULE" not in codes([rule])


def test_stale_threshold_is_configurable():
    rule = make_rule(
        hits=HitCount(hit_count=10, last_hit=datetime(2026, 5, 1),
                      collected_at=datetime(2026, 7, 28), source="api:fw")
    )
    assert "STALE_RULE" not in codes([rule], AnalysisConfig(stale_rule_days=180))
    assert "STALE_RULE" in codes([rule], AnalysisConfig(stale_rule_days=30))


# ---------------------------------------------------------------------------
# Object hygiene
# ---------------------------------------------------------------------------


def test_unresolved_object_is_reported():
    rule = make_rule(
        source=ResolvedAddresses(
            raw=["edl-feed"],
            unresolved=[Unresolved(name="edl-feed", reason=UnresolvedReason.UNKNOWN_OBJECT)],
        )
    )
    assert "UNRESOLVED_OBJECT" in codes([rule])


def test_fqdn_alone_is_not_an_unresolved_finding():
    """FQDNs are expected and shown separately; flagging them is noise."""
    rule = make_rule(
        destination=ResolvedAddresses(
            raw=["updates"], fqdns=["updates.example.com"],
            unresolved=[Unresolved(name="updates", reason=UnresolvedReason.FQDN)],
        )
    )
    assert "UNRESOLVED_OBJECT" not in codes([rule])


def test_empty_group_is_flagged():
    rule = make_rule(source=ResolvedAddresses(raw=["empty-group"]))
    assert "EMPTY_GROUP" in codes([rule])


def test_any_field_is_not_an_empty_group():
    rule = make_rule(source=ResolvedAddresses(is_any=True))
    assert "EMPTY_GROUP" not in codes([rule])


# ---------------------------------------------------------------------------
# Configuration of the check set
# ---------------------------------------------------------------------------


def test_only_enabled_checks_run():
    rule = make_rule(
        source=ResolvedAddresses(is_any=True), destination=ResolvedAddresses(is_any=True)
    )
    assert codes([rule], AnalysisConfig(enabled_checks=["ANY_ANY"])) == {"ANY_ANY"}


def test_ignore_tags_exempt_a_rule():
    rule = make_rule(
        source=ResolvedAddresses(is_any=True),
        destination=ResolvedAddresses(is_any=True),
        tags=["approved-exception"],
    )
    assert codes([rule], AnalysisConfig(ignore_tags=["approved-exception"])) == set()


def test_ignore_rule_patterns_exempt_a_rule():
    rule = make_rule(
        name="INFRA-catch-all",
        source=ResolvedAddresses(is_any=True),
        destination=ResolvedAddresses(is_any=True),
    )
    assert codes([rule], AnalysisConfig(ignore_rule_patterns=["^INFRA-"])) == set()


def test_unknown_check_codes_are_reported():
    config = AnalysisConfig(enabled_checks=["ANY_ANY", "NOT_A_REAL_CHECK"])
    assert unknown_checks(config) == ["NOT_A_REAL_CHECK"]


def test_unknown_check_codes_do_not_break_the_run():
    config = AnalysisConfig(enabled_checks=["ANY_ANY", "NOT_A_REAL_CHECK"])
    rule = make_rule(
        source=ResolvedAddresses(is_any=True), destination=ResolvedAddresses(is_any=True)
    )
    assert codes([rule], config) == {"ANY_ANY"}


def test_every_default_check_exists():
    """Guards against a typo in the shipped default configuration."""
    assert unknown_checks(AnalysisConfig()) == []


def test_findings_are_sorted_most_severe_first():
    rule = make_rule(
        source=ResolvedAddresses(is_any=True),
        destination=ResolvedAddresses(is_any=True),
        description="",
        metadata=RuleMetadata(),
        log_end=False,
    )
    results = run_checks([rule], AnalysisConfig(), TODAY)
    findings = next(iter(results.values()))
    ranks = [finding.severity.rank for finding in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_available_checks_is_not_empty():
    assert len(available_checks()) >= 10


def test_findings_carry_rule_location():
    rule = make_rule(
        source=ResolvedAddresses(is_any=True), destination=ResolvedAddresses(is_any=True)
    )
    results = run_checks([rule], AnalysisConfig(enabled_checks=["ANY_ANY"]), TODAY)
    finding = next(iter(results.values()))[0]
    assert finding.location == rule.location.label()
    assert finding.rule_name == rule.name


def test_rules_with_the_same_name_in_different_locations_stay_separate():
    """Rule names are unique per rulebase, not globally."""
    a = make_rule(
        name="dup", location=Location(source="t.xml", device_group="DG-A"),
        source=ResolvedAddresses(is_any=True), destination=ResolvedAddresses(is_any=True),
    )
    b = make_rule(
        name="dup", location=Location(source="t.xml", device_group="DG-B"),
        source=ResolvedAddresses(is_any=True), destination=ResolvedAddresses(is_any=True),
    )
    results = run_checks([a, b], AnalysisConfig(enabled_checks=["ANY_ANY"]), TODAY)
    assert len(results) == 2


# ---------------------------------------------------------------------------
# Rules that leave the estate
# ---------------------------------------------------------------------------


def _rule_to(zone: str, **kwargs):
    from panorama_team_review.model import Location, ResolvedAddresses, SecurityRule

    return SecurityRule(
        name=kwargs.pop("name", "egress"),
        location=Location(source="test"),
        source=ResolvedAddresses(raw=["clients"], networks=["10.1.0.0/24"]),
        destination=ResolvedAddresses(is_any=True),
        to_zones=[zone] if isinstance(zone, str) else list(zone),
        **kwargs,
    )


def _codes(rule, config=None):
    from panorama_team_review.analyze.findings import run_checks
    from panorama_team_review.config import AnalysisConfig

    found = run_checks([rule], config or AnalysisConfig(), date(2026, 7, 28))
    return {f.code for findings in found.values() for f in findings}


def test_an_internet_bound_rule_is_not_flagged_for_an_any_destination():
    """The internet is the destination. There is no tighter way to write it.

    Telling an owner to "name the destinations" for an egress rule is advice
    they cannot take, and a report that asks for the impossible gets skimmed.
    """
    assert "ANY_DESTINATION" not in _codes(_rule_to("outside"))
    assert "ANY_DESTINATION" not in _codes(_rule_to("untrust"))


def test_an_internal_rule_with_an_any_destination_is_still_flagged():
    assert "ANY_DESTINATION" in _codes(_rule_to("inside"))


def test_a_rule_going_both_outside_and_inside_is_still_flagged():
    """It permits unrestricted internal access as well, which is the point."""
    assert "ANY_DESTINATION" in _codes(_rule_to(["outside", "inside"]))


def test_a_rule_to_any_zone_is_still_flagged():
    assert "ANY_DESTINATION" in _codes(_rule_to("any"))


def test_the_internet_zone_names_are_configurable():
    from panorama_team_review.config import AnalysisConfig

    strict = AnalysisConfig(internet_zones=[])
    assert "ANY_DESTINATION" in _codes(_rule_to("outside"), strict)

    renamed = AnalysisConfig(internet_zones=["transfer-net"])
    assert "ANY_DESTINATION" not in _codes(_rule_to("transfer-net"), renamed)


def test_an_internet_bound_rule_is_still_flagged_for_permitting_everything():
    """Exempting the destination must not exempt the rule from every check."""
    from panorama_team_review.model import ResolvedServices

    rule = _rule_to("outside")
    rule.services = ResolvedServices(is_any=True)
    rule.applications = ["any"]
    assert "ANY_SERVICE" in _codes(rule)


# ---------------------------------------------------------------------------
# Dates that cannot be true
# ---------------------------------------------------------------------------


def _rule_dated(role: str, value: str, by: str | None = None):
    from panorama_team_review.model import DateRef, Location, RuleMetadata, SecurityRule

    return SecurityRule(
        name="dated",
        location=Location(source="test"),
        description="see the metadata",
        metadata=RuleMetadata(
            dates=[DateRef(role=role, value=date.fromisoformat(value), raw=value, by=by)]
        ),
    )


def test_a_change_dated_in_the_future_is_flagged():
    """'CHG0041299 a.beck 2027-07-18' on a 2026 report records an edit that has
    not happened yet -- almost always a mistyped year."""
    findings = _codes(_rule_dated("changed", "2027-07-18", by="a.beck"))
    assert "IMPOSSIBLE_DATE" in findings


def test_a_creation_or_review_date_in_the_future_is_flagged_too():
    assert "IMPOSSIBLE_DATE" in _codes(_rule_dated("created", "2030-01-01"))
    assert "IMPOSSIBLE_DATE" in _codes(_rule_dated("reviewed", "2030-01-01"))


def test_an_expiry_in_the_future_is_the_well_managed_case():
    assert "IMPOSSIBLE_DATE" not in _codes(_rule_dated("expires", "2030-01-01"))


def test_a_date_of_unstated_purpose_is_not_flagged():
    """It might be an expiry, and guessing wrong would invent a finding."""
    assert "IMPOSSIBLE_DATE" not in _codes(_rule_dated("unknown", "2030-01-01"))


def test_a_past_change_date_is_fine():
    assert "IMPOSSIBLE_DATE" not in _codes(_rule_dated("changed", "2024-05-30"))


def test_the_finding_names_the_editor_and_the_date():
    from panorama_team_review.analyze.findings import run_checks
    from panorama_team_review.config import AnalysisConfig

    found = run_checks(
        [_rule_dated("changed", "2027-07-18", by="a.beck")], AnalysisConfig(), date(2026, 7, 28)
    )
    finding = next(f for fs in found.values() for f in fs if f.code == "IMPOSSIBLE_DATE")
    assert "a.beck" in finding.detail
    assert "2027-07-18" in finding.detail


# ---------------------------------------------------------------------------
# Where the object names and the inventory disagree
# ---------------------------------------------------------------------------


def _gaps(objects, teams, patterns):
    """objects: [(name, cidr)], teams: {id: [cidr]}, patterns: [(regex, team_id)]."""
    from datetime import datetime

    from panorama_team_review.analyze.inventory_gaps import find_inventory_gaps
    from panorama_team_review.config import ObjectNamingRule
    from panorama_team_review.model import (
        AddressKind,
        AddressObject,
        Location,
        Snapshot,
        SnapshotMeta,
        Team,
    )

    location = Location(source="t.xml")
    snapshot = Snapshot(
        meta=SnapshotMeta(source_file="t.xml", parsed_at=datetime(2026, 7, 28)),
        addresses=[
            AddressObject(name=name, kind=AddressKind.IP_NETMASK, value=cidr, location=location)
            for name, cidr in objects
        ],
    )
    return find_inventory_gaps(
        snapshot,
        [Team(id=tid, name=tid, assets=assets) for tid, assets in teams.items()],
        [ObjectNamingRule(pattern=p, team_id=t) for p, t in patterns],
    )


PROD = (r"^net-prod-(?P<app>[a-z0-9]+)-", "{app}-p")


def test_an_object_outside_its_teams_networks_is_reported():
    """The case that made a team's report look complete while missing nine rules."""
    gaps = _gaps(
        objects=[("net-prod-payments-database-10.20.99.0-24", "10.20.99.0/24")],
        teams={"payments-p": ["10.20.12.0/22"]},
        patterns=[PROD],
    )
    assert len(gaps) == 1
    assert gaps[0].kind == "outside-team"
    assert gaps[0].team_id == "payments-p"
    assert gaps[0].network == "10.20.99.0/24"
    assert "10.20.12.0/22" in gaps[0].detail


def test_an_object_inside_its_teams_networks_is_not_reported():
    gaps = _gaps(
        objects=[("net-prod-payments-database-10.20.12.0-24", "10.20.12.0/24")],
        teams={"payments-p": ["10.20.12.0/22"]},
        patterns=[PROD],
    )
    assert gaps == []


def test_a_network_two_teams_claim_is_reported():
    gaps = _gaps(
        objects=[
            ("net-prod-payments-database-10.20.12.0-24", "10.20.12.0/24"),
            ("net-prod-orders-frontend-10.20.12.0-24", "10.20.12.0/24"),
        ],
        teams={"payments-p": ["10.20.12.0/22"], "orders-p": ["10.20.12.0/22"]},
        patterns=[PROD],
    )
    contested = [g for g in gaps if g.kind == "claimed-twice"]
    assert len(contested) == 1
    assert {contested[0].team_id, contested[0].other_team} == {"payments-p", "orders-p"}


def test_a_name_pointing_at_an_unknown_team_is_not_reported():
    """That is an account missing from the inventory entirely, which the
    unassigned-rules section already speaks to. Reporting it twice would
    double-count one gap."""
    gaps = _gaps(
        objects=[("net-prod-newapp-database-10.20.99.0-24", "10.20.99.0/24")],
        teams={"payments-p": ["10.20.12.0/22"]},
        patterns=[PROD],
    )
    assert gaps == []


def test_no_naming_convention_means_no_gaps():
    """A convention only exists where an estate has one; guessing invents findings."""
    gaps = _gaps(
        objects=[("net-prod-payments-database-10.20.99.0-24", "10.20.99.0/24")],
        teams={"payments-p": ["10.20.12.0/22"]},
        patterns=[],
    )
    assert gaps == []


def test_the_stage_mapping_has_to_be_written_down():
    """An estate whose 'staging' networks belong to '-t' accounts states it."""
    gaps = _gaps(
        objects=[("net-staging-payments-db-10.30.9.0-24", "10.30.9.0/24")],
        teams={"payments-t": ["10.30.0.0/22"]},
        patterns=[(r"^net-staging-(?P<app>[a-z0-9]+)-", "{app}-t")],
    )
    assert len(gaps) == 1 and gaps[0].team_id == "payments-t"


def test_an_object_defined_in_two_scopes_is_reported_once():
    """A merged Panorama archive holds each definition separately.

    That distinction matters to the resolver and to nobody reading this list:
    one gap is one address group to correct, however many places the object is
    written down in.
    """
    from datetime import datetime

    from panorama_team_review.analyze.inventory_gaps import find_inventory_gaps
    from panorama_team_review.config import ObjectNamingRule
    from panorama_team_review.model import (
        AddressKind,
        AddressObject,
        Location,
        Snapshot,
        SnapshotMeta,
        Team,
    )

    def address(scope):
        return AddressObject(
            name="net-prod-payments-database-10.20.99.0-24",
            kind=AddressKind.IP_NETMASK, value="10.20.99.0/24",
            location=Location(source="t.xml", device_group=scope),
        )

    snapshot = Snapshot(
        meta=SnapshotMeta(source_file="t.xml", parsed_at=datetime(2026, 7, 28)),
        addresses=[address("DG-Production"), address(None)],
    )
    gaps = find_inventory_gaps(
        snapshot,
        [Team(id="payments-p", name="Payments", assets=["10.20.12.0/22"])],
        [ObjectNamingRule(pattern=r"^net-prod-(?P<app>[a-z0-9]+)-", team_id="{app}-p")],
    )
    assert len(gaps) == 1
