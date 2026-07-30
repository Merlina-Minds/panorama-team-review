"""Ownership attribution, and above all the direction logic.

Getting direction wrong is worse than getting it missing: a report that tells
an owner "nothing reaches these systems" when something does is actively
misleading. These tests pin the inbound/outbound/internal decision precisely.
"""

from __future__ import annotations

from panorama_team_review.config import OwnershipConfig
from panorama_team_review.model import (
    Location,
    ResolvedAddresses,
    RuleAction,
    SecurityRule,
    Team,
)
from panorama_team_review.resolve.ownership import OwnershipResolver, _combine_directions


def make_rule(
    name: str = "r1",
    source: list[str] | None = None,
    destination: list[str] | None = None,
    source_any: bool = False,
    dest_any: bool = False,
    **kwargs,
) -> SecurityRule:
    return SecurityRule(
        name=name,
        location=Location(source="test.xml", device_group=kwargs.pop("device_group", None)),
        source=ResolvedAddresses(networks=source or [], is_any=source_any),
        destination=ResolvedAddresses(networks=destination or [], is_any=dest_any),
        **kwargs,
    )


TEAM_A = Team(id="alpha", name="Alpha", assets=["10.1.0.0/16"],
              asset_labels={"10.1.0.0/16": "Alpha network"})
TEAM_B = Team(id="beta", name="Beta", assets=["10.2.0.0/16"])


def resolver(teams=None, **config_kwargs) -> OwnershipResolver:
    return OwnershipResolver(teams or [TEAM_A, TEAM_B], OwnershipConfig(**config_kwargs))


# ---------------------------------------------------------------------------
# Direction
# ---------------------------------------------------------------------------


def test_team_as_source_is_outbound():
    rule = make_rule(source=["10.1.5.0/24"], destination=["10.9.9.0/24"])
    attribution = resolver().resolve(rule)
    assert attribution.teams["alpha"].direction == "outbound"
    assert attribution.teams["alpha"].peers == ["10.9.9.0/24"]


def test_team_as_destination_is_inbound():
    rule = make_rule(source=["10.9.9.0/24"], destination=["10.1.5.0/24"])
    attribution = resolver().resolve(rule)
    assert attribution.teams["alpha"].direction == "inbound"
    assert attribution.teams["alpha"].peers == ["10.9.9.0/24"]


def test_team_on_both_sides_is_internal():
    rule = make_rule(source=["10.1.1.0/24"], destination=["10.1.2.0/24"])
    attribution = resolver().resolve(rule)
    assert attribution.teams["alpha"].direction == "internal"


def test_two_teams_see_the_same_rule_from_opposite_sides():
    """The point of the whole tool: both owners of a connection get told."""
    rule = make_rule(source=["10.1.1.0/24"], destination=["10.2.1.0/24"])
    attribution = resolver().resolve(rule)
    assert attribution.teams["alpha"].direction == "outbound"
    assert attribution.teams["beta"].direction == "inbound"
    assert attribution.teams["alpha"].peer_teams == ["beta"]
    assert attribution.teams["beta"].peer_teams == ["alpha"]


def test_any_source_to_our_systems_is_inbound():
    """'anyone can reach you' is the single most important line in a report."""
    rule = make_rule(source_any=True, destination=["10.1.5.0/24"])
    attribution = resolver().resolve(rule)
    assert attribution.teams["alpha"].direction == "inbound"
    assert attribution.teams["alpha"].peers == ["any"]


def test_our_systems_to_any_destination_is_outbound():
    rule = make_rule(source=["10.1.5.0/24"], dest_any=True)
    attribution = resolver().resolve(rule)
    assert attribution.teams["alpha"].direction == "outbound"
    assert attribution.teams["alpha"].peers == ["any"]


def test_unrelated_rule_is_not_attributed():
    rule = make_rule(source=["10.9.0.0/24"], destination=["10.8.0.0/24"])
    assert not resolver().resolve(rule).is_assigned


def test_matched_assets_are_reported():
    rule = make_rule(source=["10.1.5.0/24"], destination=["10.9.9.0/24"])
    view = resolver().resolve(rule).teams["alpha"]
    assert view.matched_assets == ["10.1.0.0/16"]
    assert "Alpha network" in view.matches[0].evidence


def test_contained_match_mode_is_stricter():
    """In 'contained' mode a rule covering more than the asset does not match."""
    rule = make_rule(source=["10.0.0.0/8"], destination=["10.9.9.0/24"])
    assert resolver(match_mode="overlap").resolve(rule).is_assigned
    assert not resolver(match_mode="contained").resolve(rule).is_assigned


# ---------------------------------------------------------------------------
# any/any rules
# ---------------------------------------------------------------------------


def test_any_any_rule_reaches_every_team():
    rule = make_rule(source_any=True, dest_any=True)
    attribution = resolver().resolve(rule)
    assert attribution.affects_everyone
    assert set(attribution.teams) == {"alpha", "beta"}
    assert attribution.teams["alpha"].direction == "related"


def test_any_any_rule_can_be_suppressed():
    rule = make_rule(source_any=True, dest_any=True)
    assert not resolver(include_any_rules=False).resolve(rule).is_assigned


def test_any_any_denies_are_not_shown_to_everyone():
    """A catch-all deny affects nobody's access; showing it everywhere is noise."""
    rule = make_rule(source_any=True, dest_any=True, action=RuleAction.DENY)
    assert not resolver().resolve(rule).is_assigned


def test_any_any_budget_is_capped_per_team():
    instance = resolver(max_any_rules_per_team=2)
    instance.reset_any_budget()
    assigned = [
        instance.resolve(make_rule(name=f"r{i}", source_any=True, dest_any=True)).is_assigned
        for i in range(5)
    ]
    assert assigned == [True, True, False, False, False]


def test_reset_any_budget_clears_the_cap():
    instance = resolver(max_any_rules_per_team=1)
    instance.reset_any_budget()
    assert instance.resolve(make_rule(source_any=True, dest_any=True)).is_assigned
    assert not instance.resolve(make_rule(name="r2", source_any=True, dest_any=True)).is_assigned
    instance.reset_any_budget()
    assert instance.resolve(make_rule(name="r3", source_any=True, dest_any=True)).is_assigned


# ---------------------------------------------------------------------------
# Tag resolver
# ---------------------------------------------------------------------------


def test_tag_prefix_names_the_team():
    rule = make_rule(tags=["owner:alpha"])
    attribution = resolver().resolve(rule)
    assert attribution.teams["alpha"].direction == "related"
    assert attribution.teams["alpha"].matches[0].method == "tag"


def test_explicit_tag_from_inventory_matches():
    team = Team(id="alpha", name="Alpha", tags=["infra-critical"])
    rule = make_rule(tags=["infra-critical"])
    assert resolver([team]).resolve(rule).is_assigned


def test_tag_matching_is_case_insensitive_by_default():
    rule = make_rule(tags=["OWNER:alpha"])
    assert resolver().resolve(rule).is_assigned


def test_tag_naming_an_unknown_team_is_ignored():
    rule = make_rule(tags=["owner:nonexistent"])
    assert not resolver().resolve(rule).is_assigned


def test_tag_and_inventory_combine_on_one_rule():
    """A tag adds evidence without overriding the direction the assets gave."""
    rule = make_rule(source=["10.1.5.0/24"], destination=["10.9.9.0/24"], tags=["owner:alpha"])
    view = resolver().resolve(rule).teams["alpha"]
    assert view.direction == "outbound"
    assert {match.method for match in view.matches} == {"inventory", "tag"}


# ---------------------------------------------------------------------------
# Regex, device group and zone resolvers
# ---------------------------------------------------------------------------


def test_team_name_pattern_matches():
    team = Team(id="webshop", name="Webshop", name_patterns=["^WEB-"])
    assert resolver([team]).resolve(make_rule(name="WEB-allow-https")).is_assigned
    assert not resolver([team]).resolve(make_rule(name="OTHER-rule")).is_assigned


def test_global_name_pattern_captures_the_team_id():
    instance = resolver(name_patterns=[r"^(?P<team>alpha|beta)-"])
    attribution = instance.resolve(make_rule(name="beta-allow-ssh"))
    assert "beta" in attribution.teams


def test_description_pattern_captures_the_team_id():
    instance = resolver(description_patterns=[r"owner=(?P<team>\w+)"])
    attribution = instance.resolve(make_rule(description="CHG1 owner=alpha access"))
    assert "alpha" in attribution.teams


def test_device_group_attribution():
    team = Team(id="alpha", name="Alpha", device_groups=["DG-Prod"])
    rule = make_rule(device_group="DG-Prod")
    attribution = resolver([team]).resolve(rule)
    assert attribution.teams["alpha"].matches[0].method == "device-group"


def test_zone_carries_direction():
    """A from-zone means the team is the source, so the rule is outbound."""
    team = Team(id="alpha", name="Alpha", zones=["zone-alpha"])
    instance = resolver([team])
    outbound = instance.resolve(make_rule(from_zones=["zone-alpha"], to_zones=["untrust"]))
    inbound = instance.resolve(make_rule(from_zones=["untrust"], to_zones=["zone-alpha"]))
    assert outbound.teams["alpha"].direction == "outbound"
    assert inbound.teams["alpha"].direction == "inbound"


def test_zone_on_both_sides_is_internal():
    team = Team(id="alpha", name="Alpha", zones=["zone-alpha"])
    rule = make_rule(from_zones=["zone-alpha"], to_zones=["zone-alpha"])
    assert resolver([team]).resolve(rule).teams["alpha"].direction == "internal"


# ---------------------------------------------------------------------------
# Cascade
# ---------------------------------------------------------------------------


def test_stop_after_first_match_prefers_the_earlier_resolver():
    """A precise tag must not be drowned out by a broad device group."""
    alpha = Team(id="alpha", name="Alpha", tags=["owner:alpha"])
    beta = Team(id="beta", name="Beta", device_groups=["DG-Prod"])
    rule = make_rule(tags=["owner:alpha"], device_group="DG-Prod")

    strict = OwnershipResolver([alpha, beta], OwnershipConfig(stop_after_first_match=True))
    assert set(strict.resolve(rule).teams) == {"alpha"}

    loose = OwnershipResolver([alpha, beta], OwnershipConfig(stop_after_first_match=False))
    assert set(loose.resolve(rule).teams) == {"alpha", "beta"}


def test_inventory_always_runs_even_when_a_later_resolver_matches():
    """Direction information must never be lost to the cascade."""
    alpha = Team(id="alpha", name="Alpha", assets=["10.1.0.0/16"], tags=["owner:alpha"])
    rule = make_rule(source=["10.1.1.0/24"], destination=["10.9.9.0/24"], tags=["owner:alpha"])
    attribution = OwnershipResolver([alpha], OwnershipConfig()).resolve(rule)
    assert attribution.teams["alpha"].direction == "outbound"


def test_resolver_order_is_configurable():
    alpha = Team(id="alpha", name="Alpha", tags=["owner:alpha"])
    beta = Team(id="beta", name="Beta", device_groups=["DG-Prod"])
    rule = make_rule(tags=["owner:alpha"], device_group="DG-Prod")
    instance = OwnershipResolver(
        [alpha, beta],
        OwnershipConfig(order=["device_group", "tag"], stop_after_first_match=True),
    )
    assert set(instance.resolve(rule).teams) == {"beta"}


# ---------------------------------------------------------------------------
# Direction combination
# ---------------------------------------------------------------------------


def test_direction_combination_rules():
    assert _combine_directions("inbound", "inbound") == "inbound"
    assert _combine_directions("inbound", "outbound") == "internal"
    assert _combine_directions("outbound", "inbound") == "internal"
    assert _combine_directions("related", "inbound") == "inbound"
    assert _combine_directions("inbound", "related") == "inbound"
    assert _combine_directions("internal", "inbound") == "internal"


def test_no_teams_configured_attributes_nothing():
    instance = OwnershipResolver([], OwnershipConfig())
    assert not instance.resolve(make_rule(source=["10.1.1.0/24"])).is_assigned


def test_ipv6_assets_are_matched():
    team = Team(id="v6", name="IPv6 team", assets=["2001:db8:20::/64"])
    rule = make_rule(source=["2001:db8:20::5/128"], destination=["2001:db8:99::/64"])
    assert resolver([team]).resolve(rule).teams["v6"].direction == "outbound"
