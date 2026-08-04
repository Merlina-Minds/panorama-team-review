"""Deriving teams from naming conventions.

The premise: an estate that provisions networks automatically encodes ownership
in its object names, reliably, because a machine wrote them. Reading that beats
maintaining a parallel inventory by hand, which drifts the moment an account is
created.

The risk that comes with it: a pattern that matches too much attributes rules
to the wrong people. These tests pin both sides.
"""

from __future__ import annotations

import pytest

from panorama_team_review.config import DerivedTeamRule, OwnershipConfig
from panorama_team_review.model import (
    AddressGroup,
    AddressKind,
    AddressObject,
    Location,
    Snapshot,
    SnapshotMeta,
    Team,
)
from panorama_team_review.resolve.derive import derive_from_object_tags, derive_teams, merge_teams
from panorama_team_review.resolve.objects import build_index


def snapshot(**kwargs) -> Snapshot:
    from datetime import datetime

    return Snapshot(
        meta=SnapshotMeta(source_file="t.xml", parsed_at=datetime(2026, 7, 28)), **kwargs
    )


def loc() -> Location:
    return Location(source="t.xml", shared=True)


def address(name: str, value: str, tags: list[str] | None = None) -> AddressObject:
    return AddressObject(
        name=name, kind=AddressKind.IP_NETMASK, value=value, tags=tags or [], location=loc()
    )


def run(snap: Snapshot, *rules: DerivedTeamRule):
    index = build_index(snap)
    return derive_teams(snap, index, OwnershipConfig(derive_teams=list(rules)))


# ---------------------------------------------------------------------------
# Address groups
# ---------------------------------------------------------------------------


def test_group_name_becomes_a_team():
    snap = snapshot(
        addresses=[address("web01", "10.1.1.5/32"), address("web02", "10.1.1.6/32")],
        address_groups=[
            AddressGroup(name="awsgrp-shop-p-01", members=["web01", "web02"], location=loc())
        ],
    )
    result = run(snap, DerivedTeamRule(
        id="aws", source="address-group",
        pattern=r"^awsgrp-(?P<team>.+)$", team_id="{team}",
    ))

    assert [team.id for team in result.teams] == ["shop-p-01"]
    assert set(result.teams[0].assets) == {"10.1.1.5/32", "10.1.1.6/32"}


def test_capture_groups_compose_the_id_and_name():
    snap = snapshot(
        addresses=[address("a", "10.1.1.5/32")],
        address_groups=[
            AddressGroup(name="awsgrp-org-cat-shop-p-01", members=["a"], location=loc())
        ],
    )
    result = run(snap, DerivedTeamRule(
        id="aws", source="address-group",
        pattern=r"^awsgrp-(?P<org>[a-z]+)-(?P<cat>[a-z]+)-(?P<app>.+)-(?P<stage>[a-z])-(?P<nr>\d+)$",
        team_id="{app}-{stage}", team_name="{app} ({stage})",
    ))

    assert result.teams[0].id == "shop-p"
    assert result.teams[0].name == "shop (p)"


def test_several_groups_merge_into_one_team():
    """An application with several groups is still one team."""
    snap = snapshot(
        addresses=[address("a", "10.1.1.0/24"), address("b", "10.2.2.0/24")],
        address_groups=[
            AddressGroup(name="awsgrp-shop-p-01", members=["a"], location=loc()),
            AddressGroup(name="awsgrp-shop-p-02", members=["b"], location=loc()),
        ],
    )
    result = run(snap, DerivedTeamRule(
        id="aws", source="address-group",
        pattern=r"^awsgrp-(?P<app>[a-z]+)-(?P<stage>[a-z])-\d+$",
        team_id="{app}-{stage}",
    ))

    assert len(result.teams) == 1
    assert set(result.teams[0].assets) == {"10.1.1.0/24", "10.2.2.0/24"}


def test_exclude_pattern_skips_names():
    snap = snapshot(
        addresses=[address("a", "10.1.1.0/24")],
        address_groups=[
            AddressGroup(name="awsgrp-shop-p-01", members=["a"], location=loc()),
            AddressGroup(name="awsgrp-legacy-thing", members=["a"], location=loc()),
        ],
    )
    result = run(snap, DerivedTeamRule(
        id="aws", source="address-group", pattern=r"^awsgrp-(?P<team>.+)$",
        team_id="{team}", exclude_pattern=r"legacy",
    ))
    assert [team.id for team in result.teams] == ["shop-p-01"]


def test_nested_groups_are_resolved():
    snap = snapshot(
        addresses=[address("a", "10.1.1.0/24"), address("b", "10.1.2.0/24")],
        address_groups=[
            AddressGroup(name="inner", members=["b"], location=loc()),
            AddressGroup(name="awsgrp-shop", members=["a", "inner"], location=loc()),
        ],
    )
    result = run(snap, DerivedTeamRule(
        id="aws", source="address-group", pattern=r"^awsgrp-(?P<team>.+)$", team_id="{team}"
    ))
    assert set(result.teams[0].assets) == {"10.1.1.0/24", "10.1.2.0/24"}


# ---------------------------------------------------------------------------
# Placeholder addresses
# ---------------------------------------------------------------------------


def test_placeholder_addresses_are_not_assets():
    """A loopback in a generated group would otherwise belong to every team.

    Regression test from a real estate: 127.0.0.255 appeared as a placeholder
    in dozens of account groups. Treated as an asset, every rule touching it
    landed in every one of those teams' reports.
    """
    snap = snapshot(
        addresses=[address("real", "10.1.1.0/24"), address("placeholder", "127.0.0.255/32")],
        address_groups=[
            AddressGroup(name="awsgrp-a", members=["real", "placeholder"], location=loc()),
            AddressGroup(name="awsgrp-b", members=["placeholder"], location=loc()),
        ],
    )
    result = run(snap, DerivedTeamRule(
        id="aws", source="address-group", pattern=r"^awsgrp-(?P<team>.+)$", team_id="{team}"
    ))

    assets = {team.id: team.assets for team in result.teams}
    assert assets.get("a") == ["10.1.1.0/24"]
    # Team 'b' had nothing but the placeholder and is dropped by min_assets.
    assert "b" not in assets


def test_exclusions_are_configurable():
    snap = snapshot(
        addresses=[address("a", "10.1.1.0/24"), address("b", "192.168.99.0/24")],
        address_groups=[AddressGroup(name="awsgrp-x", members=["a", "b"], location=loc())],
    )
    result = run(snap, DerivedTeamRule(
        id="aws", source="address-group", pattern=r"^awsgrp-(?P<team>.+)$",
        team_id="{team}", exclude_networks=["192.168.0.0/16"],
    ))
    assert result.teams[0].assets == ["10.1.1.0/24"]


def test_min_assets_discards_thin_teams():
    snap = snapshot(
        addresses=[address("a", "10.1.1.0/24")],
        address_groups=[
            AddressGroup(name="awsgrp-full", members=["a"], location=loc()),
            AddressGroup(name="awsgrp-empty", members=[], location=loc()),
        ],
    )
    result = run(snap, DerivedTeamRule(
        id="aws", source="address-group", pattern=r"^awsgrp-(?P<team>.+)$",
        team_id="{team}", min_assets=1,
    ))
    assert [team.id for team in result.teams] == ["full"]


# ---------------------------------------------------------------------------
# Other sources
# ---------------------------------------------------------------------------


def test_derive_from_address_object_names():
    snap = snapshot(addresses=[
        address("awsnet-prod-shop-database-10.1.36.0-23", "10.1.36.0/23"),
        address("awsnet-prod-shop-application-10.1.38.0-23", "10.1.38.0/23"),
        address("awsnet-dev-shop-database-10.2.36.0-23", "10.2.36.0/23"),
    ])
    result = run(snap, DerivedTeamRule(
        id="subnets", source="address-object",
        pattern=r"^awsnet-(?P<stage>[a-z]+)-(?P<app>[a-z]+)-",
        team_id="{app}-{stage}",
    ))

    by_id = {team.id: team for team in result.teams}
    assert set(by_id) == {"shop-prod", "shop-dev"}

    # Adjacent networks are collapsed -- 10.1.36.0/23 and 10.1.38.0/23 become
    # 10.1.36.0/22, which covers exactly the same addresses and nothing more.
    # Asserting on coverage rather than on the literal list keeps the test
    # about what matters.
    import ipaddress

    covered = {
        address
        for cidr in by_id["shop-prod"].assets
        for address in ipaddress.ip_network(cidr)
    }
    expected = set(ipaddress.ip_network("10.1.36.0/23")) | set(
        ipaddress.ip_network("10.1.38.0/23")
    )
    assert covered == expected


def test_derive_from_tags():
    snap = snapshot(addresses=[
        address("a", "10.1.1.0/24", tags=["SHOP-PROD"]),
        address("b", "10.1.2.0/24", tags=["SHOP-PROD"]),
        address("c", "10.3.1.0/24", tags=["OTHER-DEV"]),
    ])
    result = run(snap, DerivedTeamRule(
        id="tags", source="tag", pattern=r"^(?P<app>[A-Z]+)-(?P<stage>[A-Z]+)$",
        team_id="{app}-{stage}",
    ))

    by_id = {team.id: team for team in result.teams}
    assert set(by_id) == {"SHOP-PROD", "OTHER-DEV"}
    assert set(by_id["SHOP-PROD"].assets) == {"10.1.1.0/24", "10.1.2.0/24"}


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


def test_a_pattern_that_matches_nothing_says_so():
    """Silence here would look like an estate with no teams."""
    snap = snapshot(address_groups=[AddressGroup(name="something-else", location=loc())])
    result = run(snap, DerivedTeamRule(
        id="aws", source="address-group", pattern=r"^awsgrp-(?P<team>.+)$", team_id="{team}"
    ))
    assert result.teams == []
    assert any("matched nothing" in note for note in result.notes)


def test_notes_report_what_matched():
    snap = snapshot(
        addresses=[address("a", "10.1.1.0/24")],
        address_groups=[AddressGroup(name="awsgrp-x", members=["a"], location=loc())],
    )
    result = run(snap, DerivedTeamRule(
        id="aws", source="address-group", pattern=r"^awsgrp-(?P<team>.+)$", team_id="{team}"
    ))
    assert any("matched 1 address-group" in note for note in result.notes)


# ---------------------------------------------------------------------------
# Merging with the hand-written inventory
# ---------------------------------------------------------------------------


def test_explicit_team_wins_over_derived():
    """Somebody wrote the entry deliberately; a convention cannot know why."""
    explicit = [Team(id="shop", name="Shop Team", contact="shop@example.com",
                     assets=["10.1.0.0/16"])]
    derived = [Team(id="shop", name="shop", assets=["10.1.1.0/24"])]

    merged, notes = merge_teams(explicit, derived)
    assert len(merged) == 1
    assert merged[0].name == "Shop Team"
    assert merged[0].contact == "shop@example.com"
    assert any("defined in the inventory" in note for note in notes)


def test_derived_networks_are_added_to_an_explicit_team():
    """The convention may have found assets the human missed."""
    explicit = [Team(id="shop", name="Shop", assets=["10.1.0.0/16"])]
    derived = [Team(id="shop", name="shop", assets=["10.1.0.0/16", "10.9.9.0/24"])]

    merged, _ = merge_teams(explicit, derived)
    assert "10.9.9.0/24" in merged[0].assets
    assert merged[0].name == "Shop"


def test_derived_only_teams_are_kept():
    merged, _ = merge_teams([], [Team(id="a", name="A", assets=["10.1.0.0/16"])])
    assert [team.id for team in merged] == ["a"]


def test_no_rules_means_no_derivation(panorama_snapshot):
    index = build_index(panorama_snapshot)
    result = derive_teams(panorama_snapshot, index, OwnershipConfig())
    assert result.teams == []


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------


def test_pattern_needs_a_named_group():
    with pytest.raises(ValueError, match="named group"):
        DerivedTeamRule(id="x", pattern=r"^awsgrp-.+$")


def test_templates_may_only_use_captured_groups():
    with pytest.raises(ValueError, match="does not capture"):
        DerivedTeamRule(id="x", pattern=r"^(?P<team>.+)$", team_name="{missing}")


def test_invalid_regex_is_rejected():
    with pytest.raises(ValueError, match="invalid regex"):
        DerivedTeamRule(id="x", pattern=r"^(?P<team>[unclosed")


def test_invalid_exclude_network_is_rejected():
    with pytest.raises(ValueError, match="not a network"):
        DerivedTeamRule(id="x", pattern=r"(?P<team>.+)", exclude_networks=["not-a-net"])


# ---------------------------------------------------------------------------
# End to end through the report builder
# ---------------------------------------------------------------------------


def test_derived_teams_reach_the_report(panorama_snapshot):
    from panorama_team_review.config import Config
    from panorama_team_review.report.build import build_report

    config = Config()
    config.ownership.derive_teams = [
        DerivedTeamRule(
            id="groups", source="address-group",
            pattern=r"^grp-(?P<team>[a-z-]+)-app$", team_id="{team}",
        )
    ]
    bundle = build_report(panorama_snapshot, [], config)

    assert bundle.teams, "derived teams should appear in the report"
    assert any("derive_teams" in note for note in bundle.notes)


def test_a_rule_between_two_teams_appears_in_both_reports():
    """The point of the whole tool, asserted with derived teams."""
    from datetime import datetime

    from panorama_team_review.config import Config
    from panorama_team_review.model import ResolvedAddresses, SecurityRule
    from panorama_team_review.report.build import build_report

    snap = snapshot(
        addresses=[address("a-host", "10.1.1.0/24"), address("b-host", "10.2.2.0/24")],
        address_groups=[
            AddressGroup(name="awsgrp-alpha", members=["a-host"], location=loc()),
            AddressGroup(name="awsgrp-beta", members=["b-host"], location=loc()),
        ],
        rules=[
            SecurityRule(
                name="alpha-to-beta",
                location=Location(source="t.xml", device_group="DG"),
                source=ResolvedAddresses(raw=["a-host"]),
                destination=ResolvedAddresses(raw=["b-host"]),
            )
        ],
    )
    snap.meta.parsed_at = datetime(2026, 7, 28)

    config = Config()
    config.ownership.derive_teams = [
        DerivedTeamRule(id="aws", source="address-group",
                        pattern=r"^awsgrp-(?P<team>.+)$", team_id="{team}")
    ]
    bundle = build_report(snap, [], config)

    by_id = {report.team.id: report for report in bundle.teams}
    assert [v.rule.name for v in by_id["alpha"].outbound] == ["alpha-to-beta"]
    assert [v.rule.name for v in by_id["beta"].inbound] == ["alpha-to-beta"]


# ---------------------------------------------------------------------------
# Which tags a derived team takes from the objects it was built from
# ---------------------------------------------------------------------------


def _derive_with_tags(group_tags, **ownership):
    """One address group, one derived team, whatever tags you hand it."""
    from panorama_team_review.config import DerivedTeamRule, OwnershipConfig

    snap = snapshot(
        addresses=[
            AddressObject(name="a", kind=AddressKind.IP_NETMASK, value="10.1.0.0/24",
                          location=loc())
        ],
        address_groups=[
            AddressGroup(name="awsgrp-shop", members=["a"], tags=group_tags, location=loc())
        ],
    )
    config = OwnershipConfig(
        derive_teams=[
            DerivedTeamRule(id="aws", source="address-group",
                            pattern=r"^awsgrp-(?P<team>.+)$", team_id="{team}")
        ],
        **ownership,
    )
    result = derive_teams(snap, build_index(snap), config)
    return result.teams[0]


def test_a_classification_tag_is_not_inherited():
    """The bug this exists for.

    A tag on an address group says what the object is -- it is what dynamic
    address groups are built from. Taken as ownership, one such tag made every
    derived team claim it, and because the tag index keeps one team per tag,
    every rule carrying it landed on whichever team sorted last, as its own
    work to review.
    """
    team = _derive_with_tags(["GlobalProtect-Clients", "OnPrem", "Outdated-Object"])
    assert team.tags == []


def test_an_ownership_tag_naming_this_team_is_inherited():
    team = _derive_with_tags(["owner:shop", "GlobalProtect-Clients"])
    assert team.tags == ["owner:shop"]


def test_an_ownership_tag_naming_a_different_team_is_not_inherited():
    """Otherwise this team quietly answers for another one's rules."""
    team = _derive_with_tags(["owner:payments"])
    assert team.tags == []


def test_a_suffix_convention_is_inherited_too():
    team = _derive_with_tags(["shop-owner"], tag_suffixes=["-owner"])
    assert team.tags == ["shop-owner"]


def test_without_a_convention_nothing_is_inherited():
    """An estate that does not tag for ownership inherits nothing, correctly."""
    team = _derive_with_tags(["owner:shop"], tag_prefixes=[], tag_suffixes=[])
    assert team.tags == []


# ---------------------------------------------------------------------------
# Assets from ownership tags on the objects themselves
# ---------------------------------------------------------------------------


def _from_object_tags(snap, prefixes=("owner:",), suffixes=()):
    config = OwnershipConfig(tag_prefixes=list(prefixes), tag_suffixes=list(suffixes))
    return derive_from_object_tags(snap, build_index(snap), config)


def test_a_tagged_object_becomes_a_team_asset():
    """The whole point: the object's address is the team's, as if the inventory said so."""
    snap = snapshot(addresses=[address("db01", "10.20.0.0/24", tags=["owner:payments"])])
    teams = _from_object_tags(snap).teams
    assert [t.id for t in teams] == ["payments"]
    assert teams[0].assets == ["10.20.0.0/24"]


def test_a_tagged_group_contributes_its_members():
    snap = snapshot(
        addresses=[address("web01", "10.1.1.0/24"), address("web02", "10.1.2.0/24")],
        address_groups=[
            AddressGroup(name="grp-web", members=["web01", "web02"],
                         tags=["owner:platform"], location=loc())
        ],
    )
    teams = _from_object_tags(snap).teams
    assert [t.id for t in teams] == ["platform"]
    assert set(teams[0].assets) == {"10.1.1.0/24", "10.1.2.0/24"}


def test_classification_tags_derive_nothing():
    """Only tags matching the convention count; the rest say what the object is."""
    snap = snapshot(
        addresses=[address("db01", "10.20.0.0/24", tags=["prod", "GlobalProtect-Clients"])]
    )
    assert _from_object_tags(snap).teams == []


def test_the_suffix_convention_derives_assets_too():
    snap = snapshot(addresses=[address("db01", "10.20.0.0/24", tags=["payments-owner"])])
    teams = _from_object_tags(snap, prefixes=(), suffixes=("-owner",)).teams
    assert [t.id for t in teams] == ["payments"]


def test_one_object_can_belong_to_two_teams():
    snap = snapshot(
        addresses=[address("shared", "10.5.0.0/24", tags=["owner:payments", "owner:platform"])]
    )
    assert {t.id for t in _from_object_tags(snap).teams} == {"payments", "platform"}


def test_placeholder_networks_are_excluded_from_derived_assets():
    """A loopback standing in for 'nothing here yet' must not become an asset."""
    snap = snapshot(addresses=[address("db01", "127.0.0.1/32", tags=["owner:payments"])])
    assert _from_object_tags(snap).teams == []


def test_object_tags_give_direction_through_the_builder():
    """Object tags feed the inventory resolver, so they carry inbound/outbound."""
    from datetime import datetime

    from panorama_team_review.config import Config
    from panorama_team_review.model import ResolvedAddresses, SecurityRule
    from panorama_team_review.report.build import build_report

    snap = snapshot(
        addresses=[
            address("a-host", "10.1.1.0/24", tags=["owner:alpha"]),
            address("b-host", "10.2.2.0/24", tags=["owner:beta"]),
        ],
        rules=[
            SecurityRule(
                name="alpha-to-beta",
                location=Location(source="t.xml", device_group="DG"),
                source=ResolvedAddresses(raw=["a-host"]),
                destination=ResolvedAddresses(raw=["b-host"]),
            )
        ],
    )
    snap.meta.parsed_at = datetime(2026, 7, 28)

    config = Config()
    config.ownership.derive_from_object_tags = True
    bundle = build_report(snap, [], config)

    by_id = {report.team.id: report for report in bundle.teams}
    assert [v.rule.name for v in by_id["alpha"].outbound] == ["alpha-to-beta"]
    assert [v.rule.name for v in by_id["beta"].inbound] == ["alpha-to-beta"]


def test_object_tags_extend_a_hand_written_inventory():
    """A tag adds assets to an inventory team rather than replacing it."""
    from panorama_team_review.config import Config
    from panorama_team_review.report.build import build_report

    snap = snapshot(addresses=[address("db01", "10.20.0.0/24", tags=["owner:payments"])])

    config = Config()
    config.ownership.derive_from_object_tags = True
    explicit = [Team(id="payments", name="Payments", assets=["10.99.0.0/16"])]
    bundle = build_report(snap, explicit, config)

    payments = next(report for report in bundle.teams if report.team.id == "payments")
    assert payments.team.name == "Payments"  # the explicit entry still wins
    assert set(payments.team.assets) == {"10.99.0.0/16", "10.20.0.0/24"}

