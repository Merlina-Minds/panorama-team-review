"""Deriving a draft inventory from a configuration.

The draft is a starting point a human edits, so the bar is different from the
rest of the tool: it may be incomplete, but it must never be *confidently
wrong*. An over-wide network silently claims another team's rules, and a
guessed owner is worse than a blank.
"""

from __future__ import annotations

import ipaddress

import pytest
import yaml

from panorama_team_review.analyze.suggest import (
    compare_strategies,
    render_yaml,
    suggest_inventory,
)
from panorama_team_review.resolve.objects import resolve_snapshot


@pytest.fixture
def resolved(panorama_snapshot):
    resolve_snapshot(panorama_snapshot)
    return panorama_snapshot


# ---------------------------------------------------------------------------
# Grouping strategies
# ---------------------------------------------------------------------------


def test_device_group_strategy_produces_candidates(resolved):
    draft = suggest_inventory(resolved, group_by="device-group")
    assert draft.teams
    ids = {team.suggested_id for team in draft.teams}
    assert "dg-production" in ids


def test_candidates_carry_their_evidence(resolved):
    """A reviewer has to see where a candidate came from to judge it."""
    draft = suggest_inventory(resolved, group_by="device-group")
    for team in draft.teams:
        assert team.source
        assert team.networks or team.notes


def test_shared_objects_are_reported_not_attributed(resolved):
    """Shared objects are visible everywhere; guessing an owner is wrong."""
    draft = suggest_inventory(resolved, group_by="device-group")
    assert any("shared" in warning for warning in draft.warnings)


def test_usage_strategy_uses_rules_not_definitions(resolved):
    draft = suggest_inventory(resolved, group_by="usage")
    assert draft.teams
    assert all("usage" in note for team in draft.teams for note in team.notes)


def test_usage_leaves_shared_networks_unassigned(resolved):
    """A network used by several device groups has no single owner."""
    draft = suggest_inventory(resolved, group_by="usage")
    claimed: list[str] = [cidr for team in draft.teams for cidr in team.networks]
    assert len(claimed) == len(set(claimed)), "no network may be claimed twice"


def test_zone_strategy_produces_candidates(resolved):
    draft = suggest_inventory(resolved, group_by="zone")
    assert draft.teams


def test_tag_strategy_produces_candidates(resolved):
    draft = suggest_inventory(resolved, group_by="tag")
    ids = {team.suggested_id for team in draft.teams}
    assert any("owner" in team_id for team_id in ids)


# ---------------------------------------------------------------------------
# Aggregation must not over-claim
# ---------------------------------------------------------------------------


def test_networks_are_never_widened_past_the_limit(resolved):
    """An over-wide asset silently claims rules belonging to someone else."""
    draft = suggest_inventory(resolved, group_by="device-group", min_prefix_v4=16)
    for team in draft.teams:
        for cidr in team.networks:
            net = ipaddress.ip_network(cidr)
            if net.version == 4:
                assert net.prefixlen >= 16, f"{cidr} is wider than the configured limit"


def test_aggregation_respects_the_cap(resolved):
    draft = suggest_inventory(resolved, group_by="device-group", max_networks_per_team=3)
    for team in draft.teams:
        assert len(team.networks) <= 3


def test_suggested_networks_are_valid_cidrs(resolved):
    draft = suggest_inventory(resolved, group_by="device-group")
    for team in draft.teams:
        for cidr in team.networks:
            ipaddress.ip_network(cidr)  # raises if malformed


def test_uncovered_networks_are_listed(resolved):
    """What the draft misses matters more than what it got right."""
    draft = suggest_inventory(resolved, group_by="device-group")
    assert isinstance(draft.uncovered_networks, list)
    for cidr, count in draft.uncovered_networks:
        ipaddress.ip_network(cidr)
        assert count > 0


# ---------------------------------------------------------------------------
# Rendered output
# ---------------------------------------------------------------------------


def test_rendered_draft_is_valid_yaml(resolved):
    draft = suggest_inventory(resolved, group_by="device-group")
    parsed = yaml.safe_load(render_yaml(draft, source="test.xml"))
    assert "teams" in parsed
    assert len(parsed["teams"]) == len(draft.teams)


def test_rendered_draft_marks_what_it_cannot_know(resolved):
    """Names and contacts are TODO, not invented."""
    draft = suggest_inventory(resolved, group_by="device-group")
    parsed = yaml.safe_load(render_yaml(draft, source="test.xml"))
    for team in parsed["teams"]:
        assert team["name"] == "TODO"
        assert team["contact"] == "TODO"
        assert team["id"]


def test_rendered_draft_warns_it_is_a_draft(resolved):
    rendered = render_yaml(suggest_inventory(resolved), source="test.xml")
    assert "REVIEW BEFORE USE" in rendered
    assert "NOT a finished inventory" in rendered


def test_rendered_draft_loads_as_an_inventory(resolved, tmp_path):
    """The draft must be structurally valid, so editing it is the only work."""
    from panorama_team_review.resolve.inventory import load_inventory

    path = tmp_path / "draft.yaml"
    path.write_text(render_yaml(suggest_inventory(resolved), source="t.xml"), encoding="utf-8")

    teams = load_inventory(path)
    assert teams
    assert all(team.id for team in teams)


def test_empty_configuration_does_not_crash(panorama_snapshot):
    panorama_snapshot.addresses.clear()
    panorama_snapshot.rules.clear()
    draft = suggest_inventory(panorama_snapshot, group_by="device-group")
    assert draft.teams == []
    assert "teams:" in render_yaml(draft, source="empty.xml")


# ---------------------------------------------------------------------------
# Strategy comparison
# ---------------------------------------------------------------------------


def test_comparison_covers_every_strategy(resolved):
    rows = compare_strategies(resolved)
    assert {row["strategy"] for row in rows} == {"device-group", "usage", "zone", "tag"}


def test_comparison_reports_coverage(resolved):
    for row in compare_strategies(resolved):
        assert 0 <= row["coverage_percent"] <= 100
        assert row["candidates"] >= 0


# ---------------------------------------------------------------------------
# The draft must actually load
# ---------------------------------------------------------------------------


def test_colliding_names_produce_unique_ids(resolved):
    """Slugging is lossy: 'VPN', 'vpn' and 'VPN-1' all reduce to 'vpn'.

    Regression test for a draft that could not be loaded at all -- duplicate
    ids make the inventory invalid, turning a helpful starting point into a
    puzzle the user has to debug first. Found on a real configuration whose
    zones differed only in case.
    """
    resolved.zones.update({"VPN": [], "vpn": [], "VPN-1": [], "Vpn_1": []})
    for name in ("VPN", "vpn", "VPN-1", "Vpn_1"):
        rule = resolved.rules[0].model_copy(deep=True)
        rule.name = f"rule-into-{name}"
        rule.to_zones = [name]
        resolved.rules.append(rule)

    draft = suggest_inventory(resolved, group_by="zone")
    ids = [team.suggested_id for team in draft.teams]
    assert len(ids) == len(set(ids)), f"duplicate ids: {ids}"


def test_draft_with_colliding_names_still_loads(resolved, tmp_path):
    from panorama_team_review.resolve.inventory import load_inventory

    resolved.zones.update({"VPN": [], "vpn": []})
    for name in ("VPN", "vpn"):
        rule = resolved.rules[0].model_copy(deep=True)
        rule.name = f"rule-into-{name}"
        rule.to_zones = [name]
        resolved.rules.append(rule)

    path = tmp_path / "draft.yaml"
    path.write_text(
        render_yaml(suggest_inventory(resolved, group_by="zone"), source="t.xml"),
        encoding="utf-8",
    )
    assert load_inventory(path)


@pytest.mark.parametrize("strategy", ["device-group", "usage", "zone", "tag"])
def test_every_strategy_produces_a_loadable_draft(resolved, tmp_path, strategy):
    from panorama_team_review.resolve.inventory import load_inventory

    path = tmp_path / f"{strategy}.yaml"
    path.write_text(
        render_yaml(suggest_inventory(resolved, group_by=strategy), source="t.xml"),
        encoding="utf-8",
    )
    load_inventory(path)
