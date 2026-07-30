"""The order in which a firewall evaluates its rules.

These assertions encode PAN-OS behaviour rather than this tool's preferences,
so they are written against the sequence a packet actually takes: shared
pre-rules, device groups from the top of the hierarchy down, the firewall's own
rules, then post-rules from the firewall's own device group back up to shared.

Getting this wrong is not a cosmetic bug. A report that lists rules in the
wrong order tells an owner that a rule is reachable when a broader one above it
has already matched.
"""

from __future__ import annotations

import pytest

from panorama_team_review.model import Rulebase
from panorama_team_review.parse import panos
from panorama_team_review.resolve.evaluation import EvaluationOrder


@pytest.fixture
def order(panorama_snapshot) -> EvaluationOrder:
    return EvaluationOrder(panorama_snapshot)


@pytest.fixture
def scope_ids(order: EvaluationOrder) -> list[str]:
    return [scope.id for scope in order.scopes()]


def _position(scope_ids: list[str], scope_id: str) -> int:
    assert scope_id in scope_ids, f"{scope_id} missing from {scope_ids}"
    return scope_ids.index(scope_id)


# ---------------------------------------------------------------------------
# Stage order
# ---------------------------------------------------------------------------


def test_shared_pre_rules_are_evaluated_first(scope_ids):
    assert scope_ids[0] == "shared/pre"


def test_shared_post_rules_are_evaluated_last(scope_ids):
    assert scope_ids[-1] == "shared/post"


def test_every_pre_block_precedes_every_post_block(order):
    stages = [scope.stage for scope in order.scopes()]
    assert stages == sorted(stages, key=["pre", "local", "post", "default"].index)


# ---------------------------------------------------------------------------
# Hierarchy order
# ---------------------------------------------------------------------------


def test_pre_rules_run_from_the_top_of_the_hierarchy_down(scope_ids):
    """A child device group's pre-rules come after its parent's."""
    parent = _position(scope_ids, "DG-Shared-Services/pre")
    child = _position(scope_ids, "DG-Development/pre")
    assert parent < child


def test_post_rules_run_from_the_innermost_device_group_outwards(scope_ids):
    """The reverse of the pre-rules, which is what puts the catch-all last."""
    parent = _position(scope_ids, "DG-Shared-Services/post")
    child = _position(scope_ids, "DG-Development/post")
    assert child < parent
    assert parent < _position(scope_ids, "shared/post")


def test_a_device_groups_own_pre_rules_follow_shared(scope_ids):
    assert _position(scope_ids, "shared/pre") < _position(scope_ids, "DG-Production/pre")


# ---------------------------------------------------------------------------
# Rule keys
# ---------------------------------------------------------------------------


def test_rules_sort_into_evaluation_order(panorama_snapshot, order):
    ordered = sorted(panorama_snapshot.rules, key=order.key)
    positions = [order.scope_of(rule).position for rule in ordered]
    assert positions == sorted(positions)


def test_rules_within_a_block_keep_their_configured_position(panorama_snapshot, order):
    ordered = sorted(panorama_snapshot.rules, key=order.key)
    within = [r.order for r in ordered if r.location.label() == "DG-Production/pre"]
    assert within == sorted(within)


def test_ordering_does_not_fall_back_to_alphabetical_scope_names(scope_ids):
    """The regression this module exists for.

    Sorting on ``Location.label()`` -- which is what the reports used to do --
    puts every device group ahead of ``shared`` because 'D' sorts before 's'.
    That ordering is not a rough approximation of the evaluation order, it is
    unrelated to it, and it looked authoritative.
    """
    assert scope_ids != sorted(scope_ids)


# ---------------------------------------------------------------------------
# What a block reaches
# ---------------------------------------------------------------------------


def test_a_block_says_which_firewalls_evaluate_it(order):
    for scope in order.scopes():
        assert scope.applies_to, f"{scope.id} does not say what it applies to"


def test_shared_blocks_reach_every_managed_firewall(order):
    shared = next(scope for scope in order.scopes() if scope.id == "shared/pre")
    assert "firewalls managed by this Panorama" in shared.applies_to


def test_a_block_reports_its_full_size(order, panorama_snapshot):
    """Including the rules a given team never sees.

    Without this a reader cannot tell that other rules sit between the ones
    they are shown, which is exactly what decides whether their own rule is
    ever reached.
    """
    for scope in order.scopes():
        actual = sum(1 for r in panorama_snapshot.rules if r.location.label() == scope.id)
        assert scope.rule_count == actual


# ---------------------------------------------------------------------------
# Local rules
# ---------------------------------------------------------------------------


def test_local_rules_sit_between_the_pre_and_post_blocks(panorama_snapshot, firewall_snapshot):
    """A managed firewall's own rules are evaluated after every pre-rulebase.

    Merging the two fixtures reproduces what a Panorama backup archive
    actually contains: the Panorama configuration plus one document per
    managed firewall.
    """
    merged = panos.merge([panorama_snapshot, firewall_snapshot])
    order = EvaluationOrder(merged)
    scopes = order.scopes()

    local = [s for s in scopes if s.stage == "local"]
    assert local, "the firewall fixture defines rules in its own rulebase"

    last_pre = max(s.position for s in scopes if s.stage == "pre")
    first_post = min(s.position for s in scopes if s.stage == "post")
    for scope in local:
        assert last_pre < scope.position < first_post


def test_a_firewalls_local_block_names_only_that_firewall(firewall_snapshot):
    order = EvaluationOrder(firewall_snapshot)
    local = [s for s in order.scopes() if s.stage == "local"]
    assert local
    for scope in local:
        assert scope.applies_to.endswith("only")


def test_rulebase_kinds_all_map_to_a_stage(panorama_snapshot):
    """Every Rulebase value must place a rule somewhere, including DEFAULT.

    A rule that falls through to an unknown stage would be sorted into an
    arbitrary position rather than failing loudly.
    """
    order = EvaluationOrder(panorama_snapshot)
    rule = panorama_snapshot.rules[0]
    for kind in Rulebase:
        moved = rule.model_copy(
            update={"location": rule.location.model_copy(update={"rulebase": kind})}
        )
        assert order.scope_of(moved).stage in {"pre", "local", "post", "default"}
