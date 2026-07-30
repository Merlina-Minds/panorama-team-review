"""The distinction between a team's own rules and the ones that merely cover it.

A rule naming an object inside a team's address space was written for them.
A rule naming ``10.0.0.0/8``, or ``any``, covers them along with everyone else
-- the estate-wide permissions for ping, DNS or Active Directory. Both belong
in a report; only the first is the team's to justify.

Getting this backwards in either direction has a cost. Treating estate-wide
rules as a team's own buries the handful they can act on under hundreds they
cannot, and asks them to review other people's work. Dropping them instead
would leave owners requesting access they already have.
"""

from __future__ import annotations

from datetime import date

import pytest

from panorama_team_review.config import Config, OwnershipConfig
from panorama_team_review.model import Team
from panorama_team_review.report.build import build_report

TODAY = date(2026, 7, 28)

# A host inside DG-Shared-Services' 10.10/16. Rules naming the whole /16 cover
# this team without being about it; rules naming the host itself are its own.
HOST_TEAM = Team(id="single-host", name="One Host", assets=["10.10.1.7/32"])


@pytest.fixture
def teams_with_a_host(teams) -> list[Team]:
    return [*teams, HOST_TEAM]


@pytest.fixture
def bundle(panorama_snapshot, teams_with_a_host, config):
    return build_report(panorama_snapshot, teams_with_a_host, config, today=TODAY)


def _report(bundle, team_id):
    return next(r for r in bundle.teams if r.team.id == team_id)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def test_a_rule_naming_the_teams_network_is_its_own(bundle):
    platform = _report(bundle, "platform")
    assert platform.own_views
    for view in platform.own_views:
        assert view.coverage == "own"


def test_a_rule_naming_only_a_supernet_merely_covers_the_team(bundle):
    """The team owns one host; a rule about the whole /16 is not theirs."""
    host = _report(bundle, "single-host")
    covered = host.covered_views
    assert covered, "rules naming 10.10.0.0/16 exist in the fixture"
    supernet = [v for v in covered if "lies inside" in v.coverage_reason]
    assert supernet, "at least one rule must be covered via a supernet, not just via any/any"


def test_an_any_any_rule_covers_every_team(bundle):
    for report in bundle.teams:
        fallback = [
            view for view in report.covered_views
            if any(match.method == "fallback" for match in view.matches)
        ]
        for view in fallback:
            assert view.coverage == "covered"


def test_owning_beats_being_covered(bundle):
    """A rule naming both the team's network and a wider one is still theirs."""
    host = _report(bundle, "single-host")
    own = [v for v in host.own_views if "names your network" in v.coverage_reason]
    assert own, "the fixture has a rule naming the single host directly"


def test_every_view_explains_its_classification(bundle):
    for report in bundle.teams:
        for view in report.all_views:
            assert view.coverage_reason, f"{view.rule.name} has no reason recorded"


def test_a_tag_makes_a_rule_the_teams_own(panorama_snapshot, config):
    """An explicit label is a decision somebody made, not an accident of size."""
    tagged = Team(id="platform", name="Platform", tags=["owner:platform"])
    bundle = build_report(panorama_snapshot, [tagged], config, today=TODAY)
    report = bundle.teams[0]
    by_tag = [
        view for view in report.all_views
        if any(match.method == "tag" for match in view.matches)
    ]
    assert by_tag
    for view in by_tag:
        assert view.coverage == "own"


def test_the_supernet_tolerance_is_configurable(panorama_snapshot, config):
    """An inventory of individual hosts can count the surrounding /24 as its own."""
    config.ownership = OwnershipConfig(covering_supernet_bits=17)
    bundle = build_report(panorama_snapshot, [HOST_TEAM], config, today=TODAY)
    report = bundle.teams[0]

    strict = build_report(
        panorama_snapshot, [HOST_TEAM], Config(), today=TODAY
    ).teams[0]

    assert report.own_rule_count > strict.own_rule_count


# ---------------------------------------------------------------------------
# Consequences for the report
# ---------------------------------------------------------------------------


def test_covering_rules_carry_no_findings(bundle):
    """Nothing to act on, so nothing that looks like work."""
    for report in bundle.teams:
        for view in report.covered_views:
            assert view.findings == []


def test_the_teams_finding_list_holds_only_its_own_rules(bundle):
    for report in bundle.teams:
        own_names = {view.rule.name for view in report.own_views}
        for finding in report.findings:
            assert finding.rule_name in own_names


def test_findings_on_covering_rules_survive_in_the_global_list(bundle):
    """They are the firewall team's work, not nobody's."""
    covering = {
        view.rule.name
        for report in bundle.teams
        for view in report.covered_views
    }
    team_findings = {f.rule_name for report in bundle.teams for f in report.findings}
    global_findings = {f.rule_name for f in bundle.global_findings}

    only_covering = covering - {v.rule.name for r in bundle.teams for v in r.own_views}
    hidden = only_covering & global_findings
    assert not (hidden & team_findings)
    assert global_findings >= team_findings


def test_covered_views_come_back_in_evaluation_order(bundle):
    for report in bundle.teams:
        ranks = [view.evaluation_rank for view in report.covered_views]
        assert ranks == sorted(ranks)


def test_sections_are_sorted_by_evaluation_order(bundle):
    for report in bundle.teams:
        for section in (report.inbound, report.outbound, report.internal, report.related):
            ranks = [view.evaluation_rank for view in section]
            assert ranks == sorted(ranks)


def test_the_split_is_reported_in_the_statistics(bundle):
    assert bundle.stats["team_rules_own"] + bundle.stats["team_rules_covering"] == sum(
        report.rule_count for report in bundle.teams
    )


# ---------------------------------------------------------------------------
# Objects and groups inside a team's networks
# ---------------------------------------------------------------------------


def test_objects_inside_a_teams_networks_are_listed(bundle):
    """A change request cites an object name; nobody can guess the convention."""
    platform = _report(bundle, "platform")
    assert platform.objects, "the fixture defines address objects inside 10.10.0.0/16"
    for obj in platform.objects:
        assert obj.networks
        assert obj.kind in {"object", "group"}


def test_an_object_belongs_to_a_team_only_if_all_of_it_does(bundle):
    """Partial containment is not enough, or shared groups become everyone's."""
    import ipaddress

    for report in bundle.teams:
        assets = [ipaddress.ip_network(cidr) for cidr in report.team.assets]
        for obj in report.objects:
            for cidr in obj.networks:
                net = ipaddress.ip_network(cidr)
                assert any(
                    net.version == asset.version and net.subnet_of(asset) for asset in assets
                ), f"{obj.name} lists {cidr}, which is outside {report.team.id}'s networks"


def test_a_team_with_no_networks_claims_no_objects(bundle):
    for report in bundle.teams:
        if not report.team.assets:
            assert report.objects == []


# ---------------------------------------------------------------------------
# Per-object resolution
# ---------------------------------------------------------------------------


def test_every_named_object_carries_its_own_resolution(panorama_snapshot, teams, config):
    """The union alone cannot say which object contributed which address."""
    bundle = build_report(panorama_snapshot, teams, config, today=TODAY)
    checked = 0
    for report in bundle.teams:
        for view in report.all_views:
            for side in (view.rule.source, view.rule.destination):
                if side.is_any:
                    continue
                assert [m.name for m in side.members] == side.raw
                for member in side.members:
                    assert set(member.networks) <= set(side.networks)
                    checked += 1
    assert checked, "the fixture has rules with named objects"


def test_a_shared_group_resolves_in_every_field_that_names_it(panorama_snapshot, teams, config):
    """Two objects in one field sharing a member must both report it.

    The union only needs each address once, so the resolver skips names it has
    already expanded. Reusing that bookkeeping for the per-object breakdown
    would leave whichever object came second looking empty.
    """
    bundle = build_report(panorama_snapshot, teams, config, today=TODAY)
    for report in bundle.teams:
        for view in report.all_views:
            for side in (view.rule.source, view.rule.destination):
                for member in side.members:
                    if member.unresolved or member.fqdns:
                        continue
                    assert member.networks, (
                        f"{member.name} resolved to nothing while the field as a whole "
                        f"resolved to {len(side.networks)} networks"
                    )
