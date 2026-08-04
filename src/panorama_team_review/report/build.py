"""Assemble the report bundle: the single place where all stages meet.

Pipeline, in order:

    parse -> resolve objects -> extract metadata -> attribute ownership
          -> run checks -> group per team -> ReportBundle

Everything above this module is analysis; everything below it is rendering.
The ``ReportBundle`` it produces is fully serialisable, which is what makes the
JSON output a complete record of a run rather than a summary of one.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from datetime import date, datetime

from ..analyze.findings import rule_key, run_checks, unknown_checks
from ..analyze.inventory_gaps import find_inventory_gaps
from ..config import Config
from ..enrich.metadata import MetadataExtractor, annotate_rules
from ..model import (
    Finding,
    NamedObject,
    ReportBundle,
    RuleView,
    SecurityRule,
    Snapshot,
    Team,
    TeamReport,
)
from ..resolve.evaluation import EvaluationOrder
from ..resolve.inventory import inventory_warnings
from ..resolve.nettrie import NetworkTrie, contains
from ..resolve.objects import resolve_named_objects, resolve_snapshot
from ..resolve.ownership import Attribution, OwnershipResolver

# Sort order for rule views within a section.
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def build_report(
    snapshot: Snapshot,
    teams: list[Team],
    config: Config,
    today: date | None = None,
) -> ReportBundle:
    """Run the full analysis pipeline over one snapshot."""
    today = today or date.today()
    notes: list[str] = []

    # 1. Flatten object references into concrete networks and ports.
    index = resolve_snapshot(snapshot)

    # 1b. Teams that the configuration names itself. Merged with the inventory,
    # where an explicit entry always wins -- see resolve.derive.
    if config.ownership.derive_teams:
        from ..resolve.derive import derive_teams, merge_teams

        derivation = derive_teams(snapshot, index, config.ownership)
        teams, merge_notes = merge_teams(list(teams), derivation.teams)
        notes.extend(derivation.notes)
        notes.extend(merge_notes)

    # 1c. Assets from ownership tags on the objects themselves. Same merge rule:
    # a tag extends a hand-written inventory, or stands in for it.
    if config.ownership.derive_from_object_tags:
        from ..resolve.derive import derive_from_object_tags, merge_teams

        tagged = derive_from_object_tags(snapshot, index, config.ownership)
        teams, tag_notes = merge_teams(list(teams), tagged.teams)
        notes.extend(tagged.notes)
        notes.extend(tag_notes)

    # 2. Recover tickets, dates and requesters from free text.
    extractor = MetadataExtractor(config.metadata)
    annotate_rules(snapshot.rules, extractor)
    annotate_rules(snapshot.nat_rules, extractor)

    # 3. Attribute every rule to the teams it concerns.
    resolver = OwnershipResolver(teams, config.ownership)
    resolver.reset_any_budget()

    rules = _selected_rules(snapshot, config)
    attributions: dict[int, Attribution] = {
        id(rule): resolver.resolve(rule) for rule in rules
    }

    # 4. Hygiene and cleanup checks.
    if missing := unknown_checks(config.analysis):
        notes.append(
            f"configuration enables unknown checks that were skipped: {', '.join(missing)}"
        )
    findings_by_rule = run_checks(rules, config.analysis, today, snapshot)

    # 5. Group into per-team reports, ordered the way the firewall reads them.
    order = EvaluationOrder(snapshot)
    ranks = {id(rule): rank for rank, rule in enumerate(sorted(rules, key=order.key))}
    objects = _objects_by_team(snapshot, index, teams)
    team_reports = _build_team_reports(
        rules, teams, attributions, findings_by_rule, config, order, ranks, objects
    )
    unassigned = _build_unassigned(rules, attributions, findings_by_rule, config, order, ranks)

    notes.extend(inventory_warnings(teams))
    notes.extend(snapshot.parse_warnings)

    return ReportBundle(
        meta=snapshot.meta,
        generated_at=datetime.now(),
        scopes=order.scopes(),
        teams=team_reports,
        unassigned=unassigned,
        global_findings=_global_findings(findings_by_rule),
        inventory_gaps=find_inventory_gaps(snapshot, teams, config.ownership.object_naming),
        stats=_build_stats(snapshot, rules, team_reports, unassigned, findings_by_rule),
        hitcount_available=any(rule.hits is not None for rule in snapshot.rules),
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Rule selection
# ---------------------------------------------------------------------------


def _selected_rules(snapshot: Snapshot, config: Config) -> list[SecurityRule]:
    if config.report.include_disabled_rules:
        return snapshot.rules
    return [rule for rule in snapshot.rules if not rule.disabled]


# ---------------------------------------------------------------------------
# Team reports
# ---------------------------------------------------------------------------


def _build_team_reports(
    rules: list[SecurityRule],
    teams: list[Team],
    attributions: dict[int, Attribution],
    findings_by_rule: dict[str, list[Finding]],
    config: Config,
    order: EvaluationOrder,
    ranks: dict[int, int],
    objects: dict[str, list[NamedObject]],
) -> list[TeamReport]:
    reports = {
        team.id: TeamReport(team=team, objects=objects.get(team.id, [])) for team in teams
    }

    for rule in rules:
        attribution = attributions[id(rule)]
        rule_findings = findings_by_rule.get(rule_key(rule), [])

        for team_id, view in attribution.teams.items():
            report = reports.get(team_id)
            if report is None:
                continue

            # Findings are annotated with every team they concern, so a team's
            # own list is filterable without re-running the checks.
            #
            # They are attached only to the team's own rules. A finding on a
            # rule that merely covers them -- the estate-wide DNS or Active
            # Directory permission -- is addressed to whoever maintains that
            # rule, and a team cannot act on it: not by fixing it, since the
            # rule is not theirs, and not by ignoring it, since it arrives
            # looking like work. Estate-wide, those findings outnumbered the
            # actionable ones roughly two to one. They remain in
            # ``bundle.global_findings``, which is the firewall team's list.
            scoped_findings = (
                [f.model_copy(update={"teams": [team_id]}) for f in rule_findings]
                if view.coverage == "own"
                else []
            )

            rule_view = RuleView(
                rule=rule,
                direction=view.direction,
                scope_id=order.scope_of(rule).id,
                evaluation_rank=ranks[id(rule)],
                coverage=view.coverage,
                coverage_reason=view.coverage_reason,
                matched_assets=view.matched_assets,
                highlight_networks=view.highlight_networks,
                peers=view.peers,
                peer_teams=view.peer_teams,
                matches=view.matches,
                findings=scoped_findings,
            )
            _section_for(report, view.direction).append(rule_view)
            report.findings.extend(scoped_findings)

    for report in reports.values():
        _sort_sections(report, config, order)
        report.findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity.value], f.rule_name))

    # A team with nothing to review still gets a report: "no rules touch your
    # systems" is a meaningful and reassuring answer, and its absence would
    # look like the tool forgot them.
    return sorted(reports.values(), key=lambda r: (-r.rule_count, r.team.name))


def _objects_by_team(
    snapshot: Snapshot, index, teams: list[Team]
) -> dict[str, list[NamedObject]]:
    """Which address objects and groups live inside each team's networks.

    An object counts as a team's when *every* network it resolves to lies
    inside that team's address space. Partial containment is deliberately not
    enough: a group holding the whole estate is not the payments team's object
    just because a payments network happens to be in it, and listing it as
    theirs would invite a change request against something shared.
    """
    named = resolve_named_objects(snapshot, index)
    if not named:
        return {}

    trie: NetworkTrie[str] = NetworkTrie()
    for team in teams:
        for cidr in team.assets:
            trie.insert(cidr, team.id)
    if not len(trie):
        return {}

    out: dict[str, list[NamedObject]] = defaultdict(list)
    for obj in named:
        # Teams whose assets contain *every* network of this object.
        covering: set[str] | None = None
        for cidr in obj.networks:
            net = ipaddress.ip_network(cidr)
            here = {
                team_id
                for asset, team_id in trie.find_overlaps(net)
                if contains(asset, net)
            }
            covering = here if covering is None else covering & here
            if not covering:
                break
        for team_id in covering or ():
            out[team_id].append(obj)

    return dict(out)


def _section_for(report: TeamReport, direction: str) -> list[RuleView]:
    return {
        "inbound": report.inbound,
        "outbound": report.outbound,
        "internal": report.internal,
        "related": report.related,
    }[direction]


def _sort_sections(report: TeamReport, config: Config, order: EvaluationOrder) -> None:
    """Order the rules within each section.

    ``order`` -- the default -- means the order the firewall evaluates them
    in, which is the only one that carries information: it is what decides
    whether a rule below a broader one ever matches a packet. It used to sort
    on ``Location.label()``, which is alphabetical by device group and put
    ``DC/post`` ahead of ``shared/pre``. That is not an approximation of the
    evaluation order, it is unrelated to it, and it read as though it were.
    """
    mode = config.report.sort_rules_by

    def key(view: RuleView):
        if mode == "name":
            return (view.rule.name.lower(),)
        if mode == "severity":
            worst = min(
                (_SEVERITY_ORDER[f.severity.value] for f in view.findings), default=99
            )
            return (worst, *order.key(view.rule))
        return order.key(view.rule)

    for section in (report.inbound, report.outbound, report.internal, report.related):
        section.sort(key=key)


def _build_unassigned(
    rules: list[SecurityRule],
    attributions: dict[int, Attribution],
    findings_by_rule: dict[str, list[Finding]],
    config: Config,
    order: EvaluationOrder,
    ranks: dict[int, int],
) -> list[RuleView]:
    """Rules no team could be determined for.

    This section is the tool's honesty check, and worth reading first: a large
    unassigned list means the inventory is incomplete, not that the rules are
    unimportant.
    """
    if not config.report.show_unassigned_section:
        return []

    out: list[RuleView] = []
    for rule in rules:
        if attributions[id(rule)].is_assigned:
            continue
        out.append(
            RuleView(
                rule=rule,
                direction="related",
                scope_id=order.scope_of(rule).id,
                evaluation_rank=ranks[id(rule)],
                peers=[],
                findings=findings_by_rule.get(rule_key(rule), []),
            )
        )
    out.sort(key=lambda v: order.key(v.rule))
    return out


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def _global_findings(findings_by_rule: dict[str, list[Finding]]) -> list[Finding]:
    everything = [f for findings in findings_by_rule.values() for f in findings]
    everything.sort(key=lambda f: (_SEVERITY_ORDER[f.severity.value], f.code, f.rule_name))
    return everything


def _build_stats(
    snapshot: Snapshot,
    rules: list[SecurityRule],
    team_reports: list[TeamReport],
    unassigned: list[RuleView],
    findings_by_rule: dict[str, list[Finding]],
) -> dict[str, int]:
    severity_counts = Counter(
        f.severity.value for findings in findings_by_rule.values() for f in findings
    )
    code_counts = Counter(
        f.code for findings in findings_by_rule.values() for f in findings
    )

    stats: dict[str, int] = {
        "rules_total": len(snapshot.rules),
        "rules_analysed": len(rules),
        "rules_disabled": sum(1 for r in snapshot.rules if r.disabled),
        "rules_unassigned": len(unassigned),
        "nat_rules": len(snapshot.nat_rules),
        "address_objects": len(snapshot.addresses),
        "address_groups": len(snapshot.address_groups),
        "service_objects": len(snapshot.services),
        "device_groups": len(snapshot.device_groups),
        "teams": len(team_reports),
        "teams_with_rules": sum(1 for r in team_reports if r.rule_count > 0),
        # Split across all team reports, so the effect of the distinction is
        # visible without opening a single report.
        "team_rules_own": sum(len(r.own_views) for r in team_reports),
        "team_rules_covering": sum(len(r.covered_views) for r in team_reports),
        "findings_total": sum(len(f) for f in findings_by_rule.values()),
        "rules_with_tickets": sum(1 for r in rules if r.metadata.tickets),
    }
    for severity, count in severity_counts.items():
        stats[f"findings_{severity}"] = count
    for code, count in code_counts.items():
        stats[f"check_{code}"] = count
    return stats
