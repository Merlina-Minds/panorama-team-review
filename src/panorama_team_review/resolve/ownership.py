"""Attribute rules to teams, and work out which side of the rule they are on.

Two classes of resolver, and the difference is the whole point of the report:

*Inventory* compares a rule's resolved networks against each team's assets.
Because it knows *which side* matched, it can distinguish:

  - **outbound** -- the team's systems are the source: what my systems reach
  - **inbound**  -- the team's systems are the destination: who reaches my systems
  - **internal** -- both sides belong to the team

*Tag, regex, device-group* attribute a rule to a team but say nothing about
direction, so their hits land in the team's "related" section.  Zone matching
sits in between: a zone appears in ``from`` or ``to``, so it does carry
direction.

A rule legitimately belongs to two teams at once -- the source team and the
destination team -- and will appear in both reports, from each one's
perspective.  That is a feature: the two owners of a connection should see the
same rule described in their own terms.

Cutting across all of that is a second question, and it decides what a report
may *ask* of its reader: was this rule written for the team, or does it merely
happen to include them?  A rule naming an object inside their address space is
theirs.  A rule naming ``10.0.0.0/8``, or ``any``, covers them along with
everybody else -- the estate-wide permissions for ping, DNS, Active Directory.
Both belong in the report, because a team that cannot see the second kind
requests access it already has.  Only the first kind is theirs to justify, and
mixing the two buries it.  See ``model.Coverage``.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Literal

from ..config import OwnershipConfig
from ..model import Coverage, IPNetwork, OwnerMatch, ResolvedAddresses, SecurityRule, Team
from .nettrie import NetworkTrie, contains

Direction = Literal["inbound", "outbound", "internal", "related"]

# How much to trust each method, shown in the report so a wrong attribution can
# be traced to the rule that produced it.
CONFIDENCE = {
    "inventory": 90,
    "tag": 80,
    "regex": 60,
    "zone": 50,
    "device-group": 40,
    "fallback": 10,
}


@dataclass(slots=True)
class AssetHit:
    """One overlap between a rule's network and a network the team owns."""

    asset: str
    """The team's own network, as written in the inventory."""

    rule_network: str
    """The network the rule resolved to, which overlaps that asset."""

    names_the_team: bool
    """True when the rule's network lies inside the asset rather than around it.

    Only these two arrangements exist: CIDR blocks either nest or are
    disjoint, so an overlap is always one containing the other. Inside means
    somebody wrote this rule against the team's address space. Around it means
    the team was swept up in a broader network.
    """


@dataclass(slots=True)
class TeamAttribution:
    """One team's view of one rule."""

    team_id: str
    direction: Direction
    coverage: Coverage = "covered"
    coverage_reason: str = ""
    matched_assets: list[str] = field(default_factory=list)
    highlight_networks: list[str] = field(default_factory=list)
    peers: list[str] = field(default_factory=list)
    peer_teams: list[str] = field(default_factory=list)
    matches: list[OwnerMatch] = field(default_factory=list)

    def claim_own(self, reason: str) -> None:
        """Record evidence that the rule was written for this team.

        Owning beats being covered and never the other way round: a rule that
        names the team's own network *and* a wider one was still written for
        them, and demoting it because of the wider network would hide it from
        the section they are asked to review.
        """
        if self.coverage != "own":
            self.coverage = "own"
            self.coverage_reason = reason

    def note_covered(self, reason: str) -> None:
        if self.coverage != "own" and not self.coverage_reason:
            self.coverage_reason = reason


@dataclass(slots=True)
class Attribution:
    """The full attribution of one rule: zero or more teams, each with a view."""

    teams: dict[str, TeamAttribution] = field(default_factory=dict)
    affects_everyone: bool = False

    @property
    def is_assigned(self) -> bool:
        return bool(self.teams)


class OwnershipResolver:
    def __init__(self, teams: list[Team], config: OwnershipConfig) -> None:
        self.teams = teams
        self.config = config
        self._by_id = {team.id: team for team in teams}
        self._trie: NetworkTrie[str] = NetworkTrie()
        self._compiled_names = [re.compile(p) for p in config.name_patterns]
        self._compiled_descriptions = [re.compile(p) for p in config.description_patterns]
        self._any_rule_counts: dict[str, int] = defaultdict(int)

        for team in teams:
            for cidr in team.assets:
                self._trie.insert(cidr, team.id)

        self._tag_index = self._build_tag_index()
        self._dg_index = self._build_index(lambda t: t.device_groups)
        self._zone_index = self._build_index(lambda t: t.zones)
        self._team_name_patterns = [
            (team.id, re.compile(pattern))
            for team in teams
            for pattern in team.name_patterns
        ]

    # -- index construction -------------------------------------------------

    def _build_tag_index(self) -> dict[str, str]:
        """Map an explicit ``tags:`` entry from the inventory to its team id."""
        index: dict[str, str] = {}
        for team in self.teams:
            for tag in team.tags:
                index[self._normalise_tag(tag)] = team.id
        return index

    def _build_index(self, extract) -> dict[str, str]:
        index: dict[str, str] = {}
        for team in self.teams:
            for value in extract(team):
                index[value.lower()] = team.id
        return index

    def _normalise_tag(self, tag: str) -> str:
        return tag if self.config.tag_case_sensitive else tag.lower()

    # -- public API ---------------------------------------------------------

    def resolve(self, rule: SecurityRule) -> Attribution:
        """Determine which teams a rule belongs to and how."""
        attribution = Attribution()

        # inventory runs first, exactly once, and outside the cascade --
        # wherever `order` puts it, and whether or not `order` names it at all.
        # It is the only resolver that knows inbound from outbound, and letting
        # an earlier tag match end the loop before it ran cost the report the
        # direction, the peer team and the matched networks: the rule still
        # reached the team, but as a bare 'related' entry.
        self._resolve_inventory(rule, attribution)

        for method in self.config.order:
            if method == "tag":
                self._resolve_tag(rule, attribution)
            elif method == "regex":
                self._resolve_regex(rule, attribution)
            elif method == "device_group":
                self._resolve_device_group(rule, attribution)
            elif method == "zone":
                self._resolve_zone(rule, attribution)
            else:
                continue  # inventory -- handled above.

            # The cascade covers only the non-directional methods, so that a
            # precise tag is not drowned out by a broad device group.
            if self.config.stop_after_first_match and self._has_match_from(attribution, method):
                break

        self._handle_any_any(rule, attribution)
        return attribution

    def reset_any_budget(self) -> None:
        """Clear the per-team cap on 'any/any' rules. Call once per report run."""
        self._any_rule_counts.clear()

    # -- inventory ----------------------------------------------------------

    def _resolve_inventory(self, rule: SecurityRule, attribution: Attribution) -> None:
        if not len(self._trie):
            return

        source_hits = self._match_side(rule.source)
        dest_hits = self._match_side(rule.destination)

        # Computed once per rule, not once per team. Both were previously
        # recalculated inside the loop, which is quadratic in the number of
        # teams a rule touches -- on an estate with a few hundred derived
        # teams that turned a run from seconds into minutes.
        source_text = self._describe(rule.source)
        dest_text = self._describe(rule.destination)
        source_teams = sorted(source_hits)
        dest_teams = sorted(dest_hits)

        for team_id in set(source_hits) | set(dest_hits):
            in_source = team_id in source_hits
            in_dest = team_id in dest_hits

            if in_source and in_dest:
                direction: Direction = "internal"
                hits = source_hits[team_id] + dest_hits[team_id]
                peers = source_text + dest_text
                peer_teams: list[str] = []
            elif in_source:
                direction = "outbound"
                hits = source_hits[team_id]
                peers = dest_text
                peer_teams = [other for other in dest_teams if other != team_id]
            else:
                direction = "inbound"
                hits = dest_hits[team_id]
                peers = source_text
                peer_teams = [other for other in source_teams if other != team_id]

            assets = sorted({hit.asset for hit in hits})
            view = self._view(attribution, team_id, direction)
            view.matched_assets = _merge(view.matched_assets, assets)
            view.peers = _merge(view.peers, peers)
            view.peer_teams = _merge(view.peer_teams, peer_teams)
            self._record_coverage(view, team_id, hits, assets)
            view.matches.append(
                OwnerMatch(
                    team_id=team_id,
                    method="inventory",
                    confidence=CONFIDENCE["inventory"],
                    evidence=view.coverage_reason,
                    side="both" if direction == "internal" else (
                        "source" if direction == "outbound" else "destination"
                    ),
                )
            )

    def _record_coverage(
        self, view: TeamAttribution, team_id: str, hits: list[AssetHit], assets: list[str]
    ) -> None:
        """Decide whether this rule was written for the team or merely covers it."""
        own = [hit for hit in hits if hit.names_the_team]
        if own:
            view.highlight_networks = _merge(
                view.highlight_networks, [hit.rule_network for hit in own]
            )
            view.claim_own(self._asset_evidence(team_id, assets))
            return

        # Nothing in the rule points at the team's address space; they were
        # caught by a wider network. Naming the widest one is what makes the
        # classification checkable -- and it is the fact the reader needs,
        # since it says who else the rule covers.
        widest = max(hits, key=lambda hit: ipaddress.ip_network(hit.rule_network).num_addresses)
        view.highlight_networks = _merge(view.highlight_networks, [widest.rule_network])
        view.note_covered(
            f"your network {widest.asset} lies inside {widest.rule_network}, "
            "which is what the rule names"
        )

    def _match_side(self, side: ResolvedAddresses) -> dict[str, list[AssetHit]]:
        """Team id -> the overlaps between this address field and the team's assets."""
        hits: dict[str, list[AssetHit]] = defaultdict(list)
        if side.is_any:
            return hits

        for cidr in side.networks:
            net = ipaddress.ip_network(cidr)
            for asset_net, team_id in self._trie.find_overlaps(net):
                if self.config.match_mode == "contained" and not contains(asset_net, net):
                    continue
                hits[team_id].append(
                    AssetHit(
                        asset=str(asset_net),
                        rule_network=cidr,
                        names_the_team=self._names_the_team(net, asset_net),
                    )
                )
        return hits

    def _names_the_team(self, rule_net: IPNetwork, asset: IPNetwork) -> bool:
        """Is the rule's network inside the team's, rather than around it?"""
        if rule_net.version != asset.version:
            return False
        if contains(asset, rule_net):
            return True
        # Tolerance for estates whose inventory lists individual hosts: a rule
        # naming the /24 those hosts sit in is still recognisably about them,
        # where one naming the /8 is not. Off by default -- see the config.
        slack = self.config.covering_supernet_bits
        return slack > 1 and (asset.prefixlen - rule_net.prefixlen) < slack

    def _asset_evidence(self, team_id: str, assets: list[str]) -> str:
        team = self._by_id.get(team_id)
        if team is None:
            return "matches " + ", ".join(assets)
        labelled = [
            f"{cidr} ({team.asset_labels[cidr]})" if cidr in team.asset_labels else cidr
            for cidr in assets[:5]
        ]
        suffix = f" and {len(assets) - 5} more" if len(assets) > 5 else ""
        return "the rule names your network " + ", ".join(labelled) + suffix

    # -- tag ----------------------------------------------------------------

    def _resolve_tag(self, rule: SecurityRule, attribution: Attribution) -> None:
        for tag in rule.tags:
            normalised = self._normalise_tag(tag)

            # Explicit mapping from the inventory takes precedence.
            team_id = self._tag_index.get(normalised)
            evidence = f"tag {tag!r} listed for this team"

            if team_id is None:
                candidate = ownership_tag_team(tag, self.config)
                if candidate and candidate in self._by_id:
                    team_id = candidate
                    evidence = f"tag {tag!r} names team {candidate!r}"

            if team_id is not None:
                self._add_related(attribution, team_id, "tag", evidence)

    # -- regex --------------------------------------------------------------

    def _resolve_regex(self, rule: SecurityRule, attribution: Attribution) -> None:
        # Per-team patterns from the inventory.
        for team_id, pattern in self._team_name_patterns:
            if pattern.search(rule.name):
                self._add_related(
                    attribution, team_id, "regex",
                    f"rule name matches team pattern {pattern.pattern!r}",
                )

        # Global patterns that capture the team id themselves.
        for pattern in self._compiled_names:
            match = pattern.search(rule.name)
            captured = match.groupdict().get("team") if match else None
            if captured and captured in self._by_id:
                self._add_related(
                    attribution, captured, "regex",
                    f"rule name matches {pattern.pattern!r} -> {captured!r}",
                )

        for pattern in self._compiled_descriptions:
            match = pattern.search(rule.description)
            captured = match.groupdict().get("team") if match else None
            if captured and captured in self._by_id:
                self._add_related(
                    attribution, captured, "regex",
                    f"description matches {pattern.pattern!r} -> {captured!r}",
                )

    # -- device group -------------------------------------------------------

    def _resolve_device_group(self, rule: SecurityRule, attribution: Attribution) -> None:
        scope = rule.location.device_group or rule.location.vsys
        if not scope:
            return
        team_id = self._dg_index.get(scope.lower())
        if team_id:
            self._add_related(
                attribution, team_id, "device-group", f"rule is defined in {scope!r}"
            )

    # -- zone ---------------------------------------------------------------

    def _resolve_zone(self, rule: SecurityRule, attribution: Attribution) -> None:
        """Zones carry direction: a 'from' zone means the team is the source."""
        for zone in rule.from_zones:
            team_id = self._zone_index.get(zone.lower())
            if team_id:
                evidence = f"source zone {zone!r} belongs to this team"
                view = self._view(attribution, team_id, "outbound")
                view.peers = _merge(view.peers, self._describe(rule.destination))
                view.claim_own(evidence)
                view.matches.append(
                    OwnerMatch(
                        team_id=team_id, method="zone", confidence=CONFIDENCE["zone"],
                        evidence=evidence, side="source",
                    )
                )

        for zone in rule.to_zones:
            team_id = self._zone_index.get(zone.lower())
            if team_id:
                evidence = f"destination zone {zone!r} belongs to this team"
                view = self._view(attribution, team_id, "inbound")
                view.peers = _merge(view.peers, self._describe(rule.source))
                view.claim_own(evidence)
                view.matches.append(
                    OwnerMatch(
                        team_id=team_id, method="zone", confidence=CONFIDENCE["zone"],
                        evidence=evidence, side="destination",
                    )
                )

    # -- any/any ------------------------------------------------------------

    def _handle_any_any(self, rule: SecurityRule, attribution: Attribution) -> None:
        """A rule with 'any' on both sides affects every team.

        Hiding these would understate exposure, but showing hundreds of them
        buries the specific rules an owner actually needs to look at -- hence
        the per-team cap, and hence their landing among the rules that merely
        cover a team rather than among the ones it is asked to review.
        """
        if not rule.source.is_any or not rule.destination.is_any:
            return
        if not self.config.include_any_rules or not rule.action.permits_traffic:
            return
        attribution.affects_everyone = True

        for team in self.teams:
            if self._any_rule_counts[team.id] >= self.config.max_any_rules_per_team:
                continue
            if team.id in attribution.teams:
                continue
            self._any_rule_counts[team.id] += 1
            evidence = (
                "the rule permits any source to any destination, so it covers this "
                "team's networks along with every other"
            )
            view = self._view(attribution, team.id, "related")
            view.peers = _merge(view.peers, ["any"])
            view.note_covered(evidence)
            view.matches.append(
                OwnerMatch(
                    team_id=team.id, method="fallback", confidence=CONFIDENCE["fallback"],
                    evidence=evidence,
                    side="rule",
                )
            )

    # -- helpers ------------------------------------------------------------

    def _view(self, attribution: Attribution, team_id: str, direction: Direction) -> TeamAttribution:
        """Fetch or create a team's view, upgrading its direction if needed.

        Direction precedence: a rule where a team appears on both sides is
        internal regardless of what an earlier resolver decided, and any
        concrete direction beats the non-directional 'related'.
        """
        existing = attribution.teams.get(team_id)
        if existing is None:
            view = TeamAttribution(team_id=team_id, direction=direction)
            attribution.teams[team_id] = view
            return view

        existing.direction = _combine_directions(existing.direction, direction)
        return existing

    def _add_related(
        self, attribution: Attribution, team_id: str, method: str, evidence: str
    ) -> None:
        view = self._view(attribution, team_id, "related")
        # A tag, a naming convention or a device group is a deliberate label:
        # somebody wrote this rule down as belonging to this team. Direction is
        # unknown, ownership is not.
        view.claim_own(evidence)
        view.matches.append(
            OwnerMatch(
                team_id=team_id,
                method=method,  # type: ignore[arg-type]
                confidence=CONFIDENCE.get(method, 50),
                evidence=evidence,
                side="rule",
            )
        )

    def _describe(self, side: ResolvedAddresses) -> list[str]:
        """Readable description of the far side of a connection."""
        if side.is_any:
            return ["any"]
        out = list(side.networks)
        out.extend(f"fqdn:{f}" for f in side.fqdns)
        out.extend(
            f"{u.name} (unresolved: {u.reason.value})"
            for u in side.unresolved
            if u.reason.value != "fqdn"
        )
        return out or list(side.raw)

    @staticmethod
    def _has_match_from(attribution: Attribution, method: str) -> bool:
        normalised = "device-group" if method == "device_group" else method
        return any(
            match.method == normalised
            for view in attribution.teams.values()
            for match in view.matches
        )


def ownership_tag_team(tag: str, config: OwnershipConfig) -> str | None:
    """The team id an ownership tag names, or None if it names none.

    A tag in PAN-OS is a classification before it is anything else --
    ``GlobalProtect-Clients`` says what an object *is*, and dynamic address
    groups are built on precisely that. Ownership-by-tag is a convention an
    estate adds on top, and it is only legible once the estate has written the
    convention down. That is what ``tag_prefixes`` and ``tag_suffixes`` are:
    the statement "a tag shaped like this names an owner". Anything not shaped
    that way is a type, and this returns None for it.

    Shared with the team derivation, which needs the same question answered
    before any team exists to compare against -- so this decides on shape
    alone and leaves "does that team exist?" to the caller.
    """
    normalised = tag if config.tag_case_sensitive else tag.lower()

    for prefix in config.tag_prefixes:
        marker = prefix if config.tag_case_sensitive else prefix.lower()
        if marker and normalised.startswith(marker):
            return _clean_tag_value(tag[len(prefix):])

    for suffix in config.tag_suffixes:
        marker = suffix if config.tag_case_sensitive else suffix.lower()
        if marker and normalised.endswith(marker):
            return _clean_tag_value(tag[: len(tag) - len(suffix)])

    return None


def _clean_tag_value(value: str) -> str | None:
    """Strip the separators a convention leaves behind, e.g. 'owner: payments'."""
    cleaned = value.strip().strip(":-_ ").strip()
    return cleaned or None


def _combine_directions(existing: Direction, incoming: Direction) -> Direction:
    if existing == incoming:
        return existing
    if "related" in (existing, incoming):
        return existing if incoming == "related" else incoming
    # outbound + inbound seen for the same team means both sides are theirs.
    return "internal"


def _merge(existing: list[str], incoming: list[str]) -> list[str]:
    """Union preserving first-seen order, so output stays deterministic."""
    seen = set(existing)
    out = list(existing)
    for item in incoming:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
