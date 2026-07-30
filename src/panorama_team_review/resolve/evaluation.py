"""Where a rule sits in the firewall's evaluation order.

A rule's position is part of its meaning.  The firewall stops at the first
match, so a broad allow further up makes a narrower rule below it dead, and a
deny above an allow silently overrides it.  Listing rules alphabetically -- or
by device-group name, which is what sorting on ``Location.label()`` amounts to
-- tells an owner nothing about what actually happens to a packet, and worse,
looks like it does.

Panorama stores the effective order nowhere.  It emerges from *where* a rule
was defined.  For one firewall the sequence is::

    shared pre-rules
    device-group pre-rules   -- top-most parent first, the firewall's own last
    the firewall's own local rules
    device-group post-rules  -- the firewall's own first, top-most parent last
    shared post-rules
    the default rules

Pre-rules therefore run outermost-first and post-rules innermost-first, which
is what puts the estate-wide catch-all deny at the very end where it belongs.

**One caveat this module cannot engineer away.** That sequence is per firewall.
Rules in two sibling device groups -- ``FRA`` and ``GOP`` -- are never
evaluated by the same device, so no single total order over the whole estate
exists.  What is produced here is the true order wherever a team's rules share
one device-group chain (the common case, and exact), and a stable
stage-grouped order otherwise: all pre-rules before all local rules before all
post-rules, with sibling branches kept in separate blocks rather than
interleaved into a sequence that no firewall ever evaluates.  Reports render
those blocks with their own heading and say which firewalls each one reaches,
so the grouping is visible rather than implied.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Literal

from ..model import (
    DeviceGroup,
    Location,
    ManagedDevice,
    PolicyScope,
    Rulebase,
    SecurityRule,
    Snapshot,
)

# Stage ranks.  Ordering is by stage first, so every pre-rule precedes every
# local rule regardless of which device group it came from.
STAGE_PRE = 0
STAGE_LOCAL = 1
STAGE_POST = 2
STAGE_DEFAULT = 3

# `shared` sits above the root device group in both directions: first among
# pre-rules, last among post-rules.  Giving it a depth one step above the root
# makes the same arithmetic produce both.
_SHARED_DEPTH = -1

# Annotated rather than inferred: `PolicyScope.stage` is a Literal, and an
# inferred `dict[int, str]` would let a typo reach the model unchecked.
_STAGE_NAMES: dict[int, Literal["pre", "local", "post", "default"]] = {
    STAGE_PRE: "pre",
    STAGE_LOCAL: "local",
    STAGE_POST: "post",
    STAGE_DEFAULT: "default",
}


@dataclass(slots=True)
class EvaluationOrder:
    """Evaluation-order keys and scope descriptions for one snapshot."""

    snapshot: Snapshot
    _depths: dict[str, int] = field(default_factory=dict, init=False)
    _keys: dict[str, tuple[int, int, str]] = field(default_factory=dict, init=False)
    _scopes: dict[str, PolicyScope] = field(default_factory=dict, init=False)
    _counts: Counter[str] = field(default_factory=Counter, init=False)

    def __post_init__(self) -> None:
        for rule in self.snapshot.rules:
            self._counts[rule.location.label()] += 1
        # Scopes are built for the whole snapshot up front so that `position`
        # is a rank over the complete configuration rather than over whichever
        # subset a given team happens to see. Two teams comparing reports
        # otherwise read the same block as step 2 and step 5.
        for rule in self.snapshot.rules:
            self._register(rule.location)
        for rank, scope in enumerate(sorted(self._scopes.values(), key=self._rank_of)):
            self._scopes[scope.id] = scope.model_copy(update={"position": rank})

    # -- public API ---------------------------------------------------------

    def key(self, rule: SecurityRule) -> tuple[int, int, str, int, str]:
        """Sort key placing a rule where the firewall would evaluate it.

        The rule name is the final tiebreak so that two rules sharing a
        position -- which happens when a snapshot merges configurations that
        number their rulebases independently -- still sort deterministically.
        """
        stage, rank, scope_id = self._sort_key(rule.location)
        return (stage, rank, scope_id, rule.order, rule.name)

    def scope_of(self, rule: SecurityRule) -> PolicyScope:
        return self._register(rule.location)

    def scopes(self) -> list[PolicyScope]:
        """Every block in the configuration, in evaluation order."""
        return sorted(self._scopes.values(), key=lambda s: s.position)

    # -- construction -------------------------------------------------------

    def _register(self, location: Location) -> PolicyScope:
        scope_id = location.label()
        cached = self._scopes.get(scope_id)
        if cached is None:
            cached = self._build_scope(scope_id, location)
            self._scopes[scope_id] = cached
        return cached

    def _sort_key(self, location: Location) -> tuple[int, int, str]:
        scope_id = location.label()
        cached = self._keys.get(scope_id)
        if cached is not None:
            return cached

        stage = _stage_of(location)
        group = location.device_group
        depth = self._depth(group) if group else _SHARED_DEPTH

        # Post-rules run inside-out: the device group closest to the firewall
        # is evaluated first and `shared` last.  Negating the depth turns the
        # same hierarchy into that reversed sequence.
        rank = depth if stage in (STAGE_PRE, STAGE_DEFAULT) else -depth
        if stage == STAGE_LOCAL:
            rank = 0

        key = (stage, rank, scope_id)
        self._keys[scope_id] = key
        return key

    def _rank_of(self, scope: PolicyScope) -> tuple[int, int, str]:
        return self._keys[scope.id]

    def _build_scope(self, scope_id: str, location: Location) -> PolicyScope:
        stage = _stage_of(location)
        self._sort_key(location)
        return PolicyScope(
            id=scope_id,
            title=self._title(location, stage),
            stage=_STAGE_NAMES[stage],
            applies_to=self._applies_to(location, location.device_group),
            position=0,
            device_group=location.device_group,
            device=location.device,
            rule_count=self._counts.get(scope_id, 0),
        )

    def _title(self, location: Location, stage: int) -> str:
        suffix = {
            STAGE_PRE: "pre-rules",
            STAGE_POST: "post-rules",
            STAGE_LOCAL: "rules configured on the firewall",
            STAGE_DEFAULT: "default rules",
        }[stage]

        if location.device_group:
            return f"{location.device_group} — {suffix}"
        if location.device:
            return f"{location.device} — {suffix}"
        return f"Shared — {suffix}"

    def _applies_to(self, location: Location, group: str | None) -> str:
        if group:
            return self._device_group_reach(group)
        if location.device:
            return f"{location.device} only"
        managed = len({d.serial for d in self.snapshot.devices if d.device_group})
        if managed:
            return f"all {managed} firewalls managed by this Panorama"
        return "every firewall managed by this Panorama"

    def _device_group_reach(self, group: str) -> str:
        """Which firewalls a device group's rules reach, named where possible.

        Naming them matters: an owner who sees ``DC — pre-rules`` cannot tell
        whether that is one site or the whole estate, and the difference
        decides whether a change request goes to the site or to the platform.
        """
        descendants = [group, *self._descendants(group)]
        devices = [
            device
            for name in descendants
            for device in self.snapshot.devices
            if device.device_group == name
        ]
        if devices:
            names = sorted({_device_name(d) for d in devices})
            shown = ", ".join(names[:6])
            more = f" and {len(names) - 6} more" if len(names) > 6 else ""
            return f"{shown}{more}"

        children = sorted(self._descendants(group))
        if children:
            return "the device groups below it: " + ", ".join(children)
        return f"device group {group} (no firewall is assigned to it)"

    def _descendants(self, group: str) -> list[str]:
        return [
            name
            for name, entry in self.snapshot.device_groups.items()
            if name != group and group in _ancestry(entry, self.snapshot.device_groups)
        ]

    def _depth(self, group: str) -> int:
        """Distance from the root device group; the root itself is 0."""
        cached = self._depths.get(group)
        if cached is not None:
            return cached
        entry = self.snapshot.device_groups.get(group)
        depth = len(_ancestry(entry, self.snapshot.device_groups)) - 1 if entry else 0
        self._depths[group] = depth
        return depth


def _stage_of(location: Location) -> int:
    match location.rulebase:
        case Rulebase.PRE:
            return STAGE_PRE
        case Rulebase.POST:
            return STAGE_POST
        case Rulebase.DEFAULT:
            return STAGE_DEFAULT
        case _:
            return STAGE_LOCAL


def _ancestry(entry: DeviceGroup | None, groups: dict[str, DeviceGroup]) -> list[str]:
    return entry.ancestry(groups) if entry else []


def _device_name(device: ManagedDevice) -> str:
    return device.hostname or device.serial
