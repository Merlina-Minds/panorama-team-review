"""Compare two JSON report bundles.

A review cycle is not a one-off. The second time an owner receives a report,
the useful question is not "what does my policy look like" -- they read that
last quarter -- but "what changed since then". This turns two runs into that
answer.

Rules are matched by UUID where both sides have one, since PAN-OS keeps a
rule's UUID stable across renames, and by location plus name otherwise.
"""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..errors import PanReviewError


@dataclass
class RuleChange:
    key: str
    name: str
    location: str
    fields: dict[str, tuple[Any, Any]] = field(default_factory=dict)

    def summary(self) -> str:
        return ", ".join(
            f"{field_name}: {before!r} -> {after!r}"
            for field_name, (before, after) in self.fields.items()
        )


@dataclass
class DiffResult:
    added: list[dict] = field(default_factory=list)
    removed: list[dict] = field(default_factory=list)
    changed: list[RuleChange] = field(default_factory=list)
    old_source: str = ""
    new_source: str = ""
    old_generated: str = ""
    new_generated: str = ""

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed)

    def to_dict(self) -> dict:
        return {
            "old": {"source": self.old_source, "generated_at": self.old_generated},
            "new": {"source": self.new_source, "generated_at": self.new_generated},
            "added": self.added,
            "removed": self.removed,
            "changed": [
                {
                    "name": change.name,
                    "location": change.location,
                    "fields": {
                        key: {"before": before, "after": after}
                        for key, (before, after) in change.fields.items()
                    },
                }
                for change in self.changed
            ],
            "summary": {
                "added": len(self.added),
                "removed": len(self.removed),
                "changed": len(self.changed),
            },
        }


# Fields whose change matters to a system owner. Deliberately not everything:
# a diff that reports every reordering is one nobody reads.
COMPARED_FIELDS = [
    "action",
    "disabled",
    "from_zones",
    "to_zones",
    "applications",
    "description",
    "tags",
    "log_end",
]


def load_bundle(path: Path) -> dict:
    if not path.is_file():
        raise PanReviewError(f"report not found: {path}")
    raw = path.read_bytes()
    # Reports are written gzipped (.json.gz); older plain-JSON files still load.
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PanReviewError(f"{path}: not valid JSON: {exc}") from exc
    if "teams" not in data and "team" not in data:
        raise PanReviewError(
            f"{path}: does not look like a report produced by this tool "
            "(no 'teams' or 'team' key)"
        )
    return data


def diff_bundles(old: dict, new: dict) -> DiffResult:
    old_rules = _collect_rules(old)
    new_rules = _collect_rules(new)

    result = DiffResult(
        old_source=old.get("meta", {}).get("source_file", ""),
        new_source=new.get("meta", {}).get("source_file", ""),
        old_generated=old.get("generated_at", ""),
        new_generated=new.get("generated_at", ""),
    )

    for key, rule in new_rules.items():
        if key not in old_rules:
            result.added.append(_describe(rule))

    for key, rule in old_rules.items():
        if key not in new_rules:
            result.removed.append(_describe(rule))

    for key, new_rule in new_rules.items():
        old_rule = old_rules.get(key)
        if old_rule is None:
            continue
        changes = _compare(old_rule, new_rule)
        if changes:
            result.changed.append(
                RuleChange(
                    key=key,
                    name=new_rule.get("name", ""),
                    location=_location_label(new_rule),
                    fields=changes,
                )
            )

    result.added.sort(key=lambda r: (r["location"], r["name"]))
    result.removed.sort(key=lambda r: (r["location"], r["name"]))
    result.changed.sort(key=lambda c: (c.location, c.name))
    return result


def _collect_rules(bundle: dict) -> dict[str, dict]:
    """Gather every rule in a bundle, deduplicated by identity.

    A rule appears once per team it was attributed to, so the same rule is
    present several times in one bundle; the diff needs each rule once.

    Both a team's own rules and the ones that merely cover it are taken. This
    diff is between two backups, not between two review workloads: a changed
    estate-wide rule is a change whether or not anyone is being asked about it.
    ``covered`` is read from its own key and, for reports written before that
    key existed, from the direction lists it used to be mixed into.
    """
    rules: dict[str, dict] = {}

    def take(view: dict) -> None:
        rule = view.get("rule")
        if rule:
            rules.setdefault(_identity(rule), rule)

    teams = bundle.get("teams") or ([bundle["team"]] if "team" in bundle else [])
    for team in teams:
        covered = team.get("covered") or {}
        for section in ("inbound", "outbound", "internal", "related"):
            for view in team.get(section, []):
                take(view)
            for view in covered.get(section, []):
                take(view)

    for view in bundle.get("unassigned", []):
        take(view)

    return rules


def _identity(rule: dict) -> str:
    """A rule's stable identity across two backups.

    UUID first: PAN-OS keeps it stable across renames, so a renamed rule shows
    up as a change rather than as one removal plus one addition.
    """
    uuid = rule.get("uuid")
    if uuid:
        return f"uuid:{uuid}"
    return f"loc:{_location_label(rule)}|{rule.get('name', '')}"


def _location_label(rule: dict) -> str:
    location = rule.get("location", {})
    scope = (
        "shared"
        if location.get("shared")
        else location.get("device_group") or location.get("vsys") or "local"
    )
    rulebase = location.get("rulebase")
    return f"{scope}/{rulebase}" if rulebase and rulebase != "local" else scope


def _describe(rule: dict) -> dict:
    return {
        "name": rule.get("name", ""),
        "location": _location_label(rule),
        "action": rule.get("action", ""),
        "disabled": rule.get("disabled", False),
        "source": _addresses(rule.get("source", {})),
        "destination": _addresses(rule.get("destination", {})),
        "service": _services(rule.get("services", {})),
        "description": rule.get("description", ""),
        "tickets": [t.get("id") for t in rule.get("metadata", {}).get("tickets", [])],
    }


def _addresses(field_value: dict) -> str:
    if field_value.get("is_any"):
        return "any"
    networks = field_value.get("networks") or field_value.get("raw") or []
    return ", ".join(networks[:10])


def _services(field_value: dict) -> str:
    if field_value.get("is_any"):
        return "any"
    ports = field_value.get("ports") or field_value.get("raw") or []
    return ", ".join(ports[:10])


def _compare(old: dict, new: dict) -> dict[str, tuple[Any, Any]]:
    changes: dict[str, tuple[Any, Any]] = {}

    for name in COMPARED_FIELDS:
        before, after = old.get(name), new.get(name)
        if before != after:
            changes[name] = (before, after)

    if old.get("name") != new.get("name"):
        changes["name"] = (old.get("name"), new.get("name"))

    # Address and service fields are compared on their resolved form: a group
    # gaining a member changes what the rule permits even though the rule
    # itself was not touched, and that is exactly what an owner needs to see.
    for name in ("source", "destination"):
        before = _addresses(old.get(name, {}))
        after = _addresses(new.get(name, {}))
        if before != after:
            changes[name] = (before, after)

    before_services = _services(old.get("services", {}))
    after_services = _services(new.get("services", {}))
    if before_services != after_services:
        changes["services"] = (before_services, after_services)

    return changes


def format_text(result: DiffResult) -> str:
    """Render a diff for the terminal."""
    lines: list[str] = []
    lines.append(f"Comparing {result.old_source or '<old>'} -> {result.new_source or '<new>'}")
    if result.old_generated and result.new_generated:
        lines.append(f"  generated {result.old_generated[:19]} -> {result.new_generated[:19]}")
    lines.append("")

    if result.is_empty:
        lines.append("No rule changes.")
        return "\n".join(lines)

    if result.added:
        lines.append(f"Added ({len(result.added)}):")
        for rule in result.added:
            lines.append(f"  + {rule['location']}  {rule['name']}")
            lines.append(
                f"      {rule['source']} -> {rule['destination']}  [{rule['service']}]"
                f"  {rule['action']}"
            )
        lines.append("")

    if result.removed:
        lines.append(f"Removed ({len(result.removed)}):")
        for rule in result.removed:
            lines.append(f"  - {rule['location']}  {rule['name']}")
        lines.append("")

    if result.changed:
        lines.append(f"Changed ({len(result.changed)}):")
        for change in result.changed:
            lines.append(f"  ~ {change.location}  {change.name}")
            for field_name, (before, after) in change.fields.items():
                lines.append(f"      {field_name}: {before!r} -> {after!r}")
        lines.append("")

    return "\n".join(lines)
