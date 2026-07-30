"""Cleanup and hygiene checks.

Each check is a small function registered under a stable code.  The codes are
part of the tool's contract: they appear in the JSON output and in the Excel
sheet, so a team can filter or suppress a specific class of finding, and the
set a report was produced with stays comparable over time.

The checks are deliberately conservative.  A report an owner stops trusting is
worse than no report, and the fastest way to lose that trust is to flag a
correct rule as a problem.  Where a check cannot be sure -- most obviously
"unused", which needs hit counts the backup does not contain -- it does not run
at all rather than guessing.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from datetime import date, timedelta

from ..config import AnalysisConfig
from ..model import Finding, SecurityRule, Severity, Snapshot

CheckFn = Callable[[SecurityRule, "CheckContext"], list[Finding]]
_REGISTRY: dict[str, CheckFn] = {}


class CheckContext:
    """Everything a check needs beyond the rule itself."""

    def __init__(self, config: AnalysisConfig, today: date, snapshot: Snapshot | None = None):
        self.config = config
        self.today = today
        self.snapshot = snapshot
        self._ignore_patterns = [re.compile(p) for p in config.ignore_rule_patterns]
        self._ignore_tags = {t.lower() for t in config.ignore_tags}
        self.flag_patterns = [
            (re.compile(spec.pattern), spec) for spec in config.flag_object_patterns
        ]

        self._internet_zones = {zone.lower() for zone in config.internet_zones}

    def is_exempt(self, rule: SecurityRule) -> bool:
        if self._ignore_tags & {t.lower() for t in rule.tags}:
            return True
        return any(p.search(rule.name) for p in self._ignore_patterns)

    def leaves_the_estate(self, rule: SecurityRule) -> bool:
        """Does every destination zone of this rule lead off the estate?

        Zone names are the only signal a configuration gives for this, and
        every estate uses the same handful -- ``outside`` and ``untrust`` are
        the PAN-OS conventions. Requiring *all* destination zones to be
        external is deliberate: a rule going to both ``outside`` and ``inside``
        does permit unrestricted internal access, and that is worth saying.
        """
        if not self._internet_zones or not rule.to_zones:
            return False
        if "any" in {zone.lower() for zone in rule.to_zones}:
            return False
        return all(zone.lower() in self._internet_zones for zone in rule.to_zones)


def check(code: str) -> Callable[[CheckFn], CheckFn]:
    def decorator(fn: CheckFn) -> CheckFn:
        _REGISTRY[code] = fn
        return fn

    return decorator


def _finding(
    rule: SecurityRule,
    code: str,
    title: str,
    severity: Severity,
    detail: str,
    recommendation: str = "",
) -> Finding:
    return Finding(
        code=code,
        title=title,
        severity=severity,
        rule_name=rule.name,
        rule_uuid=rule.uuid,
        location=rule.location.label(),
        detail=detail,
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# Overly broad rules
# ---------------------------------------------------------------------------


@check("ANY_ANY")
def _any_any(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    if not rule.is_any_any or not rule.action.permits_traffic or rule.disabled:
        return []
    return [
        _finding(
            rule, "ANY_ANY", "Permits any source to any destination", Severity.HIGH,
            "Both source and destination are 'any', so this rule allows traffic between all "
            "systems the firewall sees.",
            "Restrict at least one side to the address objects actually needed.",
        )
    ]


@check("ANY_DESTINATION")
def _any_destination(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    if rule.is_any_any or rule.disabled or not rule.action.permits_traffic:
        return []
    if not rule.destination.is_any:
        return []
    if ctx.leaves_the_estate(rule):
        # A rule permitting traffic to the internet has 'any' as its
        # destination because the internet is its destination. There is no
        # tighter way to write it, so telling an owner to "name the
        # destinations" is advice they cannot take -- and a report that asks
        # for the impossible is one that gets skimmed. What is still worth
        # flagging about such a rule is what it may carry, which ANY_SERVICE
        # covers and this check leaves alone.
        return []
    return [
        _finding(
            rule, "ANY_DESTINATION", "Destination is 'any'", Severity.MEDIUM,
            "The listed sources may reach any destination through this rule.",
            "Name the destinations this access is meant for.",
        )
    ]


@check("ANY_SOURCE")
def _any_source(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    if rule.is_any_any or rule.disabled or not rule.action.permits_traffic:
        return []
    if not rule.source.is_any:
        return []
    return [
        _finding(
            rule, "ANY_SOURCE", "Source is 'any'", Severity.MEDIUM,
            "Any system reaching this firewall may use this rule to access the listed "
            "destinations.",
            "Restrict the source to the networks that legitimately need this access.",
        )
    ]


@check("ANY_SERVICE")
def _any_service(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    if rule.disabled or not rule.action.permits_traffic:
        return []
    if not rule.services.is_any:
        return []
    if "any" not in rule.applications:
        # App-ID constrains the traffic even with service 'any'; that is the
        # vendor-recommended pattern, not a finding.
        return []
    return [
        _finding(
            rule, "ANY_SERVICE", "No service or application restriction", Severity.MEDIUM,
            "Service is 'any' and application is 'any', so every protocol and port is permitted.",
            "Set an application (App-ID) or a service object.",
        )
    ]


@check("BROAD_NETWORK")
def _broad_network(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    if rule.disabled or not rule.action.permits_traffic:
        return []

    findings: list[Finding] = []
    for side_name, side in (("source", rule.source), ("destination", rule.destination)):
        if side.is_any:
            continue
        broad: list[str] = []
        for cidr in side.networks:
            net = ipaddress.ip_network(cidr)
            limit = (
                ctx.config.broad_network_prefix_v4
                if net.version == 4
                else ctx.config.broad_network_prefix_v6
            )
            if net.prefixlen < limit:
                broad.append(cidr)
        if broad:
            findings.append(
                _finding(
                    rule, "BROAD_NETWORK", f"Very large network in {side_name}", Severity.LOW,
                    f"The {side_name} covers {', '.join(broad[:5])}, which is broader than the "
                    "configured threshold.",
                    "Confirm the whole range is genuinely required.",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Documentation and lifecycle
# ---------------------------------------------------------------------------


@check("NO_DESCRIPTION")
def _no_description(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    if rule.description.strip():
        return []
    return [
        _finding(
            rule, "NO_DESCRIPTION", "No description", Severity.LOW,
            "The rule has no description, so its purpose cannot be established from the "
            "configuration alone.",
            "Add the purpose, the requester and the change reference.",
        )
    ]


@check("NO_TICKET")
def _no_ticket(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    if not ctx.config.require_ticket or rule.metadata.tickets:
        return []
    if not rule.description.strip():
        # Already covered by NO_DESCRIPTION; two findings for one cause is noise.
        return []
    return [
        _finding(
            rule, "NO_TICKET", "No change reference", Severity.INFO,
            "The description holds no recognisable ticket number, so the rule cannot be traced "
            "back to an approved change.",
            "Add the ticket reference to the description.",
        )
    ]


@check("EXPIRED_RULE")
def _expired(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    expires = rule.metadata.expires_on
    if expires is None or expires >= ctx.today or rule.disabled:
        return []
    days = (ctx.today - expires).days
    return [
        _finding(
            rule, "EXPIRED_RULE", "Past its stated expiry date", Severity.HIGH,
            f"The description gives an expiry of {expires:%Y-%m-%d}, {days} days ago, "
            "but the rule is still active.",
            "Remove the rule, or extend it with a new change reference.",
        )
    ]


@check("IMPOSSIBLE_DATE")
def _impossible_date(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    """A date recording something that already happened cannot be in the future.

    ``CHG0041299 a.beck 2027-07-18`` on a rule reviewed in 2026 records an edit
    that has not happened yet -- almost always a typed year. It matters beyond
    tidiness: a wrong change date is the evidence an audit uses to decide when
    a rule was last touched, and every "last reviewed" calculation built on it
    is wrong by the same amount.

    Expiry dates are deliberately excluded. Those are *supposed* to be in the
    future, and a rule with a valid expiry is the well-managed case.
    """
    future = [
        entry
        for entry in rule.metadata.dates
        if entry.role in ("created", "changed", "reviewed") and entry.value > ctx.today
    ]
    if not future:
        return []

    worst = max(future, key=lambda entry: entry.value)
    who = f" by {worst.by}" if worst.by else ""
    return [
        _finding(
            rule, "IMPOSSIBLE_DATE", "Records a change dated in the future", Severity.LOW,
            f"The description says the rule was {worst.role}{who} on "
            f"{worst.value:%Y-%m-%d}, which is after the date this report covers "
            f"({ctx.today:%Y-%m-%d}).",
            "Correct the date in the rule description; it is almost always a mistyped year.",
        )
    ]


@check("EXPIRING_SOON")
def _expiring_soon(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    expires = rule.metadata.expires_on
    if expires is None or rule.disabled:
        return []
    horizon = ctx.today + timedelta(days=ctx.config.expiring_soon_days)
    if not (ctx.today <= expires <= horizon):
        return []
    return [
        _finding(
            rule, "EXPIRING_SOON", "Expires soon", Severity.INFO,
            f"The stated expiry is {expires:%Y-%m-%d}, in {(expires - ctx.today).days} days.",
            "Confirm whether the access is still needed before it lapses.",
        )
    ]


@check("DISABLED_RULE")
def _disabled(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    if not rule.disabled:
        return []
    return [
        _finding(
            rule, "DISABLED_RULE", "Disabled", Severity.INFO,
            "The rule is disabled and has no effect on traffic.",
            "Delete it if it is no longer needed; disabled rules accumulate and obscure "
            "the active policy.",
        )
    ]


@check("NO_LOGGING")
def _no_logging(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    if rule.disabled or rule.log_end or rule.log_start:
        return []
    return [
        _finding(
            rule, "NO_LOGGING", "Traffic is not logged", Severity.MEDIUM,
            "Neither log-start nor log-end is set, so traffic matching this rule leaves no "
            "record.",
            "Enable log-end so the traffic can be traced and the rule's usage assessed.",
        )
    ]


# ---------------------------------------------------------------------------
# Usage (requires hit-count enrichment)
# ---------------------------------------------------------------------------


@check("UNUSED_RULE")
def _unused(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    # Without hit counts this check has nothing to say, and guessing would be
    # actively harmful: an owner told to delete a rule that is in fact used
    # stops trusting the whole report.
    if rule.hits is None or rule.disabled:
        return []
    if not rule.hits.is_unused:
        return []
    since = rule.hits.last_reset or rule.hits.rule_creation
    window = f" since {since:%Y-%m-%d}" if since else ""
    return [
        _finding(
            rule, "UNUSED_RULE", "Never matched any traffic", Severity.MEDIUM,
            f"The rule has zero hits{window} (counters collected "
            f"{rule.hits.collected_at:%Y-%m-%d} from {rule.hits.source}).",
            "Confirm with the system owner, then remove it.",
        )
    ]


@check("STALE_RULE")
def _stale(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    if rule.hits is None or rule.disabled or rule.hits.is_unused:
        return []
    last_hit = rule.hits.last_hit
    if last_hit is None:
        return []
    days = (ctx.today - last_hit.date()).days
    if days < ctx.config.stale_rule_days:
        return []
    return [
        _finding(
            rule, "STALE_RULE", "No traffic for a long time", Severity.LOW,
            f"Last match was {last_hit:%Y-%m-%d}, {days} days ago "
            f"(total hits: {rule.hits.hit_count}).",
            "Check whether the access is still needed.",
        )
    ]


# ---------------------------------------------------------------------------
# Object hygiene
# ---------------------------------------------------------------------------


@check("UNRESOLVED_OBJECT")
def _unresolved(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    """Flag rules whose scope could not be fully determined offline.

    This is as much about the report's own honesty as about the rule: an owner
    must know that what they are looking at is incomplete.
    """
    problems: list[str] = []
    for side_name, side in (("source", rule.source), ("destination", rule.destination)):
        for item in side.unresolved:
            if item.reason.value == "fqdn":
                continue  # FQDNs are expected and shown separately
            problems.append(f"{side_name}: {item.name} ({item.reason.value})")

    if not problems:
        return []
    return [
        _finding(
            rule, "UNRESOLVED_OBJECT", "Contains objects that cannot be resolved offline",
            Severity.INFO,
            "The effective scope of this rule is wider than shown: "
            + "; ".join(problems[:5]),
            "External dynamic lists and regions resolve only on the device; review them there.",
        )
    ]


@check("FLAGGED_OBJECT")
def _flagged_object(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    """Flag rules referencing an object whose name matches a configured pattern.

    A rule still pointing at an object named ``OUTDATED_something`` is worth
    surfacing: somebody decided that object should go, and it is still carrying
    traffic. Which markers mean that is local knowledge, so the patterns come
    from the configuration rather than being guessed here.
    """
    if not ctx.flag_patterns or rule.disabled:
        return []

    findings: list[Finding] = []
    for compiled, spec in ctx.flag_patterns:
        hits = [
            f"{side_name}: {name}"
            for side_name, side in (("source", rule.source), ("destination", rule.destination))
            for name in side.raw
            if compiled.search(name)
        ]
        if not hits:
            continue
        findings.append(
            _finding(
                rule,
                "FLAGGED_OBJECT",
                spec.title,
                Severity(spec.severity),
                f"{spec.detail} Matched: {', '.join(hits[:5])}",
                spec.recommendation,
            )
        )
    return findings


@check("EMPTY_GROUP")
def _empty_group(rule: SecurityRule, ctx: CheckContext) -> list[Finding]:
    """A rule whose address field resolved to nothing at all matches nothing."""
    if rule.disabled:
        return []
    findings: list[Finding] = []
    for side_name, side in (("source", rule.source), ("destination", rule.destination)):
        if side.is_any or not side.raw:
            continue
        if side.networks or side.fqdns or side.unresolved:
            continue
        findings.append(
            _finding(
                rule, "EMPTY_GROUP", f"The {side_name} resolves to no addresses", Severity.LOW,
                f"The {side_name} references {', '.join(side.raw[:5])}, which contains no "
                "addresses. The rule cannot match any traffic.",
                "Remove the rule or populate the referenced group.",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def available_checks() -> list[str]:
    return sorted(_REGISTRY)


def run_checks(
    rules: list[SecurityRule], config: AnalysisConfig, today: date | None = None,
    snapshot: Snapshot | None = None,
) -> dict[str, list[Finding]]:
    """Run the enabled checks over every rule.

    Returns a mapping of rule name to its findings, sorted by descending
    severity so the renderers can take the first N and still show the worst.
    """
    ctx = CheckContext(config, today or date.today(), snapshot)
    enabled = [(code, _REGISTRY[code]) for code in config.enabled_checks if code in _REGISTRY]

    results: dict[str, list[Finding]] = {}
    for rule in rules:
        if ctx.is_exempt(rule):
            continue
        found: list[Finding] = []
        for _code, fn in enabled:
            found.extend(fn(rule, ctx))
        if found:
            found.sort(key=lambda f: (-f.severity.rank, f.code))
            results[_rule_key(rule)] = found
    return results


def unknown_checks(config: AnalysisConfig) -> list[str]:
    """Configured check codes that do not exist -- surfaced as a config warning."""
    return [code for code in config.enabled_checks if code not in _REGISTRY]


def _rule_key(rule: SecurityRule) -> str:
    """Rules are only unique per location, not globally."""
    return f"{rule.location.label()}|{rule.name}"


def rule_key(rule: SecurityRule) -> str:
    return _rule_key(rule)
