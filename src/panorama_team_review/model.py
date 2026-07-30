"""Normalised, vendor-neutral representation of a firewall configuration.

Everything downstream of the parsers (ownership resolution, analysis, all
renderers) works exclusively against the types in this module.  The parsers are
the only place that knows about PAN-OS XML; adding another vendor means writing
another parser, not touching the reports.

The model is intentionally serialisable: ``Snapshot`` round-trips through JSON,
which is what makes the ``diff`` command and the JSON report possible.
"""

from __future__ import annotations

import ipaddress
from datetime import date, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Named aliases for literal sets used in more than one module. Spelling them
# out once keeps the parser, the extractor and the renderers from drifting.
DateRole = Literal["created", "changed", "expires", "reviewed", "unknown"]
TicketField = Literal["description", "tag", "rule-name"]
OutputFormat = Literal["html", "xlsx", "pdf", "json"]
OwnershipMethod = Literal["inventory", "tag", "regex", "device_group", "zone"]


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------


class Rulebase(StrEnum):
    """Where a rule sits in the evaluation order.

    Panorama pushes ``PRE`` rules before, and ``POST`` rules after, the rules
    configured locally on the firewall.  Keeping them apart matters because a
    system owner needs to know whether a rule can be changed locally at all.
    """

    PRE = "pre"
    POST = "post"
    LOCAL = "local"
    DEFAULT = "default"


class Location(BaseModel):
    """Where in the configuration hierarchy an object or rule was defined."""

    source: str = Field(description="Backup file or device this came from")
    kind: Literal["panorama", "firewall"] = "firewall"
    device: str | None = Field(
        default=None,
        description="Firewall this local configuration belongs to. None for Panorama.",
    )
    device_group: str | None = Field(
        default=None, description="Panorama device group; None for firewall-local config"
    )
    vsys: str | None = Field(default=None, description="Virtual system, e.g. 'vsys1'")
    shared: bool = Field(default=False, description="Defined in the Panorama 'shared' scope")
    rulebase: Rulebase | None = None

    @property
    def scope(self) -> str:
        """The namespace an object name is unique within.

        Device groups are unique estate-wide, so their name is the scope. But
        ``shared`` and ``vsys1`` are *per device* -- every firewall has its own
        -- and a Panorama backup archive contains one configuration per managed
        firewall. Without the device qualifier, merging that archive collapses
        forty-seven separate namespaces into one, and an object called
        ``web-server`` on one firewall silently answers lookups meant for the
        identically named object on another. The report would then show the
        wrong addresses for a rule, which is the worst failure this tool has.
        """
        if self.device_group:
            return self.device_group
        local = "shared" if self.shared else (self.vsys or "local")
        return f"{self.device}:{local}" if self.device else local

    def label(self) -> str:
        """Short human-readable position, shown in every report."""
        parts = [self.scope]
        if self.rulebase and self.rulebase is not Rulebase.LOCAL:
            parts.append(self.rulebase.value)
        return "/".join(parts)


# ---------------------------------------------------------------------------
# Address and service objects
# ---------------------------------------------------------------------------


class AddressKind(StrEnum):
    IP_NETMASK = "ip-netmask"
    IP_RANGE = "ip-range"
    IP_WILDCARD = "ip-wildcard"
    FQDN = "fqdn"


class AddressObject(BaseModel):
    name: str
    kind: AddressKind
    value: str
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    location: Location


class AddressGroup(BaseModel):
    """Static or dynamic (tag-filter based) address group."""

    name: str
    members: list[str] = Field(default_factory=list, description="Static member names")
    dynamic_filter: str | None = Field(
        default=None, description="Tag expression of a dynamic address group"
    )
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    location: Location

    @property
    def is_dynamic(self) -> bool:
        return self.dynamic_filter is not None


class ServiceObject(BaseModel):
    name: str
    protocol: Literal["tcp", "udp", "sctp", "other"]
    port: str = Field(default="", description="Destination port spec, e.g. '443' or '8000-8100'")
    source_port: str = ""
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    location: Location


class ServiceGroup(BaseModel):
    name: str
    members: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    location: Location


class Tag(BaseModel):
    name: str
    color: str | None = None
    comments: str = ""
    location: Location


class ExternalList(BaseModel):
    """An external dynamic list: addresses fetched by the device at runtime.

    The configuration holds only the URL and the refresh schedule, never the
    contents. Recording these by name is what lets a report say "this is an
    EDL, its contents live on the device" instead of "unknown object", which
    reads like a misconfiguration and is not one.
    """

    name: str
    list_type: str = Field(default="", description="ip, domain, url, predefined-ip, …")
    url: str = ""
    description: str = ""
    location: Location


# ---------------------------------------------------------------------------
# Resolution results
# ---------------------------------------------------------------------------


class UnresolvedReason(StrEnum):
    """Why an endpoint could not be reduced to concrete networks.

    Reporting these honestly matters more than guessing: a report that silently
    drops an external dynamic list understates a system's exposure.
    """

    EXTERNAL_DYNAMIC_LIST = "external-dynamic-list"
    REGION = "region"
    FQDN = "fqdn"
    UNKNOWN_OBJECT = "unknown-object"
    WILDCARD = "ip-wildcard"
    CIRCULAR_GROUP = "circular-group"
    DEPTH_LIMIT = "depth-limit"


class Unresolved(BaseModel):
    name: str
    reason: UnresolvedReason
    detail: str = ""


class AddressMember(BaseModel):
    """What one named object in a rule field resolved to, on its own.

    The flattened union in ``ResolvedAddresses.networks`` is what the firewall
    matches on, but it loses which object contributed what -- and the object
    name is the only part of a rule a reader outside the network team can act
    on. ``grp-time-servers`` means something to them; ``10.20.12.34/32`` does
    not, and a cell holding forty of those is unreadable however correct it is.
    Keeping the breakdown lets a report lead with the name and put the
    addresses behind it.
    """

    name: str = Field(description="The object or group name as written in the rule")
    networks: list[str] = Field(default_factory=list)
    fqdns: list[str] = Field(default_factory=list)
    unresolved: list[Unresolved] = Field(default_factory=list)

    @property
    def is_literal(self) -> bool:
        """True when the rule named an address directly rather than an object."""
        return self.networks == [self.name] or [self.name] == [
            n.split("/")[0] for n in self.networks
        ]


class ResolvedAddresses(BaseModel):
    """The flattened result of resolving a rule's source or destination field."""

    is_any: bool = False
    negated: bool = False
    raw: list[str] = Field(default_factory=list, description="Object names as written in the rule")
    networks: list[str] = Field(
        default_factory=list, description="Flattened CIDRs, canonical string form"
    )
    fqdns: list[str] = Field(default_factory=list)
    unresolved: list[Unresolved] = Field(default_factory=list)
    members: list[AddressMember] = Field(
        default_factory=list,
        description="Per-object breakdown of the same resolution, in the order the rule "
        "names them",
    )

    def as_networks(self) -> list[IPNetwork]:
        return [ipaddress.ip_network(n) for n in self.networks]

    @property
    def address_count(self) -> int:
        """Number of individual addresses covered; ``-1`` for 'any'."""
        if self.is_any:
            return -1
        return sum(n.num_addresses for n in self.as_networks())


class ResolvedServices(BaseModel):
    is_any: bool = False
    is_application_default: bool = False
    raw: list[str] = Field(default_factory=list)
    ports: list[str] = Field(
        default_factory=list, description="Canonical 'proto/port' entries, e.g. 'tcp/443'"
    )
    unresolved: list[Unresolved] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Rule metadata extracted from free-text fields
# ---------------------------------------------------------------------------


class TicketRef(BaseModel):
    """A ticket reference recovered from a rule description or tag."""

    system: str = Field(description="Name of the matching pattern, e.g. 'jira'")
    id: str
    url: str | None = None
    source_field: TicketField = "description"


class DateRef(BaseModel):
    """A timestamp recovered from free text, with the role we inferred for it."""

    role: DateRole = "unknown"
    value: date
    raw: str = Field(description="The literal text this was parsed from")
    by: str | None = Field(
        default=None,
        description="Who the surrounding text names alongside this date, where the "
        "convention records one -- 'CHG0041234 (a.beck: 2024-05-30)' names the person who "
        "made the change, and that is half of what the date is worth knowing.",
    )


class RuleMetadata(BaseModel):
    tickets: list[TicketRef] = Field(default_factory=list)
    dates: list[DateRef] = Field(default_factory=list)
    requester: str | None = None

    @property
    def expires_on(self) -> date | None:
        expiries = [d.value for d in self.dates if d.role == "expires"]
        return min(expiries) if expiries else None

    @property
    def created_on(self) -> date | None:
        created = [d.value for d in self.dates if d.role == "created"]
        return min(created) if created else None

    @property
    def changed_on(self) -> date | None:
        """The most recent recorded edit. Latest, not earliest: a rule touched
        three times was last touched on the last of those dates."""
        changed = [d.value for d in self.dates if d.role == "changed"]
        return max(changed) if changed else None

    @property
    def latest_change(self) -> DateRef | None:
        """The last edit, with whoever made it.

        A description holding a rule's whole history yields one entry per
        change. Listing them all under "last changed" answers a question
        nobody asked and buries the one date that matters -- the report says
        when the rule was last touched, and the rest stays in the description
        it came from.
        """
        changes = [d for d in self.dates if d.role == "changed"]
        return max(changes, key=lambda entry: entry.value) if changes else None

    @property
    def change_count(self) -> int:
        return sum(1 for d in self.dates if d.role == "changed")


class HitCount(BaseModel):
    """Runtime counters.

    Never present in a configuration backup -- this is populated only by the
    opt-in enrichment module and carries its own provenance so a report can
    state where the numbers came from and how old they are.
    """

    hit_count: int = 0
    last_hit: datetime | None = None
    first_hit: datetime | None = None
    last_reset: datetime | None = None
    rule_creation: datetime | None = None
    rule_modification: datetime | None = None
    collected_at: datetime | None = None
    source: str = Field(default="", description="Provenance, e.g. 'api:fw01.example.com'")

    @property
    def is_unused(self) -> bool:
        return self.hit_count == 0


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


class RuleAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    DROP = "drop"
    RESET_CLIENT = "reset-client"
    RESET_SERVER = "reset-server"
    RESET_BOTH = "reset-both"

    @property
    def permits_traffic(self) -> bool:
        return self is RuleAction.ALLOW


class SecurityRule(BaseModel):
    name: str
    uuid: str | None = None
    location: Location
    order: int = Field(default=0, description="Evaluation order within the rulebase")

    disabled: bool = False
    action: RuleAction = RuleAction.ALLOW
    rule_type: str = Field(default="universal", description="universal | intrazone | interzone")

    from_zones: list[str] = Field(default_factory=lambda: ["any"])
    to_zones: list[str] = Field(default_factory=lambda: ["any"])
    source: ResolvedAddresses = Field(default_factory=ResolvedAddresses)
    destination: ResolvedAddresses = Field(default_factory=ResolvedAddresses)
    source_users: list[str] = Field(default_factory=lambda: ["any"])
    applications: list[str] = Field(default_factory=lambda: ["any"])
    services: ResolvedServices = Field(default_factory=ResolvedServices)
    categories: list[str] = Field(default_factory=lambda: ["any"])

    description: str = ""
    tags: list[str] = Field(default_factory=list)
    group_tag: str | None = None
    schedule: str | None = None

    log_start: bool = False
    log_end: bool = True
    profile_group: str | None = None

    metadata: RuleMetadata = Field(default_factory=RuleMetadata)
    hits: HitCount | None = None
    target_devices: list[str] = Field(
        default_factory=list, description="Firewall serials this rule is targeted at"
    )

    @property
    def is_any_any(self) -> bool:
        return self.source.is_any and self.destination.is_any

    @property
    def allows_any_service(self) -> bool:
        return self.services.is_any and "any" in self.applications


class NatRule(BaseModel):
    """NAT rules are reported because they explain *why* an address is reachable."""

    name: str
    uuid: str | None = None
    location: Location
    order: int = 0
    disabled: bool = False
    from_zones: list[str] = Field(default_factory=lambda: ["any"])
    to_zones: list[str] = Field(default_factory=lambda: ["any"])
    source: ResolvedAddresses = Field(default_factory=ResolvedAddresses)
    destination: ResolvedAddresses = Field(default_factory=ResolvedAddresses)
    service: str = "any"
    translated_source: ResolvedAddresses | None = None
    translated_destination: ResolvedAddresses | None = None
    translated_port: str | None = None
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: RuleMetadata = Field(default_factory=RuleMetadata)


# ---------------------------------------------------------------------------
# Devices and the snapshot as a whole
# ---------------------------------------------------------------------------


class DeviceGroup(BaseModel):
    name: str
    parent: str | None = None
    devices: list[str] = Field(default_factory=list, description="Member firewall serials")
    description: str = ""

    def ancestry(self, groups: dict[str, DeviceGroup]) -> list[str]:
        """Names from this group up to the root, nearest first."""
        chain: list[str] = []
        seen: set[str] = set()
        current: str | None = self.name
        while current and current not in seen:
            seen.add(current)
            chain.append(current)
            node = groups.get(current)
            current = node.parent if node else None
        return chain


class ManagedDevice(BaseModel):
    serial: str
    hostname: str | None = None
    ip_address: str | None = None
    device_group: str | None = None
    model: str | None = None
    sw_version: str | None = None


class SnapshotMeta(BaseModel):
    """Provenance of the parsed backup, shown on every report."""

    source_file: str
    source_files: list[str] = Field(
        default_factory=list,
        description="Every configuration document this snapshot was built from. A Panorama "
        "scheduled backup holds one per managed firewall, so this is routinely dozens.",
    )
    source_type: Literal["panorama", "firewall"] = "firewall"
    file_mtime: datetime | None = None
    parsed_at: datetime
    pan_os_version: str | None = None
    hostname: str | None = None
    tool_version: str = "0.1.0"
    config_hash: str = Field(default="", description="SHA-256 of the raw config, for change detection")

    @property
    def document_count(self) -> int:
        return len(self.source_files) or 1

    @property
    def backup_label(self) -> str:
        """The backup as an operator refers to it: one file name, not fifty.

        Members of an archive are recorded as ``archive.tgz:member.xml``, so
        the common prefix is the archive itself. Naming the archive is useful
        -- it identifies which run produced the report -- where naming its
        dozens of members is not, which is why reports show this and not
        ``source_file``.
        """
        archives = {name.split(":", 1)[0] for name in self.source_files}
        if len(archives) == 1:
            return archives.pop()
        return self.source_file


class Snapshot(BaseModel):
    """One parsed backup file: the complete input to the reporting stage."""

    meta: SnapshotMeta
    device_groups: dict[str, DeviceGroup] = Field(default_factory=dict)
    devices: list[ManagedDevice] = Field(default_factory=list)
    addresses: list[AddressObject] = Field(default_factory=list)
    address_groups: list[AddressGroup] = Field(default_factory=list)
    services: list[ServiceObject] = Field(default_factory=list)
    service_groups: list[ServiceGroup] = Field(default_factory=list)
    tags: list[Tag] = Field(default_factory=list)
    external_lists: list[ExternalList] = Field(default_factory=list)
    rules: list[SecurityRule] = Field(default_factory=list)
    nat_rules: list[NatRule] = Field(default_factory=list)
    zones: dict[str, list[str]] = Field(
        default_factory=dict, description="Zone name -> interfaces, per template/vsys"
    )
    parse_warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------


class OwnerMatch(BaseModel):
    """One reason to believe a rule belongs to a team.

    Provenance is deliberately part of the model: an owner reading the report
    must be able to see *why* a rule showed up in their list, otherwise they
    cannot correct a wrong assignment.
    """

    team_id: str
    method: Literal["inventory", "tag", "device-group", "zone", "regex", "fallback"]
    confidence: int = Field(default=50, ge=0, le=100)
    evidence: str = Field(description="What matched, e.g. '10.1.2.0/24 in asset WEB-PROD'")
    side: Literal["source", "destination", "both", "rule"] = "rule"


class Team(BaseModel):
    """A system owner: the addressee of a report."""

    id: str
    name: str
    contact: str | None = None
    description: str = ""
    assets: list[str] = Field(default_factory=list, description="CIDRs owned by this team")
    asset_labels: dict[str, str] = Field(
        default_factory=dict, description="CIDR -> human readable system name"
    )
    tags: list[str] = Field(default_factory=list)
    device_groups: list[str] = Field(default_factory=list)
    zones: list[str] = Field(default_factory=list)
    name_patterns: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3}[self.value]


class Finding(BaseModel):
    """A cleanup or review candidate attached to a rule."""

    code: str = Field(description="Stable identifier, e.g. 'ANY_DESTINATION'")
    title: str
    severity: Severity
    rule_name: str
    rule_uuid: str | None = None
    location: str
    detail: str
    recommendation: str = ""
    teams: list[str] = Field(default_factory=list)


class InventoryGap(BaseModel):
    """A disagreement between the object names and the team inventory.

    Where a naming convention states which account an address object belongs
    to, that statement can be checked against what the inventory says the
    account owns -- and where the two disagree, one of them is wrong. Both
    kinds below were found on a real estate, and both are invisible in an
    ordinary report: the rules touching those networks simply never reach the
    team, and nothing says why.
    """

    kind: Literal["outside-team", "claimed-twice"]
    team_id: str = Field(description="The team the object's name points at")
    object_name: str
    network: str
    detail: str
    other_team: str | None = Field(
        default=None, description="For 'claimed-twice', the second team laying claim"
    )
    other_object: str | None = None


class NamedObject(BaseModel):
    """An address object or group, with what it resolves to.

    Reported per team for the objects that live inside their networks, because
    a change request has to cite an object *name* and the naming convention is
    invisible from the outside: nobody can guess that their 10.20.12.0/24 is
    called ``grp-aws-payments-prod-01`` in the firewall.
    """

    name: str
    kind: Literal["object", "group"]
    scope: str = Field(description="Device group, vsys or 'shared' the object is defined in")
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    networks: list[str] = Field(default_factory=list)
    fqdns: list[str] = Field(default_factory=list)

    @property
    def address_count(self) -> int:
        return sum(ipaddress.ip_network(n).num_addresses for n in self.networks)


# ---------------------------------------------------------------------------
# Evaluation order
# ---------------------------------------------------------------------------


class PolicyScope(BaseModel):
    """One block of rules a firewall evaluates as a unit, and where it sits.

    Rules are grouped by scope in every report because the two questions an
    owner has about position both need it: *does this rule come before the one
    below it* (only meaningful inside a block, since sibling device groups are
    never evaluated together) and *who would have to change it* (the block
    decides that -- a site's post-rules are the site's, ``shared`` belongs to
    the platform).
    """

    id: str = Field(description="Stable identifier, equal to Location.label() of its rules")
    title: str = Field(description="Heading for the block, e.g. 'FRA — post-rules'")
    stage: Literal["pre", "local", "post", "default"]
    applies_to: str = Field(description="Which firewalls evaluate this block, in words")
    position: int = Field(description="Rank of the block in the evaluation order, from 0")
    device_group: str | None = None
    device: str | None = None
    rule_count: int = Field(
        default=0,
        description="Rules in the block as a whole, including ones a given team never sees",
    )


# ---------------------------------------------------------------------------
# Report views
# ---------------------------------------------------------------------------


Coverage = Literal["own", "covered"]
"""Whether a rule was written for a team, or merely happens to include them.

The distinction decides what a report may ask of its reader.

``own``      The rule names the team's own address space -- an address object
             inside one of their networks, a tag or zone assigned to them.
             Somebody asked for this rule on their behalf. They are the ones
             who can say whether it is still needed.

``covered``  The team's network sits inside a much larger one the rule names,
             or the rule permits ``any``. Rules that let every system ping,
             resolve DNS or reach Active Directory are the usual case. The
             team benefits from them and needs to know the access exists --
             so that nobody requests what they already have, and so that
             anyone who must *not* have it can say so -- but the rule is not
             theirs to justify or remove, and asking them to review it wastes
             the attention the ``own`` rules need.
"""


class RuleView(BaseModel):
    """A rule as presented to one team, from that team's point of view."""

    rule: SecurityRule
    direction: Literal["inbound", "outbound", "internal", "related"]
    scope_id: str = Field(
        default="", description="Id of the PolicyScope in ReportBundle.scopes this rule sits in"
    )
    evaluation_rank: int = Field(
        default=0,
        description="Position of the rule in the estate-wide evaluation order. Sorting any "
        "set of views by this reproduces the order a firewall reads them in, which the "
        "per-direction lists on their own cannot.",
    )
    coverage: Coverage = "own"
    coverage_reason: str = Field(
        default="",
        description="Why this rule counts as the team's own or merely as covering them",
    )
    matched_assets: list[str] = Field(
        default_factory=list, description="The team's own CIDRs this rule touches"
    )
    highlight_networks: list[str] = Field(
        default_factory=list,
        description="Networks in the rule that caused it to appear in this team's report. "
        "Rendered bold among the resolved addresses, so that the stated reason points at "
        "something the reader can see rather than at one entry in a list of forty.",
    )
    peers: list[str] = Field(
        default_factory=list, description="The other side of the connection, resolved"
    )
    peer_teams: list[str] = Field(
        default_factory=list, description="Team ids owning the other side, if known"
    )
    matches: list[OwnerMatch] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class TeamReport(BaseModel):
    team: Team
    objects: list[NamedObject] = Field(
        default_factory=list,
        description="Address objects and groups that resolve entirely inside this team's "
        "networks -- the names to cite in a change request",
    )
    inbound: list[RuleView] = Field(default_factory=list)
    outbound: list[RuleView] = Field(default_factory=list)
    internal: list[RuleView] = Field(default_factory=list)
    related: list[RuleView] = Field(default_factory=list)
    findings: list[Finding] = Field(
        default_factory=list,
        description="Cleanup candidates on this team's own rules. Findings on rules that "
        "merely cover them are deliberately absent: they belong to whoever maintains "
        "the rule, and this report is addressed to the team.",
    )

    @property
    def rule_count(self) -> int:
        return len(self.inbound) + len(self.outbound) + len(self.internal) + len(self.related)

    @property
    def all_views(self) -> list[RuleView]:
        return [*self.inbound, *self.outbound, *self.internal, *self.related]

    def own(self, direction: str) -> list[RuleView]:
        """The team's own rules in one direction."""
        return [v for v in getattr(self, direction) if v.coverage == "own"]

    def covered(self, direction: str) -> list[RuleView]:
        """Rules that merely cover the team, in one direction.

        Split the same way as their own rules: "who may reach me" and "what may
        my systems reach" are different questions with different consequences,
        and that does not stop being true because the rule was written
        centrally.
        """
        views = [v for v in getattr(self, direction) if v.coverage == "covered"]
        views.sort(key=lambda v: v.evaluation_rank)
        return views

    @property
    def own_views(self) -> list[RuleView]:
        return [v for v in self.all_views if v.coverage == "own"]

    @property
    def covered_views(self) -> list[RuleView]:
        """Rules that include the team's networks without being about them.

        Returned as one list rather than split by direction: they are read as
        a block ("what am I already allowed to do?"), not reviewed rule by
        rule, and splitting a hundred of them across four tables only makes
        that harder. Re-sorted for the same reason -- concatenating the
        per-direction lists would order them by direction first, which is not
        the order any firewall reads them in.
        """
        views = [v for v in self.all_views if v.coverage == "covered"]
        views.sort(key=lambda v: v.evaluation_rank)
        return views

    @property
    def own_rule_count(self) -> int:
        return len(self.own_views)


class ReportBundle(BaseModel):
    """Everything the renderers need: the full result of one tool run."""

    meta: SnapshotMeta
    generated_at: datetime
    scopes: list[PolicyScope] = Field(
        default_factory=list,
        description="Every rule block in the configuration, in evaluation order",
    )
    teams: list[TeamReport] = Field(default_factory=list)
    unassigned: list[RuleView] = Field(
        default_factory=list, description="Rules no team could be determined for"
    )
    global_findings: list[Finding] = Field(default_factory=list)
    inventory_gaps: list[InventoryGap] = Field(
        default_factory=list,
        description="Where the object names and the team inventory disagree about who "
        "owns a network. Addressed to whoever maintains the inventory, so it appears in "
        "the cross-team overview rather than in a team's report.",
    )
    stats: dict[str, int] = Field(default_factory=dict)
    hitcount_available: bool = False
    notes: list[str] = Field(default_factory=list)
