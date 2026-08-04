"""Configuration schema and loader.

The whole tool is driven by one YAML file.  Every setting has a working
default, so a minimal configuration is a handful of lines; everything beyond
that is opt-in.  Validation happens here rather than at point of use, so a
typo in the config fails immediately with a readable message instead of
producing a subtly wrong report three minutes later.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from .errors import ConfigError
from .model import OutputFormat, OwnershipMethod, TicketField

# Defaults named once rather than inlined, so the shipped behaviour is visible
# in one place and the literal types stay checkable.
DEFAULT_FORMATS: list[OutputFormat] = ["html", "xlsx", "json"]
DEFAULT_OWNERSHIP_ORDER: list[OwnershipMethod] = [
    "inventory", "tag", "regex", "device_group", "zone",
]
DEFAULT_TICKET_FIELDS: list[TicketField] = ["description", "tag"]


def _is_list_field(annotation: Any) -> bool:
    from typing import get_origin

    return get_origin(annotation) is list


class ConfigModel(BaseModel):
    """Base for every configuration section.

    Treats an empty YAML key as an empty list. Writing

        devices:
          # - fw01.example.com
          # - fw02.example.com

    is the natural way to comment out every entry of a list, and YAML parses
    the result as null. Rejecting that is technically correct and practically
    hostile -- the shipped example configuration did exactly this and failed
    its own validation.
    """

    @model_validator(mode="before")
    @classmethod
    def _empty_key_is_empty_list(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        cleaned = dict(data)
        for name, field_info in cls.model_fields.items():
            key = field_info.alias or name
            if cleaned.get(key, ...) is None and _is_list_field(field_info.annotation):
                cleaned[key] = []
        return cleaned

# ---------------------------------------------------------------------------
# Input / output
# ---------------------------------------------------------------------------


class FetchConfig(ConfigModel):
    """Optionally pull the configuration backup live from the devices.

    Off by default.  When on, ``run`` downloads the running configuration from
    each configured device into ``backup_dir`` before analysing it, so a
    separately scheduled export landing on disk is no longer required.

    The connection -- devices, API key, TLS -- is the *same* as hit-count
    collection and is taken from the ``hitcounts`` section, so the access is
    configured once.  Read-only: only the configuration export endpoint is ever
    called.
    """

    enabled: bool = False
    filename_template: str = Field(
        default="{device}_{date}.xml",
        description="Name for each downloaded configuration. Placeholders: {device}, {date}.",
    )

    @field_validator("filename_template")
    @classmethod
    def _known_placeholders(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("fetch.filename_template must not be empty")
        allowed = {"device", "date"}
        unknown = set(re.findall(r"\{(\w+)\}", value)) - allowed
        if unknown:
            raise ValueError(
                f"fetch.filename_template uses unknown placeholder(s) {sorted(unknown)}; "
                f"allowed: {sorted(allowed)}"
            )
        return value


class InputConfig(ConfigModel):
    """Where backups come from.

    ``backup_dir`` plus ``select: latest`` is the cron case; ``pan-review run
    --backup FILE`` overrides all of it for a one-off manual run.
    """

    backup_dir: Path | None = Field(
        default=None, description="Directory the firewall writes scheduled backups into"
    )
    patterns: list[str] = Field(
        default_factory=lambda: ["*.xml", "*.xml.gz", "*.tgz", "*.tar.gz"],
        description="Glob patterns considered to be backups",
    )
    select: Literal["latest", "all"] = "latest"
    recursive: bool = False

    select_by: Literal["mtime", "filename"] = Field(
        default="mtime",
        description="How 'newest' is decided. 'mtime' uses the file timestamp. "
        "'filename' reads a date out of the name, which survives copying and "
        "syncing -- those rewrite mtimes and can make an old backup look new.",
    )
    filename_date_pattern: str = Field(
        default=r"(?P<date>\d{4}-?\d{2}-?\d{2})",
        description="Regex with a named group 'date', applied to the file name",
    )
    filename_date_formats: list[str] = Field(
        default_factory=lambda: ["%Y%m%d", "%Y-%m-%d"],
        description="strptime formats tried against the captured date",
    )
    max_age_days: int | None = Field(
        default=None,
        description="Fail if the newest backup is older than this. Guards against a silently "
        "broken backup job feeding stale reports into a review cycle.",
    )

    fetch: FetchConfig = Field(
        default_factory=FetchConfig,
        description="Optionally pull the configuration live from the devices instead of "
        "relying on a scheduled export landing in backup_dir. Reuses the hitcounts connection.",
    )

    @field_validator("backup_dir", mode="before")
    @classmethod
    def _expand(cls, v: Any) -> Any:
        return Path(os.path.expandvars(str(v))).expanduser() if v else v

    @field_validator("filename_date_pattern")
    @classmethod
    def _has_date_group(cls, value: str) -> str:
        try:
            compiled = re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid filename_date_pattern: {exc}") from exc
        if "date" not in compiled.groupindex:
            raise ValueError("filename_date_pattern needs a named group '(?P<date>...)'")
        return value


class OutputConfig(ConfigModel):
    directory: Path = Path("./out")
    formats: list[OutputFormat] = Field(default_factory=lambda: list(DEFAULT_FORMATS))
    per_team: bool = Field(default=True, description="One report file per team")
    combined: bool = Field(default=True, description="Additionally write one overview across teams")
    filename_template: str = "{date}_{team_id}_firewall-review"
    combined_filename_template: str = Field(
        default="{date}_00_OVERVIEW_all-teams",
        description="Name of the cross-team overview. The leading '00' is not decoration: "
        "a run writes one of these beside a hundred-odd team reports sharing the same date "
        "prefix, and a name that sorts into the middle of them is a name nobody finds. "
        "Digits sort ahead of letters, so this lands first in every file listing.",
    )
    timestamped_subdir: bool = Field(
        default=True, description="Write into out/<YYYY-MM-DD>/ so cron runs do not overwrite"
    )
    timestamped_subdir_format: str = Field(
        default="%Y-%m-%d",
        description="strftime format for the per-run subdirectory name. Extend it with "
        "%H-%M-%S to keep several runs on the same day instead of overwriting.",
    )
    keep_runs: int | None = Field(
        default=None, description="Delete all but the N newest run directories; None keeps all"
    )
    render_workers: int = Field(
        default=0,
        ge=0,
        description="Worker processes for rendering the report files, which is CPU-bound and "
        "dominates a large run. 0 means auto (one per CPU, capped); a small run stays "
        "sequential regardless. 1 disables parallelism. Each worker holds its own copy of the "
        "analysed estate, so raise this only if there is memory to spare.",
    )

    @field_validator("directory", mode="before")
    @classmethod
    def _expand(cls, v: Any) -> Any:
        return Path(os.path.expandvars(str(v))).expanduser()

    @field_validator("timestamped_subdir_format")
    @classmethod
    def _valid_subdir_format(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("output.timestamped_subdir_format must not be empty")
        if "/" in value or "\\" in value:
            raise ValueError(
                "output.timestamped_subdir_format must not contain a path separator -- "
                "a run directory is a single level"
            )
        # No strftime directive means every run resolves to the same name and
        # overwrites the previous one, which defeats the point of the setting.
        if datetime(2026, 1, 2, 3, 4, 5).strftime(value) == value:
            raise ValueError(
                "output.timestamped_subdir_format has no strftime directive such as %Y-%m-%d; "
                "as written every run would reuse the same directory"
            )
        return value


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------


# Addresses that are never a team's property, however they got into a group.
#
# Placeholder entries are common in generated object groups -- a loopback or an
# unspecified address stands in for "nothing here yet". Left in, one of them
# turns up as an asset of dozens of teams at once, and every rule touching it
# lands in every one of their reports.
DEFAULT_EXCLUDED_ASSET_NETWORKS = (
    "127.0.0.0/8",        # loopback
    "0.0.0.0/32",         # unspecified
    "255.255.255.255/32",  # broadcast
    "::1/128",
    "169.254.0.0/16",     # link-local
)


class DerivedTeamRule(ConfigModel):
    """Create teams from a naming convention rather than listing them by hand.

    Estates that provision networks automatically already encode ownership in
    their object names -- an address group ``aws-acme-shop-p-01`` names the
    account it belongs to, reliably, because a machine generated it. Reading
    that directly means a new account appears in the next report with no
    configuration change, instead of whenever somebody remembers to update the
    inventory.

    ``pattern`` needs a named group whose value becomes the team id via
    ``team_id``. Any other named group can be used in ``team_id``, ``team_name``
    and ``contact`` as ``{name}``.
    """

    id: str = Field(description="Name of this rule, used in diagnostics")
    source: Literal["address-group", "address-object", "tag"] = "address-group"
    pattern: str = Field(description="Regex with at least one named group")
    team_id: str = Field(default="{team}", description="Template for the team id")
    team_name: str | None = Field(
        default=None,
        description="Template for the display name. Defaults to team_id, so overriding "
        "one does not force overriding the other.",
    )
    contact: str | None = Field(
        default=None, description="Template for the contact, e.g. '{team}@example.com'"
    )
    exclude_pattern: str | None = Field(
        default=None, description="Names matching this are skipped"
    )
    min_assets: int = Field(
        default=1,
        description="Discard derived teams with fewer networks than this. Guards against "
        "a loose pattern producing dozens of near-empty teams.",
    )
    exclude_networks: list[str] = Field(
        default_factory=lambda: list(DEFAULT_EXCLUDED_ASSET_NETWORKS),
        description="Networks that never count as a team asset. Placeholder addresses "
        "appear in many groups at once and would attribute a rule to every team holding "
        "them.",
    )

    @field_validator("exclude_networks")
    @classmethod
    def _valid_networks(cls, values: list[str]) -> list[str]:
        import ipaddress

        for value in values:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"exclude_networks: {value!r} is not a network: {exc}") from exc
        return values

    @model_validator(mode="after")
    def _check(self) -> DerivedTeamRule:
        try:
            compiled = re.compile(self.pattern)
        except re.error as exc:
            raise ValueError(f"derive_teams rule {self.id!r}: invalid regex: {exc}") from exc

        groups = set(compiled.groupindex)
        if not groups:
            raise ValueError(
                f"derive_teams rule {self.id!r}: pattern needs at least one named group, "
                "e.g. '(?P<team>...)'"
            )

        for field_name, template in (
            ("team_id", self.team_id),
            ("team_name", self.team_name or ""),
            ("contact", self.contact),
        ):
            if not template:
                continue
            missing = [key for key in re.findall(r"\{(\w+)\}", template) if key not in groups]
            if missing:
                raise ValueError(
                    f"derive_teams rule {self.id!r}: {field_name} references {missing}, "
                    f"which the pattern does not capture (it captures {sorted(groups)})"
                )

        if self.exclude_pattern:
            try:
                re.compile(self.exclude_pattern)
            except re.error as exc:
                raise ValueError(
                    f"derive_teams rule {self.id!r}: invalid exclude_pattern: {exc}"
                ) from exc
        return self


class ObjectNamingRule(ConfigModel):
    """An object name that states which team the object belongs to.

    Not used to attribute rules -- addresses do that, and better. Used to
    *check* the inventory: where a name says which account a network belongs to
    and the inventory says that network belongs to nobody, or to somebody else,
    one of the two is wrong. The disagreement is otherwise silent -- the rules
    touching that network simply never reach the team's report, which then
    looks complete.

    Same shape as ``derive_teams``: a regex with named groups, and a template
    that builds the team id from them. Write one rule per environment rather
    than one rule with a translation table. An estate whose ``staging``
    networks belong to accounts whose id ends in ``-t`` is exactly the case
    that has to be stated rather than inferred:

        object_naming:
          - pattern: '^net-prod-(?P<app>[a-z0-9]+)-'
            team_id: "{app}-p"
          - pattern: '^net-staging-(?P<app>[a-z0-9]+)-'
            team_id: "{app}-t"
    """

    pattern: str = Field(description="Regex with at least one named group")
    team_id: str = Field(description="Template for the team id, e.g. '{app}-p'")

    @model_validator(mode="after")
    def _check(self) -> ObjectNamingRule:
        try:
            compiled = re.compile(self.pattern)
        except re.error as exc:
            raise ValueError(f"object_naming: invalid regex {self.pattern!r}: {exc}") from exc

        groups = set(compiled.groupindex)
        missing = [key for key in re.findall(r"\{(\w+)\}", self.team_id) if key not in groups]
        if missing:
            raise ValueError(
                f"object_naming: team_id references {missing}, which the pattern does not "
                f"capture (it captures {sorted(groups)})"
            )
        if not self.team_id.strip():
            raise ValueError("object_naming: team_id must not be empty")
        return self


class OwnershipConfig(ConfigModel):
    """How rules are attributed to teams.

    Two classes of resolver, and the distinction matters:

    * **inventory** compares the rule's resolved networks against each team's
      assets.  Only this one can tell inbound from outbound, which is the whole
      point of the report.
    * **tag / regex / device_group / zone** attribute a rule to a team without
      knowing which side of the connection the team is on.  Those land in the
      team's "related" section.

    ``cascade`` controls only the second class: with ``stop_after_first_match``
    the resolvers in ``order`` are tried in sequence and the first hit wins,
    which keeps a broad device-group rule from drowning out a precise tag.
    """

    order: list[OwnershipMethod] = Field(
        default_factory=lambda: list(DEFAULT_OWNERSHIP_ORDER)
    )
    stop_after_first_match: bool = True

    # -- tag resolver
    #
    # A PAN-OS tag is a *classification* before it is anything else: it says
    # what an object is, and dynamic address groups are built on exactly that.
    # `GlobalProtect-Clients` or `Outdated-Object` name a kind of object, not
    # an owner. Ownership-by-tag is a convention an estate adds on top, and the
    # tool can only read it once the estate has said what it looks like -- which
    # is what these two settings are for. An estate that tags nothing for
    # ownership sets both to [] and loses nothing.
    tag_prefixes: list[str] = Field(
        default_factory=lambda: ["owner:", "team:"],
        description="A tag 'owner:payments' assigns the rule to team id 'payments'",
    )
    tag_suffixes: list[str] = Field(
        default_factory=list,
        description="The same the other way round, for estates that write the team first: "
        "with '-owner', a tag 'payments-owner' assigns the rule to team id 'payments'. "
        "Empty by default, because a suffix is the rarer convention and a wrong one "
        "silently claims rules for the wrong team.",
    )
    tag_case_sensitive: bool = False

    # An ownership tag on an *object* says more than the same tag on a rule: the
    # object's addresses are the team's assets, so tagging carries the same
    # information the inventory does, and directionally (source vs destination),
    # which a rule tag cannot. With this on, an address object or group carrying
    # an ownership tag contributes its addresses to that team as if the
    # inventory had listed them -- extending a hand-written inventory, or
    # replacing it. Only tags matching tag_prefixes/tag_suffixes count; every
    # other tag is a classification and is ignored.
    derive_from_object_tags: bool = False

    # -- regex resolver
    name_patterns: list[str] = Field(
        default_factory=list,
        description="Regexes with a named group 'team' applied to rule names, "
        r"e.g. '^(?P<team>[A-Z]{3})-' ",
    )
    description_patterns: list[str] = Field(default_factory=list)

    # -- inventory resolver
    match_mode: Literal["overlap", "contained"] = Field(
        default="overlap",
        description="'overlap': any intersection with an asset counts (recommended). "
        "'contained': the rule's network must be fully inside the asset.",
    )
    covering_supernet_bits: int = Field(
        default=1,
        ge=1,
        le=32,
        description="How much larger than one of your networks a rule's network may be and "
        "still count as your own rule rather than as one that merely covers you. "
        "1, the default, means any strictly larger network counts as covering: a rule "
        "naming 10.0.0.0/8 is not your rule just because your /24 sits inside it. Raise it "
        "for an inventory that lists individual hosts, where a rule naming the /24 those "
        "hosts live in is still recognisably about them -- 9 would cover that case.",
    )
    include_any_rules: bool = Field(
        default=True,
        description="Whether a rule with source/destination 'any' is shown to every team. "
        "These rules affect everyone, so hiding them understates exposure.",
    )
    max_any_rules_per_team: int = Field(
        default=50, description="Cap on 'any' rules per team so the report stays readable"
    )

    object_naming: list[ObjectNamingRule] = Field(
        default_factory=list,
        description="Object names that state which team they belong to, used to check the "
        "inventory rather than to attribute rules. Empty by default: a convention only "
        "exists where an estate has one, and guessing at object names would invent "
        "findings.",
    )

    derive_teams: list[DerivedTeamRule] = Field(
        default_factory=list,
        description="Rules that create teams from naming conventions. Merged with the "
        "inventory; an explicit entry always wins over a derived one.",
    )

    unassigned_team_id: str = "_unassigned"
    unassigned_team_name: str = "Unassigned rules"

    @field_validator("name_patterns", "description_patterns")
    @classmethod
    def _compilable(cls, patterns: list[str]) -> list[str]:
        for p in patterns:
            try:
                compiled = re.compile(p)
            except re.error as exc:
                raise ValueError(f"invalid regex {p!r}: {exc}") from exc
            if "team" not in compiled.groupindex:
                raise ValueError(f"regex {p!r} must contain a named group '(?P<team>...)'")
        return patterns


# ---------------------------------------------------------------------------
# Free-text metadata extraction
# ---------------------------------------------------------------------------


class TicketPattern(ConfigModel):
    """One ticket system to recognise in rule descriptions and tags.

    ``url_template`` is formatted with the regex's named groups, so
    ``https://jira.example.com/browse/{id}`` turns match group ``id`` into a
    clickable link in the HTML and PDF reports.
    """

    name: str
    regex: str
    url_template: str | None = None
    fields: list[TicketField] = Field(default_factory=lambda: list(DEFAULT_TICKET_FIELDS))

    @model_validator(mode="after")
    def _check(self) -> TicketPattern:
        try:
            compiled = re.compile(self.regex)
        except re.error as exc:
            raise ValueError(f"ticket pattern {self.name!r}: invalid regex: {exc}") from exc
        if "id" not in compiled.groupindex:
            raise ValueError(f"ticket pattern {self.name!r}: regex needs a named group '(?P<id>...)'")
        if self.url_template:
            missing = [
                key
                for key in re.findall(r"\{(\w+)\}", self.url_template)
                if key not in compiled.groupindex
            ]
            if missing:
                raise ValueError(
                    f"ticket pattern {self.name!r}: url_template references "
                    f"{missing} which the regex does not capture"
                )
        return self


def _default_role_keywords() -> dict[str, list[str]]:
    """Words that, found shortly before a date, say what the date means."""
    return {
        "expires": ["until", "expires", "expiry", "valid until", "temp until", "remove after"],
        "created": ["created", "added", "requested", "opened"],
        "changed": ["changed", "modified", "edited", "updated", "amended"],
        "reviewed": ["reviewed", "checked", "confirmed", "recertified"],
    }


class DatePattern(ConfigModel):
    """A date format to recognise, and what the surrounding words mean.

    Role keywords normally come from ``metadata.role_keywords`` and apply to
    every date format. Set them here only to override that for one format --
    an estate that writes ISO dates in English and dotted dates in German would
    be the case for it.

    Leaving this unset is the common and correct choice: the words around a
    date do not change because the date is written differently, and an earlier
    version that required them per pattern meant an organisation using both
    ``31.12.2026`` and ``2026-12-31`` had to maintain its keyword list twice --
    which silently half-worked, recognising only the format whose list had been
    filled in.
    """

    name: str
    regex: str
    date_format: str = Field(
        default="%d.%m.%Y", description="strptime format applied to the whole match"
    )
    role_keywords: dict[str, list[str]] | None = Field(
        default=None,
        description="Overrides metadata.role_keywords for this format only. "
        "Normally left unset.",
    )
    keyword_window: int = Field(
        default=40, description="Characters before the date searched for a role keyword"
    )

    @field_validator("regex")
    @classmethod
    def _compilable(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"invalid date regex {v!r}: {exc}") from exc
        return v

    def keywords(self, shared: dict[str, list[str]]) -> dict[str, list[str]]:
        """The effective keyword map: this pattern's override, or the shared one."""
        return self.role_keywords if self.role_keywords is not None else shared


def _default_ticket_patterns() -> list[TicketPattern]:
    """Deliberately generic starting points -- users override these entirely.

    The captured id includes the prefix (``CHG0041234``, not ``0041234``): the
    report is read by people who then paste that string into a ticket system,
    and a stripped prefix makes it useless for that.
    """
    return [
        TicketPattern(
            name="jira",
            regex=r"\b(?P<id>[A-Z][A-Z0-9]{1,9}-\d{1,6})\b",
            url_template=None,
        ),
        TicketPattern(
            name="numeric-ticket",
            regex=r"\b(?P<id>(?:TICKET|CHG|RFC|REQ|INC)[ #:-]?\d{3,9})\b",
            url_template=None,
        ),
    ]


def _default_date_patterns() -> list[DatePattern]:
    return [
        DatePattern(name="dot-dmy", regex=r"\b\d{1,2}\.\d{1,2}\.\d{4}\b", date_format="%d.%m.%Y"),
        DatePattern(name="iso", regex=r"\b\d{4}-\d{2}-\d{2}\b", date_format="%Y-%m-%d"),
        DatePattern(name="slash-dmy", regex=r"\b\d{1,2}/\d{1,2}/\d{4}\b", date_format="%d/%m/%Y"),
    ]


class MetadataConfig(ConfigModel):
    ticket_patterns: list[TicketPattern] = Field(default_factory=_default_ticket_patterns)
    date_patterns: list[DatePattern] = Field(default_factory=_default_date_patterns)
    role_keywords: dict[str, list[str]] = Field(
        default_factory=_default_role_keywords,
        description="Words that identify what a date means, shared by every date format. "
        "Add your own language here once, rather than per pattern.",
    )
    requester_patterns: list[str] = Field(
        default_factory=lambda: [r"(?:requested by|owner|contact)[:\s]+(?P<requester>[\w.\- ]{3,40})"],
        description="Regexes with a named group 'requester'",
    )
    change_patterns: list[str] = Field(
        default_factory=list,
        description="Regexes recording who last touched a rule and when. Needs a named "
        "group 'date'; an optional group 'requester' names the person. A match makes the "
        "date a change date rather than one of unstated purpose, which is what lets a "
        "future-dated edit be reported as the typo it is.\n\n"
        "Nothing is recognised by default, because these conventions are positional -- "
        "'CHG0041234 (a.beck: 2024-05-30)' carries no keyword saying what the date is -- and "
        "a guess that misreads an expiry as a change date would be worse than silence.",
    )

    @field_validator("requester_patterns")
    @classmethod
    def _compilable(cls, patterns: list[str]) -> list[str]:
        for p in patterns:
            compiled = re.compile(p)
            if "requester" not in compiled.groupindex:
                raise ValueError(f"requester pattern {p!r} needs a named group '(?P<requester>...)'")
        return patterns

    @field_validator("change_patterns")
    @classmethod
    def _has_date_group(cls, patterns: list[str]) -> list[str]:
        for p in patterns:
            try:
                compiled = re.compile(p)
            except re.error as exc:
                raise ValueError(f"invalid change_patterns regex {p!r}: {exc}") from exc
            if "date" not in compiled.groupindex:
                raise ValueError(f"change pattern {p!r} needs a named group '(?P<date>...)'")
        return patterns


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


class FlaggedObjectPattern(ConfigModel):
    """Flag rules that reference an object whose name matches a pattern.

    Estates mark objects for their own purposes -- ``OUTDATED_`` for something
    scheduled for deletion, ``TEMP_`` for something that was never meant to
    last. Those markers are meaningful to the people who wrote them and
    invisible to a generic check, so the pattern is configuration.

    A rule still pointing at an object marked for deletion is exactly the kind
    of thing a review should surface: somebody decided it should go, and it is
    still carrying traffic.
    """

    pattern: str
    title: str = "References a flagged object"
    severity: Literal["info", "low", "medium", "high"] = "low"
    detail: str = "The rule references an object whose name matches a flagged pattern."
    recommendation: str = ""

    @field_validator("pattern")
    @classmethod
    def _compilable(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid flag_object_patterns regex {value!r}: {exc}") from exc
        return value


class AnalysisConfig(ConfigModel):
    """Which cleanup checks run, and the thresholds that make them actionable."""

    enabled_checks: list[str] = Field(
        default_factory=lambda: [
            "ANY_ANY",
            "ANY_DESTINATION",
            "ANY_SOURCE",
            "ANY_SERVICE",
            "BROAD_NETWORK",
            "DISABLED_RULE",
            "EXPIRED_RULE",
            "EXPIRING_SOON",
            "IMPOSSIBLE_DATE",
            "NO_DESCRIPTION",
            "NO_TICKET",
            "NO_LOGGING",
            "UNUSED_RULE",
            "STALE_RULE",
            "UNRESOLVED_OBJECT",
            "EMPTY_GROUP",
        ]
    )
    broad_network_prefix_v4: int = Field(
        default=16, description="An IPv4 network shorter than /this counts as overly broad"
    )
    broad_network_prefix_v6: int = 48
    expiring_soon_days: int = 60
    stale_rule_days: int = Field(
        default=180, description="No hit for this many days marks a rule stale (needs hit counts)"
    )
    require_ticket: bool = Field(
        default=True, description="Flag rules whose description holds no recognisable ticket"
    )
    flag_object_patterns: list[FlaggedObjectPattern] = Field(
        default_factory=list,
        description="Object name patterns that make a referencing rule a finding, "
        "e.g. '^OUTDATED_'. Drives the FLAGGED_OBJECT check.",
    )

    internet_zones: list[str] = Field(
        default_factory=lambda: ["outside", "untrust", "internet", "wan"],
        description="Zones that lead off the estate. A rule whose destination zones are all "
        "in this list is not flagged for having 'any' as its destination -- the internet is "
        "its destination, and there is no tighter way to write it. Set to [] to flag those "
        "rules anyway, or replace it with the names your estate uses.",
    )

    ignore_tags: list[str] = Field(
        default_factory=list, description="Rules with any of these tags are exempt from findings"
    )
    ignore_rule_patterns: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Hit counts (opt-in, network access)
# ---------------------------------------------------------------------------


class ConnectionConfig(ConfigModel):
    """How to reach a firewall or Panorama over the XML API.

    Shared by every network-facing feature -- hit-count collection and live
    configuration fetch -- so the device list, credentials and TLS policy are
    stated once.  Secrets are never read from this file: an API key comes from
    an environment variable or a key file, and a password the same way, so the
    configuration stays shareable.

    Authentication is either an API key or a username plus password.  With a
    username and password the tool obtains an API key from each device itself
    (a read-only ``keygen`` call), which is the path for a read-only account
    that was never issued a key.
    """

    devices: list[str] = Field(
        default_factory=list, description="Hostnames or IPs of firewalls / Panorama"
    )
    api_key_env: str = Field(
        default="PAN_API_KEY",
        description="Environment variable holding the API key. Keys are never read from this file.",
    )
    api_key_file: Path | None = Field(
        default=None, description="Alternative to the env var: a file containing only the key"
    )
    username: str | None = Field(
        default=None,
        description="Username for password authentication. Used only when no API key is "
        "configured; the tool then obtains a key from each device via keygen.",
    )
    password_env: str = Field(
        default="PAN_PASSWORD",
        description="Environment variable holding the password. Never read from this file.",
    )
    password_file: Path | None = Field(
        default=None, description="Alternative to the env var: a file containing only the password"
    )
    verify_tls: bool = True
    ca_bundle: Path | None = None
    timeout_seconds: int = 30


class HitCountConfig(ConnectionConfig):
    """Live rule-hit-count enrichment.

    Hit counters are runtime state and are never contained in a configuration
    backup, so obtaining them requires talking to the device.  This is one of
    only two parts of the tool that touch the network, it is disabled by
    default, and it issues read-only operational commands exclusively.
    """

    enabled: bool = False
    rulebases: list[str] = Field(default_factory=lambda: ["security"])
    cache_dir: Path | None = Field(
        default=None,
        description="Where collected counters are cached as sidecar JSON. Lets a later offline "
        "run reuse them without touching the network again.",
    )
    cache_max_age_hours: int = 24


# ---------------------------------------------------------------------------
# Reporting presentation
# ---------------------------------------------------------------------------


class ReportConfig(ConfigModel):
    title: str = "Firewall Rule Review"
    organisation: str = ""
    logo_path: Path | None = None
    language: Literal["en", "de"] = "en"
    intro_text: str = ""
    contact_text: str = Field(
        default="", description="Shown in the 'how to request a change' section of every report"
    )
    change_request_url: str | None = None
    include_disabled_rules: bool = True
    include_nat_rules: bool = True
    include_rule_uuid: bool = False
    max_addresses_shown: int = Field(
        default=25, description="Truncate long resolved address lists in the rendered output"
    )
    show_unassigned_section: bool = True
    sort_rules_by: Literal["order", "name", "severity"] = "order"


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------


class Config(ConfigModel):
    input: InputConfig = Field(default_factory=InputConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    teams_file: Path | None = Field(
        default=None, description="YAML file with the team/asset inventory"
    )
    ownership: OwnershipConfig = Field(default_factory=OwnershipConfig)
    metadata: MetadataConfig = Field(default_factory=MetadataConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    hitcounts: HitCountConfig = Field(default_factory=HitCountConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)

    model_config = {"extra": "forbid"}

    @field_validator("teams_file", mode="before")
    @classmethod
    def _expand(cls, v: Any) -> Any:
        return Path(os.path.expandvars(str(v))).expanduser() if v else v


def load_config(path: Path | None) -> Config:
    """Load and validate a configuration file, or return defaults if ``path`` is None."""
    if path is None:
        return Config()
    if not path.is_file():
        raise ConfigError(f"configuration file not found: {path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: top level must be a mapping, got {type(raw).__name__}")

    try:
        config = Config.model_validate(raw)
    except Exception as exc:
        raise ConfigError(f"{path}: {_format_validation_error(exc)}") from exc

    # Relative paths in the config are resolved against the config file itself,
    # so a config directory can be moved or mounted elsewhere without edits.
    base = path.parent.resolve()

    def _relative_to_config(value: Path | None) -> Path | None:
        if value is None:
            return None
        expanded = Path(os.path.expandvars(str(value))).expanduser()
        return expanded if expanded.is_absolute() else base / expanded

    if config.teams_file and not config.teams_file.is_absolute():
        config.teams_file = base / config.teams_file
    if config.input.backup_dir and not config.input.backup_dir.is_absolute():
        config.input.backup_dir = base / config.input.backup_dir
    if not config.output.directory.is_absolute():
        config.output.directory = base / config.output.directory

    # Credential, TLS and asset files sit beside the config as naturally as the
    # backup directory does, so they follow the same rule.
    config.hitcounts.api_key_file = _relative_to_config(config.hitcounts.api_key_file)
    config.hitcounts.password_file = _relative_to_config(config.hitcounts.password_file)
    config.hitcounts.ca_bundle = _relative_to_config(config.hitcounts.ca_bundle)
    config.hitcounts.cache_dir = _relative_to_config(config.hitcounts.cache_dir)
    config.report.logo_path = _relative_to_config(config.report.logo_path)
    return config


def _format_validation_error(exc: Exception) -> str:
    """Turn a pydantic ValidationError into something an operator can act on."""
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return str(exc)
    lines = []
    for err in errors():
        loc = ".".join(str(p) for p in err.get("loc", ()))
        lines.append(f"  {loc or '<root>'}: {err.get('msg', '')}")
    return "configuration is invalid:\n" + "\n".join(lines)
