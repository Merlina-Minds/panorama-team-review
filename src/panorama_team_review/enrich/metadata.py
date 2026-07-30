"""Recover structured metadata from free-text rule fields.

Operational reality: the description field of a firewall rule is where the
change history actually lives.  A typical one reads

    CHG0041234 open 443 for payment gw, requested by A. Beck, valid until 31.12.2026

That single line holds a ticket reference, a requester and an expiry date, none
of which PAN-OS models as structured data.  Recovering them turns a description
column nobody reads into clickable ticket links, expiry warnings and a usable
audit trail.

Every pattern is configuration, not code: ticket ID formats and date
conventions differ per organisation, and hard-coding either would make the tool
useless outside the estate it was written for.
"""

from __future__ import annotations

import re
from datetime import datetime
from functools import lru_cache

from ..config import DatePattern, MetadataConfig, TicketPattern
from ..model import DateRef, DateRole, RuleMetadata, TicketField, TicketRef


class MetadataExtractor:
    """Applies the configured patterns to rule descriptions, tags and names."""

    def __init__(self, config: MetadataConfig) -> None:
        self.config = config
        self._tickets = [(p, re.compile(p.regex)) for p in config.ticket_patterns]
        self._dates = [(p, re.compile(p.regex)) for p in config.date_patterns]
        self._requesters = [re.compile(p, re.IGNORECASE) for p in config.requester_patterns]
        self._changes = [re.compile(p) for p in config.change_patterns]

    def extract(self, description: str, tags: list[str], rule_name: str = "") -> RuleMetadata:
        tickets = self._extract_tickets(description, tags, rule_name)
        dates = self._extract_dates(description)
        self._apply_change_notes(description, dates)
        # The name beside a change date is whoever *edited* the rule, which is
        # not who asked for it. Reporting 'CHG0041299 a.beck 2027-07-18' as
        # "requested by a.beck" states something the description never said --
        # the administrator who made the change is rarely the person who wanted
        # it. That name belongs to the change date, and is shown there.
        requester = self._extract_requester(description)
        return RuleMetadata(tickets=tickets, dates=dates, requester=requester)

    # -- change notes -------------------------------------------------------

    def _apply_change_notes(self, description: str, dates: list[DateRef]) -> None:
        """Give a role to dates whose meaning comes from position, not wording.

        ``CHG0041234 (a.beck: 2024-05-30)`` says who touched the rule and when,
        without a single word the keyword matcher can see. Read as a bare date
        it becomes "purpose not stated", throwing away both halves: who, and
        the fact that it is an edit rather than an expiry -- and with that, the
        ability to notice a date in the future and report it as the typo it is.

        Only dates the keyword pass could not explain are considered. Wording
        beats position, always: ``valid until 2026-12-31`` is an expiry, and a
        positional pattern loose enough to catch a bare username is also loose
        enough to read ``until`` as one. Running second is what keeps that
        from happening.
        """
        if not self._changes or not description:
            return

        unknown = [entry for entry in dates if entry.role == "unknown"]
        if not unknown:
            return

        # Line by line, because a change note is one line by construction. Run
        # against the whole text, a pattern ending in `\s+(?P<date>...)` happily
        # pairs a name at the end of one line with the date at the start of the
        # next, and reports an edit by somebody who made a different one.
        for line in description.splitlines():
            for compiled in self._changes:
                for match in compiled.finditer(line):
                    raw = (match.groupdict().get("date") or "").strip()
                    who = (match.groupdict().get("requester") or "").strip(" ,;.:-()")
                    for entry in unknown:
                        if entry.role == "unknown" and entry.raw == raw:
                            entry.role = "changed"
                            entry.by = who or None

    # -- tickets ------------------------------------------------------------

    def _extract_tickets(
        self, description: str, tags: list[str], rule_name: str
    ) -> list[TicketRef]:
        found: list[TicketRef] = []
        seen: set[tuple[str, str]] = set()

        sources: list[tuple[TicketField, str]] = [
            ("description", description),
            ("rule-name", rule_name),
        ]
        sources.extend(("tag", tag) for tag in tags)

        for pattern, compiled in self._tickets:
            for field_name, text in sources:
                if field_name not in pattern.fields or not text:
                    continue
                for match in compiled.finditer(text):
                    ticket_id = match.group("id")
                    key = (pattern.name, ticket_id)
                    if key in seen:
                        continue
                    seen.add(key)
                    found.append(
                        TicketRef(
                            system=pattern.name,
                            id=ticket_id,
                            url=_build_url(pattern, match),
                            source_field=field_name,
                        )
                    )
        return found

    # -- dates --------------------------------------------------------------

    def _extract_dates(self, description: str) -> list[DateRef]:
        if not description:
            return []

        found: list[DateRef] = []
        seen: set[tuple[str, str]] = set()

        for pattern, compiled in self._dates:
            for match in compiled.finditer(description):
                raw = match.group(0)
                parsed = _parse_date(raw, pattern.date_format)
                if parsed is None:
                    continue
                role = _infer_role(
                    description, match.start(), pattern, self.config.role_keywords
                )
                key = (role, parsed.isoformat())
                if key in seen:
                    continue
                seen.add(key)
                found.append(DateRef(role=role, value=parsed, raw=raw))
        return found

    # -- requester ----------------------------------------------------------

    def _extract_requester(self, description: str) -> str | None:
        for pattern in self._requesters:
            match = pattern.search(description)
            if match:
                value = (match.groupdict().get("requester") or "").strip(" ,;.-")
                if value:
                    return value
        return None


def _build_url(pattern: TicketPattern, match: re.Match[str]) -> str | None:
    if not pattern.url_template:
        return None
    values = {key: value or "" for key, value in match.groupdict().items()}
    try:
        return pattern.url_template.format(**values)
    except (KeyError, IndexError):
        # Validated at config load time; a failure here means an optional group
        # did not participate in this particular match.
        return None


@lru_cache(maxsize=4096)
def _parse_date(raw: str, fmt: str):
    """Parse a date, tolerating single-digit day/month against a padded format."""
    try:
        return datetime.strptime(raw, fmt).date()
    except ValueError:
        pass

    # '1.3.2026' against '%d.%m.%Y' fails on some platforms; normalise and retry.
    if "." in raw or "/" in raw:
        separator = "." if "." in raw else "/"
        parts = raw.split(separator)
        if len(parts) == 3:
            padded = separator.join(
                part.zfill(2) if index < 2 else part for index, part in enumerate(parts)
            )
            try:
                return datetime.strptime(padded, fmt).date()
            except ValueError:
                return None
    return None


def _infer_role(
    description: str,
    position: int,
    pattern: DatePattern,
    shared_keywords: dict[str, list[str]],
) -> DateRole:
    """Decide what a date means from the words immediately before it.

    Looking only backwards is deliberate: descriptions are written as
    'valid until 31.12.2026', not '31.12.2026 is the expiry'.  The window is
    configurable because how much text precedes the date varies by convention.

    Keywords come from the shared ``metadata.role_keywords`` unless this
    pattern overrides them, so an estate that writes both ``31.12.2026`` and
    ``2026-12-31`` maintains one keyword list rather than one per format.
    """
    window_start = max(0, position - pattern.keyword_window)
    context = description[window_start:position].lower()

    # Never read across a line break. A description is a change log with one
    # entry per line, so the words on the line above belong to a different
    # entry -- and taking them makes this date mean what that one meant:
    #
    #     CHG0041201 gueltig bis 31.12.2026
    #     CHG0041202 a.beck 01.01.2025
    #
    # Without the clamp the second date inherits "gueltig bis" from the first
    # and is reported as an expiry, which then drives EXPIRED_RULE against a
    # rule that never had an expiry at all.
    break_at = max(context.rfind("\n"), context.rfind("\r"))
    if break_at != -1:
        context = context[break_at + 1:]

    best_role: DateRole = "unknown"
    best_position = -1

    for role, keywords in pattern.keywords(shared_keywords).items():
        for keyword in keywords:
            found = context.rfind(keyword.lower())
            if found > best_position:
                best_position = found
                best_role = role  # type: ignore[assignment]

    return best_role


def annotate_rules(rules, extractor: MetadataExtractor) -> None:
    """Attach extracted metadata to every rule in place."""
    for rule in rules:
        rule.metadata = extractor.extract(rule.description, rule.tags, rule.name)
