"""JSON output.

This is the complete, lossless record of a run.  Two consequences worth
knowing:

* It is the input to ``pan-review diff``, which is how a team sees what changed
  between two review cycles rather than re-reading the whole report.
* It is stable enough to feed a CMDB or a ticket system, so the review can be
  automated further downstream.

Written gzip-compressed (``.json.gz``): the full record repeats every rule once
per team that sees it, so on a large estate the plain text runs to hundreds of
megabytes and compresses roughly tenfold. ``diff`` and any other reader decode
it transparently.

A team's rules are split the same way the HTML and Excel reports split them:
``inbound``/``outbound``/``internal``/``related`` hold the team's own rules,
and a ``covered`` object holds the ones that merely cover them, under the same
four keys. See ``_split_coverage``.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from ..model import ReportBundle, TeamReport

DIRECTIONS = ("inbound", "outbound", "internal", "related")


def write_bundle(bundle: ReportBundle, path: Path, indent: int = 2) -> Path:
    """Write the full bundle, every team included, gzip-compressed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = bundle.model_dump(mode="json", exclude_none=False)
    payload["teams"] = [_split_coverage(team) for team in payload.get("teams", [])]
    _write_gzip(path, json.dumps(payload, indent=indent, ensure_ascii=False))
    return path


def write_team(bundle: ReportBundle, report: TeamReport, path: Path, indent: int = 2) -> Path:
    """Write one team's slice, gzip-compressed, with enough run context to stand alone."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "meta": bundle.meta.model_dump(mode="json"),
        "generated_at": bundle.generated_at.isoformat(),
        "hitcount_available": bundle.hitcount_available,
        "team": _split_coverage(report.model_dump(mode="json")),
    }
    _write_gzip(path, json.dumps(payload, indent=indent, ensure_ascii=False))
    return path


def _split_coverage(team: dict) -> dict:
    """Move the rules that merely cover a team out of its direction lists.

    The model keeps both kinds in one list per direction and tells them apart
    by each view's ``coverage`` field; the HTML and Excel reports separate them
    before showing them, because the two ask different things of the reader.
    Own rules are the ones a team is being asked to decide on. Covering rules
    are estate-wide and not theirs to change -- an "Also covers you" table
    deliberately has no decision column.

    A reader that iterates ``inbound`` should get that distinction too, rather
    than have to know to filter on ``coverage`` and silently treat central
    rules as the team's own if it does not. So the direction lists here hold
    the own rules, and ``covered`` holds the rest under the same four keys --
    by direction, not as one block, since "who may reach me" and "what may my
    systems reach" stay different questions when the rule was written
    centrally. Nothing is dropped: every view still carries its ``coverage``
    and ``coverage_reason``.
    """
    own: dict[str, list] = {}
    covered: dict[str, list] = {}
    for direction in DIRECTIONS:
        views = team[direction]
        own[direction] = [v for v in views if v["coverage"] != "covered"]
        # By evaluation order, as TeamReport.covered() returns them: a covering
        # rule is read as a block of "what am I already allowed to do?", and the
        # answer depends on which rule the firewall reaches first.
        covered[direction] = sorted(
            (v for v in views if v["coverage"] == "covered"),
            key=lambda v: v["evaluation_rank"],
        )

    out: dict = {}
    for key, value in team.items():
        out[key] = own.get(key, value)
        if key == DIRECTIONS[-1]:  # keep "covered" next to the lists it was split from
            out["covered"] = covered
    return out


def _write_gzip(path: Path, text: str) -> None:
    """Write text as gzip, with the archive's own timestamp zeroed so identical
    content produces identical bytes -- a committed report does not churn."""
    path.write_bytes(gzip.compress(text.encode("utf-8"), mtime=0))

