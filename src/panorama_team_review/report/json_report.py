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
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from ..model import ReportBundle, TeamReport


def write_bundle(bundle: ReportBundle, path: Path, indent: int = 2) -> Path:
    """Write the full bundle, every team included, gzip-compressed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = bundle.model_dump(mode="json", exclude_none=False)
    _write_gzip(path, json.dumps(payload, indent=indent, ensure_ascii=False))
    return path


def write_team(bundle: ReportBundle, report: TeamReport, path: Path, indent: int = 2) -> Path:
    """Write one team's slice, gzip-compressed, with enough run context to stand alone."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "meta": bundle.meta.model_dump(mode="json"),
        "generated_at": bundle.generated_at.isoformat(),
        "hitcount_available": bundle.hitcount_available,
        "team": report.model_dump(mode="json"),
    }
    _write_gzip(path, json.dumps(payload, indent=indent, ensure_ascii=False))
    return path


def _write_gzip(path: Path, text: str) -> None:
    """Write text as gzip, with the archive's own timestamp zeroed so identical
    content produces identical bytes -- a committed report does not churn."""
    path.write_bytes(gzip.compress(text.encode("utf-8"), mtime=0))

