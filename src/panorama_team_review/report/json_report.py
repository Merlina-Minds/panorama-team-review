"""JSON output.

This is the complete, lossless record of a run.  Two consequences worth
knowing:

* It is the input to ``pan-review diff``, which is how a team sees what changed
  between two review cycles rather than re-reading the whole report.
* It is stable enough to feed a CMDB or a ticket system, so the review can be
  automated further downstream.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..model import ReportBundle, TeamReport


def write_bundle(bundle: ReportBundle, path: Path, indent: int = 2) -> Path:
    """Write the full bundle, every team included."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = bundle.model_dump(mode="json", exclude_none=False)
    path.write_text(json.dumps(payload, indent=indent, ensure_ascii=False), encoding="utf-8")
    return path


def write_team(bundle: ReportBundle, report: TeamReport, path: Path, indent: int = 2) -> Path:
    """Write one team's slice, with enough run context to stand on its own."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "meta": bundle.meta.model_dump(mode="json"),
        "generated_at": bundle.generated_at.isoformat(),
        "hitcount_available": bundle.hitcount_available,
        "team": report.model_dump(mode="json"),
    }
    path.write_text(json.dumps(payload, indent=indent, ensure_ascii=False), encoding="utf-8")
    return path
