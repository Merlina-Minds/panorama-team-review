"""Where every file of a run lands -- decided once, before anything is rendered.

The reports have to link to each other. A team's page offers the same report as
PDF and Excel; the overview opens any team; both point back at the index. None
of the renderers can work that out on its own: the filenames come from
configurable templates, ``--sample`` means most teams have no page at all, and a
format nobody asked for has no file to link to. Worse, a renderer runs in a
worker process with no idea what the run as a whole is writing.

So the naming lives here, the run calls :func:`plan` once, and the resulting
``OutputLinks`` travels with the bundle. A template writes a link only where the
map says a file exists, which is what keeps a report from offering a PDF that
was never rendered.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from ..config import Config
from ..model import FORMAT_READING_ORDER, OutputLinks, TeamReport

# JSON is written gzip-compressed; every other format's extension is its name.
EXTENSIONS = {"json": "json.gz"}

# The order the writers are driven in: the heavy formats first, so they start on
# the first free worker instead of tailing the run.
RENDER_ORDER = ("xlsx", "pdf", "html", "json")

# The order a reader is offered them in, shared with ``OutputLinks`` so the map
# and the pages built from it cannot disagree about what exists.
FORMAT_ORDER = FORMAT_READING_ORDER

FORMAT_LABELS = {"html": "HTML", "pdf": "PDF", "xlsx": "Excel", "json": "JSON"}

INDEX_NAME = "index.html"


def plan(config: Config, generated_at: datetime, per_team: Sequence[TeamReport]) -> OutputLinks:
    """Name every file this run will write, relative to the run directory.

    ``per_team`` is the reports that will actually be rendered -- the sampled
    subset when ``--sample`` was given, so that nothing links to a page the run
    decided not to write.
    """
    stamp = generated_at.strftime("%Y-%m-%d")
    formats = [fmt for fmt in FORMAT_ORDER if fmt in set(config.output.formats)]
    links = OutputLinks(index=INDEX_NAME)

    if config.output.combined:
        stem = config.output.combined_filename_template.format(date=stamp)
        links.combined = {fmt: f"{stem}.{extension(fmt)}" for fmt in formats}

    if config.output.per_team:
        for report in per_team:
            stem = config.output.filename_template.format(
                date=stamp,
                team_id=safe(report.team.id),
                team_name=safe(report.team.name),
            )
            links.teams[report.team.id] = {fmt: f"{stem}.{extension(fmt)}" for fmt in formats}

    return links


def in_render_order(files: dict[str, str]) -> list[tuple[str, str]]:
    """One document's files, heaviest first, as (format, filename)."""
    return [(fmt, files[fmt]) for fmt in RENDER_ORDER if fmt in files]


def extension(fmt: str) -> str:
    return EXTENSIONS.get(fmt, fmt)


def safe(value: str) -> str:
    """Make a string safe for a filename on every supported platform."""
    cleaned = "".join(char if char.isalnum() or char in "-_." else "-" for char in value)
    return cleaned.strip("-") or "team"
