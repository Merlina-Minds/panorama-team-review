"""Render every requested report file, in parallel where it pays.

Rendering -- not analysis -- dominates a large run: on a 270-team estate it is
the great majority of the wall-clock time, and every output file is independent
of every other. So the writers are driven from here as a flat list of jobs, one
per (team, format) pair plus one per combined format, spread across worker
processes.

The analysed bundle is handed to each worker once, through the pool
initializer, rather than travelling with every task: it is tens of megabytes,
and pickling it per file would cost far more than the rendering it saves. A task
therefore carries only a team index into ``bundle.teams`` (or the combined
sentinel), a format name, and an output path -- all cheap to pickle.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence
from pathlib import Path

from ..config import Config
from ..model import ReportBundle
from . import excel, html, json_report, pdf

# A job's team index is either a real position in ``bundle.teams`` or this
# sentinel, meaning "render the cross-team document instead".
COMBINED = -1

# A job is (team index or COMBINED, format, output path).
Job = tuple[int, str, Path]

# Below this many files, spinning up processes and handing each worker its own
# copy of the estate costs more than it saves, so a small run stays in-process.
_MIN_PARALLEL_JOBS = 8

_WORKER_BUNDLE: ReportBundle | None = None
_WORKER_CONFIG: Config | None = None


def _init_worker(bundle: ReportBundle, config: Config) -> None:
    """Store the shared, read-only inputs in the worker so tasks stay tiny."""
    global _WORKER_BUNDLE, _WORKER_CONFIG
    _WORKER_BUNDLE = bundle
    _WORKER_CONFIG = config


def _render_task(index: int, fmt: str, path: str) -> str:
    """Render one file in a worker, using the bundle shared at start-up."""
    assert _WORKER_BUNDLE is not None and _WORKER_CONFIG is not None
    _render_one(_WORKER_BUNDLE, index, fmt, Path(path), _WORKER_CONFIG)
    return path


def _render_one(bundle: ReportBundle, index: int, fmt: str, path: Path, config: Config) -> Path:
    """Render a single job, in whichever process calls it."""
    if index == COMBINED:
        if fmt == "html":
            return html.write_combined(bundle, path, config)
        if fmt == "xlsx":
            return excel.write_combined_workbook(bundle, path, config)
        if fmt == "pdf":
            return pdf.write_combined(bundle, path, config)
        if fmt == "json":
            return json_report.write_bundle(bundle, path)
    else:
        report = bundle.teams[index]
        if fmt == "html":
            return html.write_team(bundle, report, path, config)
        if fmt == "xlsx":
            return excel.write_team_workbook(bundle, report, path, config)
        if fmt == "pdf":
            return pdf.write_team(bundle, report, path, config)
        if fmt == "json":
            return json_report.write_team(bundle, report, path)
    raise ValueError(f"unknown output format {fmt!r}")


def resolve_worker_count(configured: int, jobs: int) -> int:
    """How many processes to render with -- never more than there is work for.

    ``configured`` mirrors ``output.render_workers``: a positive value is taken
    as given, and 0 means auto. Auto is capped rather than one-per-core because
    each worker holds its own copy of the analysed estate; past a point more
    workers buy memory pressure and scheduling overhead, not speed. A handful of
    files stays sequential, since a pool would not repay its start-up there.
    """
    if jobs <= 0:
        return 0
    if configured > 0:
        return max(1, min(configured, jobs))
    if jobs < _MIN_PARALLEL_JOBS:
        return 1
    return max(1, min(os.cpu_count() or 1, 8, jobs))


def write_all(
    bundle: ReportBundle,
    jobs: Sequence[Job],
    config: Config,
    progress: Callable[[int, int], None] | None = None,
) -> list[Path]:
    """Render every job, across worker processes when the volume justifies it.

    Returns the paths written. Raises the first rendering error encountered --
    the same failure mode as calling the writers directly, since a worker's
    error is re-raised here.
    """
    total = len(jobs)
    workers = resolve_worker_count(config.output.render_workers, total)

    written: list[Path] = []
    if workers <= 1:
        for index, fmt, path in jobs:
            written.append(_render_one(bundle, index, fmt, path, config))
            if progress:
                progress(len(written), total)
        return written

    # Imported lazily so the sequential path -- and importing this module at
    # all -- carries no concurrency machinery it may never use.
    from concurrent.futures import ProcessPoolExecutor, as_completed

    with ProcessPoolExecutor(
        max_workers=workers, initializer=_init_worker, initargs=(bundle, config)
    ) as pool:
        futures = [pool.submit(_render_task, index, fmt, str(path)) for index, fmt, path in jobs]
        for future in as_completed(futures):
            written.append(Path(future.result()))
            if progress:
                progress(len(written), total)
    return written
