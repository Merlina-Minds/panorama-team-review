"""Command line interface.

Two ways in, and both matter:

* ``pan-review run`` with no arguments -- the cron case.  Picks the newest
  backup out of the configured directory, writes into a dated output directory,
  says nothing on success unless asked.
* ``pan-review run --backup FILE`` -- the manual case, after pulling an export
  by hand.

Exit codes are meaningful because cron reads them: 0 success, 1 unexpected
failure, 2 configuration problem, 3 no usable backup.  A monitoring system can
therefore distinguish "the tool is broken" from "the firewall stopped writing
backups", which are very different alerts.
"""

from __future__ import annotations

import math
import shutil
import sys
from collections import Counter
from datetime import date, datetime
from pathlib import Path
from typing import cast

import click

from . import __version__
from .analyze.findings import available_checks
from .config import Config, ConnectionConfig, load_config
from .errors import (
    BackupNotFoundError,
    BackupStaleError,
    ConfigError,
    PanReviewError,
)
from .model import OutputFormat, ReportBundle, Snapshot, TeamReport
from .parse import panos
from .parse.loader import find_backups, load
from .report import batch, html, pdf
from .report import build as report_build
from .resolve.inventory import load_inventory

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_NO_BACKUP = 3


class Context:
    def __init__(self, config: Config, config_path: Path | None, quiet: bool, verbose: bool):
        self.config = config
        self.config_path = config_path
        self.quiet = quiet
        self.verbose = verbose
        # A terminal gets live progress during the slow network steps; cron (no
        # TTY) stays quiet and just gets the summary lines, as before.
        self.interactive = sys.stderr.isatty() and not quiet

    def say(self, message: str) -> None:
        if not self.quiet:
            click.echo(message)

    def detail(self, message: str) -> None:
        if self.verbose and not self.quiet:
            click.echo(f"  {message}", err=False)

    def warn(self, message: str) -> None:
        click.echo(f"warning: {message}", err=True)

    def step(self, message: str) -> None:
        """Transient progress shown only in a terminal, so cron output is unchanged."""
        if self.interactive:
            click.echo(message, err=True)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--config", "-c", "config_path", type=click.Path(path_type=Path),
    help="Configuration file. Without it, built-in defaults are used.",
)
@click.option("--quiet", "-q", is_flag=True, help="Only report errors. Intended for cron.")
@click.option("--verbose", "-v", is_flag=True, help="Explain each step.")
@click.version_option(__version__, prog_name="pan-review")
@click.pass_context
def main(ctx: click.Context, config_path: Path | None, quiet: bool, verbose: bool) -> None:
    """Generate owner-centric firewall rule reviews from offline PAN-OS backups.

    The tool never contacts a firewall unless hit-count collection or live
    configuration fetch is explicitly enabled in the configuration.
    """
    try:
        config = load_config(config_path)
    except ConfigError as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(EXIT_CONFIG)
    ctx.obj = Context(config, config_path, quiet, verbose)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


@main.command()
@click.option(
    "--backup", "-b", type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Analyse this backup instead of the newest one in the configured directory.",
)
@click.option(
    "--output", "-o", type=click.Path(file_okay=False, path_type=Path),
    help="Override the output directory.",
)
@click.option(
    "--format", "-f", "formats", multiple=True,
    type=click.Choice(["html", "xlsx", "pdf", "json"]),
    help="Override the output formats. Repeatable.",
)
@click.option("--team", "teams_filter", multiple=True, help="Only report on these team ids.")
@click.option(
    "--sample", type=click.IntRange(min=1), metavar="N",
    help="Write only N per-team reports, picked as a spread across team size and naming "
    "families rather than the first N. For trying a configuration out without producing "
    "hundreds of files. The analysis still runs over the whole estate, so the reports "
    "written are identical to those of a full run.",
)
@click.option(
    "--no-network", is_flag=True,
    help="Force fully offline operation even if hit-count collection is enabled.",
)
@click.option(
    "--as-of", type=click.DateTime(formats=["%Y-%m-%d"]),
    help="Evaluate expiry and staleness against this date instead of today.",
)
@click.pass_obj
def run(
    ctx: Context,
    backup: Path | None,
    output: Path | None,
    formats: tuple[str, ...],
    teams_filter: tuple[str, ...],
    sample: int | None,
    no_network: bool,
    as_of: datetime | None,
) -> None:
    """Produce the review reports. This is the command cron should call."""
    config = ctx.config
    if output:
        config.output.directory = output
    if formats:
        # click's Choice already constrains these to the valid format names.
        config.output.formats = cast(list[OutputFormat], list(formats))

    # A live fetch only makes sense when analysing the configured directory; an
    # explicit --backup is the manual case and is left untouched.
    if backup is None and config.input.fetch.enabled:
        _fetch_backups(ctx, no_network)

    try:
        backups = find_backups(config.input, backup)
    except (BackupNotFoundError, BackupStaleError) as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(EXIT_NO_BACKUP)

    try:
        teams = load_inventory(config.teams_file)
    except ConfigError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(EXIT_CONFIG)

    if teams_filter:
        wanted = set(teams_filter)
        unknown = wanted - {team.id for team in teams}
        if unknown:
            click.echo(f"error: unknown team ids: {', '.join(sorted(unknown))}", err=True)
            sys.exit(EXIT_CONFIG)
        teams = [team for team in teams if team.id in wanted]

    if not teams and not config.ownership.derive_teams:
        ctx.warn(
            "no teams configured -- every rule will end up in the 'unassigned' section. "
            "Point teams_file at an inventory, or configure ownership.derive_teams, "
            "to get per-owner reports."
        )
    elif not teams:
        ctx.detail(
            f"no explicit inventory; teams come from {len(config.ownership.derive_teams)} "
            "derive_teams rule(s)"
        )

    written: list[Path] = []
    try:
        for path in backups:
            ctx.say(f"Reading {path.name}")
            snapshot = _load_snapshot(ctx, path)
            ctx.detail(
                f"{len(snapshot.rules)} security rules, {len(snapshot.addresses)} address "
                f"objects, {len(snapshot.device_groups)} device groups"
            )

            notes = _enrich(ctx, snapshot, no_network)
            bundle = report_build.build_report(
                snapshot, teams, config, today=as_of.date() if as_of else date.today()
            )
            bundle.notes.extend(notes)

            written.extend(_write_outputs(ctx, bundle, sample))
    except PanReviewError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    _prune_old_runs(ctx)

    if written:
        ctx.say(f"Wrote {len(written)} file(s) to {written[0].parent}")
        for path in written if ctx.verbose else []:
            ctx.detail(str(path))
    else:
        ctx.warn("nothing was written -- check output.formats in the configuration")


def _load_snapshot(ctx: Context, path: Path) -> Snapshot:
    documents = load(path)
    ctx.detail(f"{len(documents)} configuration document(s) in {path.name}")
    snapshots = [panos.parse(document, tool_version=__version__) for document in documents]
    return panos.merge(snapshots)


def _fetch_backups(ctx: Context, no_network: bool) -> None:
    """Pull a fresh configuration from the devices before analysing it.

    Best-effort: a failure here is a warning, not the end of the run. The tool
    falls back to whatever is already in the directory, and ``max_age_days``
    still guards against that being stale.
    """
    config = ctx.config
    if no_network:
        ctx.detail("--no-network given: skipping live configuration fetch")
        return
    if config.input.backup_dir is None:
        ctx.warn(
            "input.fetch.enabled is set but input.backup_dir is not -- "
            "nowhere to save a fetched configuration; using existing backups"
        )
        return

    from . import fetch

    try:
        written, notes = fetch.fetch_backups(
            config.input.fetch, config.hitcounts, config.input.backup_dir, progress=ctx.step
        )
    except PanReviewError as exc:
        ctx.warn(f"configuration fetch failed, using existing backups: {exc}")
        return

    for note in notes:
        ctx.detail(note)
    if written:
        ctx.say(f"Fetched {len(written)} configuration(s) into {config.input.backup_dir}")


def _enrich(ctx: Context, snapshot: Snapshot, no_network: bool) -> list[str]:
    config = ctx.config.hitcounts
    if not config.enabled:
        return []
    if no_network:
        ctx.detail("--no-network given: using cached hit counts only")

    from .enrich import hitcount

    notes = hitcount.enrich_snapshot(snapshot, config, offline_only=no_network, progress=ctx.step)
    for note in notes:
        ctx.detail(note)
    return notes


def _write_outputs(ctx: Context, bundle: ReportBundle, sample: int | None = None) -> list[Path]:
    config = ctx.config
    directory = config.output.directory
    if config.output.timestamped_subdir:
        directory = directory / bundle.generated_at.strftime(config.output.timestamped_subdir_format)
    directory.mkdir(parents=True, exist_ok=True)

    stamp = bundle.generated_at.strftime("%Y-%m-%d")
    formats = set(config.output.formats)

    # Sampling happens here rather than by cutting the inventory down before
    # the run, and the difference matters: ownership is resolved against every
    # team at once -- who owns the far side of a connection, how many 'any'
    # rules a team has already been shown -- so a five-team inventory produces
    # five reports that differ from the ones a full run would write. These are
    # the real thing, just fewer of them.
    per_team = bundle.teams
    if sample is not None and config.output.per_team:
        per_team = _sample_teams(bundle.teams, sample)
        ctx.say(
            f"Sampling {len(per_team)} of {len(bundle.teams)} team reports: "
            + ", ".join(report.team.id for report in per_team)
        )

    # Every output file is one job: (team index or COMBINED, format, path). They
    # are handed to the batch writer, which renders them across worker processes
    # when the volume justifies it. Heavy formats and the combined document come
    # first so they start on the first free workers instead of tailing the run,
    # and the file extension matches the format name.
    active = [fmt for fmt in ("xlsx", "pdf", "html", "json") if fmt in formats]
    position = {id(report): index for index, report in enumerate(bundle.teams)}
    jobs: list[batch.Job] = []

    # An index.html links the HTML reports together, so opening the run's
    # directory lands on a table of contents rather than a file listing.
    want_index = "html" in formats
    index_entries: list[tuple[TeamReport, str]] = []
    overview_href: str | None = None

    if config.output.combined:
        stem = config.output.combined_filename_template.format(date=stamp)
        for fmt in active:
            jobs.append((batch.COMBINED, fmt, directory / f"{stem}.{fmt}"))
        if want_index:
            overview_href = f"{stem}.html"

    if config.output.per_team:
        for report in per_team:
            stem = config.output.filename_template.format(
                date=stamp, team_id=_safe(report.team.id), team_name=_safe(report.team.name)
            )
            for fmt in active:
                jobs.append((position[id(report)], fmt, directory / f"{stem}.{fmt}"))
            if want_index:
                index_entries.append((report, f"{stem}.html"))

    if not jobs:
        return []

    workers = batch.resolve_worker_count(config.output.render_workers, len(jobs))
    ctx.step(
        f"Rendering {len(jobs)} file(s) across {workers} workers"
        if workers > 1
        else f"Rendering {len(jobs)} file(s)"
    )

    def report_progress(done: int, count: int) -> None:
        if done == count or done % 25 == 0:
            ctx.step(f"  rendered {done}/{count} file(s)")

    written = batch.write_all(bundle, jobs, config, progress=report_progress)

    if want_index and (index_entries or overview_href):
        written.append(
            html.write_index(bundle, config, directory / "index.html", index_entries, overview_href)
        )

    return written


def _sample_teams(reports: list[TeamReport], count: int) -> list[TeamReport]:
    """Pick ``count`` team reports that represent the run rather than start it.

    Taking the first N is the obvious implementation and a useless one. The
    list is ordered by rule count, so the sample comes out as N variations on
    the largest team -- and on an estate whose ids share a prefix, such as the
    ``nonstandard-*`` teams a naming convention failed to match, all N can come
    from that one family and none from the teams the report is actually for.

    What a trial run needs is one report from each size band and from different
    families, so that the shapes a renderer has to survive -- hundreds of
    rules, a handful, findings, none -- all turn up. Teams with no rules at all
    are left out: their report is a single sentence, and it is not what
    somebody checking a configuration wants to look at.

    Deterministic, so two runs over the same estate sample the same teams and
    their reports can be compared.
    """
    # Size means the team's *own* rules, not every rule in its report. The
    # estate-wide rules that merely cover a team land on all of them in
    # roughly equal numbers, so ranking by the total sorts teams by an almost
    # constant and picks a sample of near-identical reports -- on the estate
    # this was written against, banding by the total missed every one of the
    # teams with hundreds of rules to review.
    def workload(report: TeamReport) -> tuple[int, int, str]:
        return (-report.own_rule_count, -report.rule_count, report.team.id)

    candidates = (
        [report for report in reports if report.own_rule_count]
        or [report for report in reports if report.rule_count]
        or list(reports)
    )
    if count >= len(candidates):
        return sorted(candidates, key=workload)

    ordered = sorted(candidates, key=workload)
    # No family may take more than a third of the sample, so one prefix cannot
    # crowd out the rest -- unless there is nothing else, which the fill-up
    # pass below handles.
    per_family = max(1, math.ceil(count / 3))

    picked: list[TeamReport] = []
    chosen: set[str] = set()
    families: Counter[str] = Counter()

    def take(report: TeamReport) -> None:
        picked.append(report)
        chosen.add(report.team.id)
        families[_family(report.team.id)] += 1

    # The biggest team is in every sample. It is the one that exercises the
    # renderer hardest, and a run that looks fine without it proves least.
    take(ordered[0])

    rest = ordered[1:]
    for index in range(count - 1):
        low = index * len(rest) // (count - 1)
        high = max(low + 1, (index + 1) * len(rest) // (count - 1))
        band = rest[low:high]
        # Start at the middle of the band: its edges are the neighbours of the
        # adjacent bands, and picking those makes the sample cluster.
        middle = len(band) // 2
        for report in [*band[middle:], *band[:middle]]:
            if report.team.id in chosen or families[_family(report.team.id)] >= per_family:
                continue
            take(report)
            break

    # Bands come up empty when a family has already reached its cap, so the
    # sample can be short. Fill it by raising the cap a step at a time rather
    # than dropping it: an estate with only two families cannot honour a cap
    # of a third each, but it can still split six reports three and three
    # instead of handing every spare slot back to the larger family. Each pass
    # takes at most one more per family, which is what produces that.
    cap = per_family
    while len(picked) < count and cap <= count:
        for report in ordered:
            if len(picked) >= count:
                break
            if report.team.id in chosen or families[_family(report.team.id)] >= cap:
                continue
            take(report)
        cap += 1

    picked.sort(key=workload)
    return picked


def _family(team_id: str) -> str:
    """The naming family of a team id: everything before the first separator.

    Ids generated from a convention share their leading segment --
    ``segment-1``, ``nonstandard-foo``, ``dmz-rnd-bitbucket`` -- which makes
    this a good enough proxy for "more of the same" without the tool needing
    to know any particular estate's convention.
    """
    return team_id.split("-", 1)[0].lower()


def _prune_old_runs(ctx: Context) -> None:
    """Keep the N newest dated run directories, if configured."""
    keep = ctx.config.output.keep_runs
    if keep is None or not ctx.config.output.timestamped_subdir:
        return
    base = ctx.config.output.directory
    if not base.is_dir():
        return

    fmt = ctx.config.output.timestamped_subdir_format
    runs = sorted(
        (
            (parsed, path)
            for path in base.iterdir()
            if path.is_dir() and (parsed := _run_dir_time(path.name, fmt)) is not None
        ),
        key=lambda item: item[0],
        reverse=True,
    )
    for _, stale in runs[keep:]:
        ctx.detail(f"removing old run directory {stale}")
        shutil.rmtree(stale, ignore_errors=True)


def _run_dir_time(name: str, fmt: str) -> datetime | None:
    """The run time encoded in a directory name, or ``None`` if it is not one."""
    try:
        return datetime.strptime(name, fmt)
    except ValueError:
        return None


def _safe(value: str) -> str:
    """Make a string safe for a filename on every supported platform."""
    cleaned = "".join(char if char.isalnum() or char in "-_." else "-" for char in value)
    return cleaned.strip("-") or "team"


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


@main.command()
@click.option(
    "--backup", "-b", type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Backup to inspect. Defaults to the newest in the configured directory.",
)
@click.pass_obj
def inspect(ctx: Context, backup: Path | None) -> None:
    """Summarise a backup without producing reports.

    Useful as a first step against a new estate: it shows what the tool sees,
    which is the fastest way to find out whether the inventory needs work.
    """
    try:
        paths = find_backups(ctx.config.input, backup)
    except (BackupNotFoundError, BackupStaleError) as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(EXIT_NO_BACKUP)

    for path in paths:
        snapshot = _load_snapshot(ctx, path)
        click.echo(f"\n{path}")
        click.echo(f"  type            {snapshot.meta.source_type}")
        click.echo(f"  PAN-OS version  {snapshot.meta.pan_os_version or 'unknown'}")
        click.echo(f"  hostname        {snapshot.meta.hostname or 'unknown'}")
        click.echo(
            f"  backup time     "
            f"{snapshot.meta.file_mtime.strftime('%Y-%m-%d %H:%M') if snapshot.meta.file_mtime else 'unknown'}"
        )
        click.echo(f"  security rules  {len(snapshot.rules)}")
        click.echo(f"  NAT rules       {len(snapshot.nat_rules)}")
        click.echo(f"  address objects {len(snapshot.addresses)}")
        click.echo(f"  address groups  {len(snapshot.address_groups)}")
        click.echo(f"  service objects {len(snapshot.services)}")
        click.echo(f"  device groups   {len(snapshot.device_groups)}")
        click.echo(f"  zones           {len(snapshot.zones)}")

        if snapshot.device_groups:
            click.echo("\n  Device groups:")
            for name, group in sorted(snapshot.device_groups.items()):
                parent = f" (child of {group.parent})" if group.parent else ""
                count = sum(1 for r in snapshot.rules if r.location.device_group == name)
                click.echo(f"    {name}{parent}: {count} rules, {len(group.devices)} devices")

        if snapshot.parse_warnings:
            click.echo(f"\n  {len(snapshot.parse_warnings)} parse warning(s):")
            for warning in snapshot.parse_warnings[:10]:
                click.echo(f"    - {warning}")


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


@main.command()
@click.pass_obj
def validate(ctx: Context) -> None:
    """Check the configuration and inventory without touching a backup."""
    problems: list[str] = []
    config = ctx.config

    click.echo(f"Configuration: {ctx.config_path or '<defaults>'}")

    if config.teams_file:
        try:
            teams = load_inventory(config.teams_file)
            total_assets = sum(len(team.assets) for team in teams)
            click.echo(f"Inventory:     {len(teams)} teams, {total_assets} networks")
            for team in teams:
                if not any([team.assets, team.tags, team.device_groups, team.zones,
                            team.name_patterns]):
                    problems.append(
                        f"team {team.id!r} has no assets, tags, device groups, zones or name "
                        "patterns -- no rule can ever be attributed to it"
                    )
        except ConfigError as exc:
            problems.append(str(exc))
    elif config.ownership.derive_teams:
        click.echo("Inventory:     not configured (teams come from derive_teams)")
    else:
        click.echo("Inventory:     not configured (all rules will be unassigned)")

    if config.ownership.derive_teams:
        click.echo(f"Derived teams: {len(config.ownership.derive_teams)} rule(s):")
        for derive_rule in config.ownership.derive_teams:
            click.echo(f"               {derive_rule.id} <- {derive_rule.source}")

    if config.input.backup_dir:
        if config.input.backup_dir.is_dir():
            try:
                found = find_backups(config.input)
                click.echo(f"Backups:       {config.input.backup_dir} -> {found[0].name}")
            except (BackupNotFoundError, BackupStaleError) as exc:
                problems.append(str(exc))
        else:
            problems.append(f"input.backup_dir does not exist: {config.input.backup_dir}")
    else:
        click.echo("Backups:       no directory configured (--backup required)")

    from .analyze.findings import unknown_checks

    if missing := unknown_checks(config.analysis):
        problems.append(f"unknown checks in analysis.enabled_checks: {', '.join(missing)}")

    if "pdf" in config.output.formats and not pdf.available():
        problems.append(
            "output.formats includes 'pdf' but weasyprint is not usable in this environment "
            "(install panorama-team-review[pdf] and the pango/cairo system libraries)"
        )

    if config.hitcounts.enabled:
        click.echo(
            f"Hit counts:    enabled for {len(config.hitcounts.devices)} device(s) "
            f"-- this contacts the network"
        )
        if not config.hitcounts.devices:
            problems.append("hitcounts.enabled is true but hitcounts.devices is empty")
    else:
        click.echo("Hit counts:    disabled (fully offline)")

    if config.input.fetch.enabled:
        click.echo(
            f"Config fetch:  enabled for {len(config.hitcounts.devices)} device(s) "
            "-- this contacts the network"
        )
        if not config.hitcounts.devices:
            problems.append(
                "input.fetch.enabled is true but hitcounts.devices is empty "
                "(configuration fetch reuses the hitcounts connection)"
            )
        if config.input.backup_dir is None:
            problems.append(
                "input.fetch.enabled is true but input.backup_dir is not set "
                "(nowhere to save the fetched configuration)"
            )
    else:
        click.echo("Config fetch:  disabled (backups read from disk)")

    if config.hitcounts.enabled or config.input.fetch.enabled:
        _check_connection(config.hitcounts, problems)

    click.echo(f"Output:        {config.output.directory}, formats: {', '.join(config.output.formats)}")

    if problems:
        click.echo(f"\n{len(problems)} problem(s):", err=True)
        for problem in problems:
            click.echo(f"  - {problem}", err=True)
        sys.exit(EXIT_CONFIG)
    click.echo("\nConfiguration is valid.")


def _check_connection(conn: ConnectionConfig, problems: list[str]) -> None:
    """Report the credential method and flag any configured file that is missing.

    Environment variables are deliberately not checked: the recommended pattern
    supplies the secret only at run time, so an unset variable during an
    interactive validate is not an error. A file named in the config that does
    not exist always is.
    """
    if conn.api_key_file is not None:
        method = f"API key from file {conn.api_key_file}"
    elif conn.username:
        source = conn.password_file or f"${conn.password_env}"
        method = f"username {conn.username!r} with password from {source}"
    else:
        method = f"API key from ${conn.api_key_env} (must be set at run time)"
    click.echo(f"Credentials:   {method}")

    for label, path_value, allow_empty in (
        ("hitcounts.api_key_file", conn.api_key_file, False),
        ("hitcounts.password_file", conn.password_file, False),
        ("hitcounts.ca_bundle", conn.ca_bundle, True),
    ):
        if path_value is None:
            continue
        if not path_value.is_file():
            problems.append(f"{label} does not exist: {path_value}")
        elif not allow_empty and path_value.stat().st_size == 0:
            problems.append(f"{label} is empty: {path_value}")


# ---------------------------------------------------------------------------
# init, checks, collect-hitcounts
# ---------------------------------------------------------------------------


@main.command()
@click.argument("directory", type=click.Path(file_okay=False, path_type=Path), default=".")
@click.option("--force", is_flag=True, help="Overwrite existing files.")
def init(directory: Path, force: bool) -> None:
    """Write a commented example configuration and inventory to DIRECTORY."""
    directory.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).parent.parent.parent / "config"

    written = []
    for name, target_name in (
        ("config.example.yaml", "config.yaml"),
        ("inventory.example.yaml", "inventory.yaml"),
    ):
        example = source / name
        if not example.is_file():
            example = Path(__file__).parent / "examples" / name
        if not example.is_file():
            click.echo(f"error: bundled example {name} not found", err=True)
            sys.exit(EXIT_ERROR)

        target = directory / target_name
        if target.exists() and not force:
            click.echo(f"skipping {target} (exists; use --force to overwrite)")
            continue
        target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
        written.append(target)

    for path in written:
        click.echo(f"wrote {path}")
    if written:
        click.echo("\nNext: edit inventory.yaml with your networks, then run")
        click.echo(f"  pan-review -c {directory / 'config.yaml'} validate")


@main.command("checks")
def list_checks() -> None:
    """List the available analysis checks and their codes."""
    from .analyze import findings as findings_module

    click.echo("Available checks (use these codes in analysis.enabled_checks):\n")
    for code in available_checks():
        doc = (findings_module._REGISTRY[code].__doc__ or "").strip().split("\n")[0]
        click.echo(f"  {code:<20} {doc}")


@main.command("collect-hitcounts")
@click.pass_obj
def collect_hitcounts(ctx: Context) -> None:
    """Collect rule hit counters from the configured devices into the cache.

    Separated from ``run`` so the network-facing part can be scheduled
    independently -- typically once a night, while reports stay offline.
    """
    config = ctx.config.hitcounts
    if not config.enabled:
        click.echo(
            "error: hit-count collection is disabled. Set hitcounts.enabled: true and list "
            "the devices in the configuration.",
            err=True,
        )
        sys.exit(EXIT_CONFIG)
    if config.cache_dir is None:
        click.echo(
            "error: hitcounts.cache_dir must be set for this command, otherwise the collected "
            "counters have nowhere to go.",
            err=True,
        )
        sys.exit(EXIT_CONFIG)

    from .enrich import hitcount

    try:
        counters = hitcount.collect(config, progress=ctx.step)
        hitcount._write_cache(config, counters)
    except PanReviewError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    click.echo(f"collected {len(counters)} rule counters into {config.cache_dir}")


@main.command("fetch-backup")
@click.pass_obj
def fetch_backup(ctx: Context) -> None:
    """Fetch the running configuration from the configured devices into the backup directory.

    Separated from ``run`` so the network-facing part can be scheduled
    independently -- pull a fresh configuration nightly, and keep ``run`` fully
    offline. The connection is the same as hit-count collection and is taken
    from the ``hitcounts`` section.
    """
    config = ctx.config
    if not config.input.fetch.enabled:
        click.echo(
            "error: configuration fetch is disabled. Set input.fetch.enabled: true and list "
            "the devices under hitcounts.devices (fetch reuses the hitcounts connection).",
            err=True,
        )
        sys.exit(EXIT_CONFIG)
    if config.input.backup_dir is None:
        click.echo(
            "error: input.backup_dir must be set for this command -- it is where the fetched "
            "configuration is written.",
            err=True,
        )
        sys.exit(EXIT_CONFIG)

    from . import fetch

    try:
        written, notes = fetch.fetch_backups(
            config.input.fetch, config.hitcounts, config.input.backup_dir, progress=ctx.step
        )
    except PanReviewError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    for note in notes:
        ctx.detail(note)
    click.echo(f"fetched {len(written)} configuration(s) into {config.input.backup_dir}")


@main.command("fetch-cert")
@click.argument("devices", nargs=-1)
@click.option(
    "-o", "--output", type=click.Path(dir_okay=False, path_type=Path),
    help="Write the certificate bundle here. Defaults to panorama-ca.pem.",
)
@click.pass_obj
def fetch_cert(ctx: Context, devices: tuple[str, ...], output: Path | None) -> None:
    """Fetch the TLS certificate(s) from the device(s) into a CA bundle.

    For a device with a self-signed or internal-CA certificate, this is the
    secure alternative to turning verification off: point `hitcounts.ca_bundle`
    at the written file and the connection is verified against a pinned
    certificate.

    Trust on first use -- the certificate is fetched without verification, so
    check the printed SHA-256 fingerprint against the device before trusting it.
    DEVICES defaults to the hosts in `hitcounts.devices`.
    """
    targets = list(devices) or ctx.config.hitcounts.devices
    if not targets:
        click.echo(
            "error: no devices given and hitcounts.devices is empty -- pass one or more "
            "hostnames, or list them in the configuration.",
            err=True,
        )
        sys.exit(EXIT_CONFIG)

    from . import panos_api

    out_path = output or Path("panorama-ca.pem")
    pems: list[str] = []
    for target in targets:
        host, _, port = target.partition(":")
        try:
            pem, fingerprint = panos_api.fetch_certificate(
                host, int(port) if port else 443, ctx.config.hitcounts.timeout_seconds
            )
        except PanReviewError as exc:
            click.echo(f"error: {exc}", err=True)
            sys.exit(EXIT_ERROR)
        pems.append(pem if pem.endswith("\n") else pem + "\n")
        click.echo(f"{host}: SHA-256 {fingerprint}")

    out_path.write_text("".join(pems), encoding="utf-8")
    click.echo(f"\nWrote {len(pems)} certificate(s) to {out_path}")
    click.echo("Verify the fingerprint(s) above against the device, then set in the config:")
    click.echo(f"  hitcounts:\n    ca_bundle: {out_path}")


@main.command("suggest-inventory")
@click.option(
    "--backup", "-b", type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Backup to derive from. Defaults to the newest in the configured directory.",
)
@click.option(
    "--group-by", type=click.Choice(["device-group", "zone", "tag", "usage"]),
    default="device-group", show_default=True,
    help="Which grouping in the configuration to turn into team candidates.",
)
@click.option(
    "--output", "-o", type=click.Path(dir_okay=False, path_type=Path),
    help="Write the draft here instead of to stdout.",
)
@click.option(
    "--max-networks", default=40, show_default=True,
    help="Cap on networks per candidate before they are rolled up.",
)
@click.option(
    "--min-prefix", default=16, show_default=True,
    help="Never aggregate IPv4 networks wider than this prefix.",
)
@click.option(
    "--compare", is_flag=True,
    help="Show how well each grouping strategy fits this estate, and write nothing.",
)
@click.pass_obj
def suggest_inventory(
    ctx: Context,
    backup: Path | None,
    group_by: str,
    output: Path | None,
    max_networks: int,
    min_prefix: int,
    compare: bool,
) -> None:
    """Derive a draft inventory from a configuration.

    Writing an inventory from scratch is where adoption usually stalls, and
    most of it is derivable: a configuration already groups its addresses by
    device group, zone or tag, and those groupings were made by people who knew
    what belonged together.

    What it cannot know is what the groups are called in your organisation and
    who to send the report to. Those come out as TODO markers rather than
    guesses.

    The result is a draft to read and cut down, not a finished inventory.
    """
    from .analyze.suggest import render_yaml
    from .analyze.suggest import suggest_inventory as build_draft

    try:
        paths = find_backups(ctx.config.input, backup)
    except (BackupNotFoundError, BackupStaleError) as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(EXIT_NO_BACKUP)

    try:
        snapshot = _load_snapshot(ctx, paths[0])
        from .resolve.objects import resolve_snapshot

        resolve_snapshot(snapshot)

        if compare:
            from .analyze.suggest import compare_strategies

            rows = compare_strategies(
                snapshot, max_networks_per_team=max_networks, min_prefix_v4=min_prefix
            )
            _print_strategy_comparison(rows, snapshot)
            return

        draft = build_draft(
            snapshot,
            group_by=group_by,  # type: ignore[arg-type]
            max_networks_per_team=max_networks,
            min_prefix_v4=min_prefix,
        )
    except PanReviewError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    rendered = render_yaml(draft, source=paths[0].name)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
        ctx.say(f"wrote {output}")
        ctx.say(
            f"  {draft.stats['candidate_teams']} candidate teams, "
            f"{draft.stats['networks_suggested']} networks"
        )
        if draft.uncovered_networks:
            ctx.say(
                f"  {len(draft.uncovered_networks)} network(s) used by rules are not "
                "covered by any candidate -- listed at the end of the file"
            )
        ctx.say("\nThis is a draft. Review it, then point teams_file at it.")
    else:
        click.echo(rendered)


def _print_strategy_comparison(rows: list[dict], snapshot: Snapshot) -> None:
    """Show the fit of each grouping strategy, with a reading of the numbers."""
    click.echo(f"\n{len(snapshot.rules)} rules, {len(snapshot.addresses)} address objects\n")
    click.echo(f"  {'strategy':<14} {'candidates':>11} {'networks':>9} {'coverage':>9}")
    click.echo(f"  {'-' * 14} {'-' * 11:>11} {'-' * 9:>9} {'-' * 9:>9}")
    for row in rows:
        click.echo(
            f"  {row['strategy']:<14} {row['candidates']:>11} "
            f"{row['networks']:>9} {row['coverage_percent']:>8}%"
        )

    click.echo(
        "\n  coverage   = share of the networks rules actually use that the draft claims\n"
        "  candidates = how many teams the grouping produces\n"
    )
    click.echo("How to read this:")
    click.echo(
        "  * High coverage with a plausible candidate count is the one to start from.\n"
        "  * Very few candidates means most networks were used across several groups,\n"
        "    so the grouping could not separate them -- common with shared infrastructure.\n"
        "  * Very many candidates means the grouping is not about ownership. Tags used\n"
        "    for automation rather than ownership look like this.\n"
        "  * Low coverage everywhere means the inventory has to come from a CMDB or\n"
        "    from people; the configuration does not carry the information."
    )


@main.command("diff")
@click.argument("old", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("new", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.option(
    "--fail-on-change", is_flag=True,
    help="Exit non-zero when anything changed. For use in a pipeline.",
)
def diff_reports(old: Path, new: Path, as_json: bool, fail_on_change: bool) -> None:
    """Compare two JSON reports and show what changed between them.

    The second review cycle onwards, this is the question owners actually
    have -- not what the policy looks like, but what moved since last time.
    """
    from .report import diff as diff_module

    try:
        result = diff_module.diff_bundles(
            diff_module.load_bundle(old), diff_module.load_bundle(new)
        )
    except PanReviewError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    if as_json:
        import json as json_module

        click.echo(json_module.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        click.echo(diff_module.format_text(result))

    if fail_on_change and not result.is_empty:
        sys.exit(EXIT_ERROR)


@main.command("scrub")
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("destination", type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--salt",
    help="Salt for the pseudonym mapping. Omit for a random one, which makes "
         "the mapping irreversible but also non-reproducible across runs.",
)
@click.option("--force", is_flag=True, help="Overwrite the destination if it exists.")
def scrub(source: Path, destination: Path, salt: str | None, force: bool) -> None:
    """Pseudonymise a configuration so a problem can be reproduced safely.

    Replaces addresses, object names, hostnames, serials and all free text
    while preserving the structure that makes a reproducer useful.

    This is PSEUDONYMISATION, not anonymisation: structure is preserved, and
    with the salt the mapping is reversible. Share the result only with people
    you would already trust with a network diagram, and never publish it.
    """
    if destination.exists() and not force:
        click.echo(f"error: {destination} exists (use --force to overwrite)", err=True)
        sys.exit(EXIT_ERROR)

    from .privacy.scrub import Scrubber, scrub_string

    scrubber = Scrubber(salt=salt) if salt else Scrubber.with_random_salt()

    try:
        content = source.read_text(encoding="utf-8", errors="replace")
        destination.write_text(scrub_string(content, scrubber), encoding="utf-8")
    except Exception as exc:  # noqa: BLE001 - reported to the operator
        click.echo(f"error: could not scrub {source}: {exc}", err=True)
        sys.exit(EXIT_ERROR)

    click.echo(f"wrote {destination}")
    click.echo(
        "\nThis file is pseudonymised, not anonymised: the structure is intact and the\n"
        "mapping is reversible by anyone holding the salt. Do not publish it.\n"
        "For public test data use tests/fixtures/generator.py instead."
    )


if __name__ == "__main__":
    main()
