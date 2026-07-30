"""PDF output via WeasyPrint.

WeasyPrint is an optional dependency because it needs system libraries
(pango, cairo, gdk-pixbuf) that are not always available on a hardened
management host.  The rest of the tool works without it; asking for PDF output
when it is missing produces a clear message naming the package to install
rather than an ImportError from three frames down.

A separate print template is used rather than the interactive one with a print
stylesheet: the two want genuinely different layouts, and pretending otherwise
produces a bad version of both.
"""

from __future__ import annotations

from pathlib import Path

from ..config import Config
from ..errors import RenderError
from ..model import ReportBundle, TeamReport
from .html import _asset_counts, _environment, _stylesheet


def available() -> bool:
    """Whether PDF rendering can run in this environment."""
    try:
        import weasyprint  # noqa: F401
    except Exception:
        return False
    return True


def _require_weasyprint():
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise RenderError(
            "PDF output requires the optional 'weasyprint' dependency.\n"
            "  Install it with:  pip install 'panorama-team-review[pdf]'\n"
            "  On Debian/Ubuntu it also needs:  apt install libpango-1.0-0 "
            "libpangoft2-1.0-0 libcairo2\n"
            "  Alternatively, drop 'pdf' from output.formats in the configuration."
        ) from exc
    except OSError as exc:
        raise RenderError(
            f"weasyprint is installed but its system libraries are missing: {exc}\n"
            "  On Debian/Ubuntu:  apt install libpango-1.0-0 libpangoft2-1.0-0 libcairo2\n"
            "  On RHEL/Fedora:    dnf install pango cairo"
        ) from exc
    return HTML


def render_team_html(bundle: ReportBundle, report: TeamReport, config: Config) -> str:
    """The print-specific HTML, exposed separately so it can be tested without WeasyPrint."""
    template = _environment().get_template("team_report_print.html.j2")
    return template.render(
        bundle=bundle,
        report=report,
        config=config,
        css=_stylesheet("print.css"),
        asset_counts=_asset_counts(report),
    )


def write_team(bundle: ReportBundle, report: TeamReport, path: Path, config: Config) -> Path:
    html_class = _require_weasyprint()
    path.parent.mkdir(parents=True, exist_ok=True)
    document = html_class(string=render_team_html(bundle, report, config))
    document.write_pdf(str(path))
    return path


def write_combined(bundle: ReportBundle, path: Path, config: Config) -> Path:
    """The cross-team PDF: one section per team, for the firewall team's records."""
    html_class = _require_weasyprint()
    template = _environment().get_template("combined_report_print.html.j2")
    rendered = template.render(
        bundle=bundle,
        config=config,
        css=_stylesheet("print.css"),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    html_class(string=rendered).write_pdf(str(path))
    return path
