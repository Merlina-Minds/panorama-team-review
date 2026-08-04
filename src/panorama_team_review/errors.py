"""Exception types.

All of these carry messages meant for an operator reading cron output, not a
stack trace.  The CLI catches ``PanReviewError`` and prints it without a
traceback; anything else is a genuine bug and keeps its traceback.
"""

from __future__ import annotations


class PanReviewError(Exception):
    """Base class for all expected, operator-facing failures."""


class ConfigError(PanReviewError):
    """The configuration or inventory file is missing or invalid."""


class BackupNotFoundError(PanReviewError):
    """No backup matched the configured directory and patterns."""


class BackupStaleError(PanReviewError):
    """The newest backup is older than ``input.max_age_days``."""


class ParseError(PanReviewError):
    """The backup could not be parsed as a PAN-OS or Panorama configuration."""


class EnrichmentError(PanReviewError):
    """Optional enrichment (hit counts) failed. Never fatal to the report."""


class FetchError(PanReviewError):
    """Optional live configuration fetch failed."""


class RenderError(PanReviewError):
    """A renderer could not produce its output, e.g. a missing optional dependency."""
