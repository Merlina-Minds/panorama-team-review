"""panorama-team-review: owner-centric firewall rule reviews from offline backups.

The tool reads exported Palo Alto Panorama or PAN-OS configurations from disk
and produces, per system owner, a report answering two questions: what can my
systems reach, and who can reach my systems.

By design it performs no network access.  The single exception is the hit-count
enrichment module, which is disabled by default and must be enabled explicitly.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
