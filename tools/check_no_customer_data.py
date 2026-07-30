#!/usr/bin/env python3
"""Refuse to commit anything that looks like real customer configuration.

The project's privacy guarantee cannot rest on everyone remembering the rule.
This script is the mechanical enforcement: run as a pre-commit hook and in CI,
it scans staged (or given) files and fails on anything that looks like it came
out of a real estate.

What it looks for:

* IP addresses outside the documentation and private ranges
* Hostnames and email domains other than the example domains reserved by
  RFC 2606
* PAN-OS device serial numbers
* API keys and password hashes
* Files that look like an exported configuration regardless of content

It is deliberately biased towards false positives: a maintainer annoyed by an
unnecessary block loses a minute, while a missed leak is permanent and public.
Use ``# allow-customer-data-check`` on a line to override a genuine false
positive, and say why in the commit message.

Usage:
    python tools/check_no_customer_data.py [FILE ...]
    python tools/check_no_customer_data.py --staged
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# What is allowed
# ---------------------------------------------------------------------------

# Documentation ranges (RFC 5737, RFC 3849), private space (RFC 1918, RFC 4193),
# loopback, link-local, benchmarking (RFC 2544) and the unspecified address.
ALLOWED_NETWORKS = [
    ipaddress.ip_network(cidr)
    for cidr in (
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",   # TEST-NET-1..3
        "2001:db8::/32",                                        # IPv6 doc range
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",        # RFC 1918
        "fc00::/7", "fe80::/10",                                # ULA, link-local
        "127.0.0.0/8", "::1/128",
        "169.254.0.0/16",
        "198.18.0.0/15",                                        # benchmarking
        "0.0.0.0/32", "224.0.0.0/4", "255.255.255.255/32",
    )
]

# RFC 2606 reserved names, plus the placeholders this project uses.
ALLOWED_DOMAIN_SUFFIXES = (
    ".example.com", ".example.org", ".example.net", ".example.edu",
    ".example", ".test", ".invalid", ".localhost", ".localdomain",
    "example.com", "example.org", "example.net", "example",
)

# Public infrastructure this project legitimately links to. Not customer data
# by any reading, and blocking them would mean a README that cannot cite its
# own repository.
#
# The project's own domain is here for the same reason: the maintainer contact
# has to appear in pyproject.toml and SECURITY.md, and a guard that blocks a
# project from naming itself is a guard people start bypassing. Add YOUR
# organisation's domain here if you fork this -- and nothing else. A customer's
# domain never belongs in this list.
ALLOWED_DOMAINS = {
    # This project.
    "merlina-minds.de",
    # Public infrastructure.
    "github.com", "raw.githubusercontent.com", "pypi.org", "python.org",
    "docs.python.org", "semver.org", "keepachangelog.com", "apache.org",
    "www.apache.org", "readthedocs.io", "docs.pytest.org", "astral.sh",
    "paloaltonetworks.com", "docs.paloaltonetworks.com", "pan.dev",
    "weasyprint.org", "pydantic.dev", "spdx.org",
}

# Paths that are not scanned: this file (it lists the patterns by necessity),
# the documents that explain them, and generated or vendored trees.
SKIP_PATHS = {
    "tools/check_no_customer_data.py",
    "docs/PRIVACY.md",
    "LICENSE",
    "uv.lock",
    ".gitignore",
}

SKIP_DIR_PARTS = {
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "node_modules", "build", "dist", "htmlcov",
}

SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".xlsx", ".ico", ".woff", ".woff2"}

OVERRIDE_MARKER = "allow-customer-data-check"

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")

# A PAN-OS serial is 12 digits. Bare 12-digit runs are rare enough in source
# that flagging them is worth the occasional false positive.
#
# Digit-boundary rather than word-boundary, because the single most likely way
# a serial reaches this repository is glued to a hostname: Panorama names the
# members of a backup archive `fw-eu-02_<serial>.xml`, and somebody quotes
# one in a comment to explain what the parser handles. `\b` does not match
# between `2` and `0` there -- an underscore is a word character -- so the
# original pattern let through exactly the case it was written for.
SERIAL_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")

# The one serial prefix this repository is allowed to contain, in exactly the
# spirit of ALLOWED_NETWORKS and ALLOWED_DOMAINS above: a reserved fiction.
# `tests/fixtures/generator.py` numbers its invented devices `001901……` and
# nothing else may. Without it the generated example estate -- whose whole
# point is to be committed and read -- cannot pass its own guard, and the two
# tests that use a fixture serial had to disable the check by hand.
#
# It is a narrow hole and a deliberate one. A real serial could of course begin
# with these digits; so could a real address fall inside 192.0.2.0/24. The
# guarantee this file makes is "nothing traceable to a real estate", and a
# documented placeholder is not traceable to anything.
ALLOWED_SERIAL_PREFIXES = ("001901",)

# The same member-name shape, caught by structure rather than by length, so a
# serial of some other width is not a free pass.
DEVICE_MEMBER_RE = re.compile(r"\b[A-Za-z][\w-]*_\d{9,}\b")

# Public TLDs only.
#
# Internal suffixes (.internal, .local, .corp, .lan) are deliberately NOT in
# this list. They collide with ordinary attribute access -- `report.internal`,
# `self.local` -- and flagging every one of those buries the real findings in
# noise, which is how a guard stops being read. They are also the least
# identifying case: every estate uses the same handful.
HOSTNAME_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|de|eu|io|ch|at|uk|fr|nl|be|us|dev|cloud|systems)\b"
)

EMAIL_RE = re.compile(r"\b[\w.+-]+@([\w-]+\.[\w.-]+)\b")

SECRET_PATTERNS = [
    (re.compile(r"LUFRPT[A-Za-z0-9+/=]{20,}"), "PAN-OS API key"),
    (re.compile(r"\$1\$[A-Za-z0-9./]{8,}"), "PAN-OS password hash"),
    (re.compile(r"\$5\$[A-Za-z0-9./$]{20,}"), "SHA-256 password hash"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
]

# Filenames that are exported configurations no matter what is inside them.
SUSPICIOUS_NAMES = [
    re.compile(r"running-config\.xml$"),
    re.compile(r"candidate-config\.xml$"),
    re.compile(r"^\d{4}-\d{2}-\d{2}.*\.(xml|tgz|tar\.gz)$"),
    re.compile(r".*\.pan-backup\..*"),
]


class Finding:
    def __init__(self, path: Path, line_number: int, kind: str, detail: str, line: str):
        self.path = path
        self.line_number = line_number
        self.kind = kind
        self.detail = detail
        self.line = line.strip()[:120]

    def __str__(self) -> str:
        return (
            f"{self.path}:{self.line_number}: {self.kind}: {self.detail}\n"
            f"    {self.line}"
        )


def is_allowed_ip(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True  # not actually an address, e.g. a version string
    return any(address in network for network in ALLOWED_NETWORKS)


def is_allowed_serial(digits: str) -> bool:
    """Is this one of the invented serials the fixture generator produces?"""
    return digits.startswith(ALLOWED_SERIAL_PREFIXES)


def is_allowed_domain(name: str) -> bool:
    lowered = name.lower().rstrip(".")
    if lowered in ALLOWED_DOMAINS:
        return True
    if any(lowered.endswith(suffix) for suffix in ALLOWED_DOMAIN_SUFFIXES):
        return True
    # A name that starts with 'example.' is a placeholder whatever follows,
    # e.g. example.service-now.com in the ticket-system samples.
    return lowered.startswith("example.")


def scan_file(path: Path) -> list[Finding]:
    relative = _relative(path)
    if str(relative) in SKIP_PATHS or path.suffix.lower() in SKIP_SUFFIXES:
        return []
    if SKIP_DIR_PARTS.intersection(path.parts):
        return []
    if path.name.endswith(".egg-info") or ".egg-info" in str(path):
        return []

    findings: list[Finding] = []

    for pattern in SUSPICIOUS_NAMES:
        if pattern.search(path.name):
            findings.append(
                Finding(relative, 0, "suspicious filename",
                        "looks like an exported device configuration", path.name)
            )

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    for number, line in enumerate(content.splitlines(), start=1):
        if OVERRIDE_MARKER in line:
            continue
        findings.extend(_scan_line(relative, number, line))

    return findings


def _scan_line(path: Path, number: int, line: str) -> list[Finding]:
    findings: list[Finding] = []

    for match in IPV4_RE.finditer(line):
        if not is_allowed_ip(match.group(0)):
            findings.append(
                Finding(path, number, "non-documentation IPv4",
                        f"{match.group(0)} is outside the documentation and private ranges", line)
            )

    for match in IPV6_RE.finditer(line):
        if not is_allowed_ip(match.group(0)):
            findings.append(
                Finding(path, number, "non-documentation IPv6",
                        f"{match.group(0)} is outside the documentation ranges", line)
            )

    for match in HOSTNAME_RE.finditer(line):
        if not is_allowed_domain(match.group(0)):
            findings.append(
                Finding(path, number, "non-example hostname",
                        f"{match.group(0)} is not an RFC 2606 example name", line)
            )

    for match in EMAIL_RE.finditer(line):
        if not is_allowed_domain(match.group(1)):
            findings.append(
                Finding(path, number, "non-example email domain",
                        f"{match.group(1)} is not an RFC 2606 example name", line)
            )

    for match in SERIAL_RE.finditer(line):
        if is_allowed_serial(match.group(0)):
            continue
        findings.append(
            Finding(path, number, "possible device serial",
                    f"{match.group(0)} looks like a PAN-OS serial number", line)
        )

    for match in DEVICE_MEMBER_RE.finditer(line):
        digits = match.group(0).rsplit("_", 1)[-1]
        if is_allowed_serial(digits):
            continue
        findings.append(
            Finding(path, number, "possible device member name",
                    f"{match.group(0)} looks like a hostname with a device serial "
                    "attached, the way Panorama names the members of a backup archive",
                    line)
        )

    for pattern, label in SECRET_PATTERNS:
        if pattern.search(line):
            findings.append(Finding(path, number, "secret", f"looks like a {label}", line))

    return findings


def _relative(path: Path) -> Path:
    try:
        return path.resolve().relative_to(Path.cwd().resolve())
    except ValueError:
        return path


def staged_files() -> list[Path]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        print("error: not a git repository, or git failed", file=sys.stderr)
        sys.exit(2)
    return [Path(name) for name in result.stdout.splitlines() if name and Path(name).is_file()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("files", nargs="*", type=Path)
    parser.add_argument("--staged", action="store_true", help="Scan files staged in git")
    args = parser.parse_args()

    paths = staged_files() if args.staged else [p for p in args.files if p.is_file()]
    if not paths:
        return 0

    findings: list[Finding] = []
    for path in paths:
        findings.extend(scan_file(path))

    if not findings:
        return 0

    print(
        f"\nBLOCKED: {len(findings)} potential customer-data leak(s) found.\n"
        "This repository must contain no configuration traceable to a real estate.\n",
        file=sys.stderr,
    )
    for finding in findings[:60]:
        print(finding, file=sys.stderr)
    if len(findings) > 60:
        print(f"\n... and {len(findings) - 60} more", file=sys.stderr)

    print(
        "\nIf a hit is genuinely a false positive, append "
        f"'# {OVERRIDE_MARKER}' to that line and explain why in the commit message.\n"
        "Test data belongs in tests/fixtures/generator.py, which produces only "
        "documentation-range addresses.\n"
        "See docs/PRIVACY.md.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
