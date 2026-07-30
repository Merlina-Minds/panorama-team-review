"""Privacy machinery: the scrubber and the repository data guard.

These tests exist because the project's data guarantee must not depend on
anyone remembering it. If they fail, the guarantee is broken.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
from pathlib import Path

import pytest

from panorama_team_review.parse import panos
from panorama_team_review.parse.loader import load
from panorama_team_review.privacy.scrub import Scrubber, scrub_string

REPO_ROOT = Path(__file__).resolve().parent.parent
GUARD = REPO_ROOT / "tools" / "check_no_customer_data.py"

# Everything the scrubber may emit: private space and the documentation ranges.
PERMITTED = [
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "2001:db8::/32",
                 "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def is_permitted(text: str) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return True
    return any(address in network for network in PERMITTED)


# ---------------------------------------------------------------------------
# Scrubber
# ---------------------------------------------------------------------------


def test_scrub_is_deterministic_for_a_salt(panorama_xml):
    first = scrub_string(panorama_xml, Scrubber(salt="fixed"))
    second = scrub_string(panorama_xml, Scrubber(salt="fixed"))
    assert first == second


def test_different_salts_give_different_output(panorama_xml):
    a = scrub_string(panorama_xml, Scrubber(salt="one"))
    b = scrub_string(panorama_xml, Scrubber(salt="two"))
    assert a != b


def test_random_salt_is_not_the_empty_string():
    scrubber = Scrubber.with_random_salt()
    assert len(scrubber.salt) >= 16


def test_every_emitted_address_is_non_routable(panorama_xml):
    """The whole point: a scrubbed file must not contain a real address."""
    scrubbed = scrub_string(panorama_xml, Scrubber(salt="s"))
    offenders = [
        match for match in IPV4_RE.findall(scrubbed)
        if not is_permitted(match) and not _looks_like_a_version(match, scrubbed)
    ]
    assert offenders == [], f"scrubbed output leaked routable addresses: {offenders[:5]}"


def _looks_like_a_version(match: str, text: str) -> bool:
    """PAN-OS version strings such as 11.1.0 are not addresses."""
    return match.count(".") == 3 and False


def test_broad_networks_keep_their_prefix_length(panorama_xml):
    """A /16 must stay a /16, or breadth findings differ on the reproducer."""
    scrubber = Scrubber(salt="s")
    assert scrubber.network("10.10.0.0/16").endswith("/16")
    assert scrubber.network("172.16.0.0/12").endswith("/12")
    assert scrubber.network("10.0.0.0/8").endswith("/8")


def test_networks_broader_than_the_pool_are_clamped():
    """A /4 cannot fit inside a /8; clamping is correct and stays in range."""
    result = Scrubber(salt="s").network("0.0.0.0/4")
    assert ipaddress.ip_network(result).subnet_of(ipaddress.ip_network("10.0.0.0/8"))


def test_ranges_stay_syntactically_valid():
    """An ip-range takes bare addresses; a prefix would break reimport."""
    result = Scrubber(salt="s").network("10.0.0.5-10.0.0.9")
    start, _, end = result.partition("-")
    assert "/" not in start and "/" not in end
    ipaddress.ip_address(start)
    ipaddress.ip_address(end)


def test_the_same_input_maps_to_the_same_output():
    scrubber = Scrubber(salt="s")
    assert scrubber.network("10.1.1.1/32") == scrubber.network("10.1.1.1/32")
    assert scrubber.name("web01") == scrubber.name("web01")


def test_different_inputs_map_to_different_outputs():
    """Collapsing two networks into one would silently merge unrelated rules."""
    scrubber = Scrubber(salt="s")
    seen = {scrubber.network(f"10.1.{i}.0/24") for i in range(50)}
    assert len(seen) == 50


def test_keywords_are_preserved():
    """Replacing 'any' would change what the configuration means."""
    scrubber = Scrubber(salt="s")
    for keyword in ("any", "application-default", "allow", "deny", "vsys1"):
        assert scrubber.name(keyword) == keyword


def test_descriptions_are_replaced_wholesale(panorama_xml):
    scrubbed = scrub_string(panorama_xml, Scrubber(salt="s"))
    assert "requested by" not in scrubbed
    assert "scrubbed description" in scrubbed


def test_fqdns_become_example_domains(panorama_xml):
    scrubbed = scrub_string(panorama_xml, Scrubber(salt="s"))
    assert "updates.example.com" not in scrubbed
    for match in re.findall(r"<fqdn>([^<]+)</fqdn>", scrubbed):
        assert match.endswith(".example.com")


def test_structure_survives_scrubbing(panorama_file, tmp_path):
    """A reproducer is only useful if it reproduces the same shape."""
    original = panos.parse(load(panorama_file)[0])

    scrubbed_path = tmp_path / "scrubbed.xml"
    scrubbed_path.write_text(
        scrub_string(panorama_file.read_text(encoding="utf-8"), Scrubber(salt="s")),
        encoding="utf-8",
    )
    scrubbed = panos.parse(load(scrubbed_path)[0])

    assert len(scrubbed.rules) == len(original.rules)
    assert len(scrubbed.addresses) == len(original.addresses)
    assert len(scrubbed.address_groups) == len(original.address_groups)
    assert len(scrubbed.device_groups) == len(original.device_groups)
    assert len(scrubbed.services) == len(original.services)


def test_scrubbed_config_still_resolves(panorama_file, tmp_path):
    """Group membership must survive, or the reproducer resolves to nothing."""
    from panorama_team_review.resolve.objects import resolve_snapshot

    scrubbed_path = tmp_path / "scrubbed.xml"
    scrubbed_path.write_text(
        scrub_string(panorama_file.read_text(encoding="utf-8"), Scrubber(salt="s")),
        encoding="utf-8",
    )
    snapshot = panos.parse(load(scrubbed_path)[0])
    resolve_snapshot(snapshot)

    resolved = [rule for rule in snapshot.rules if rule.source.networks or rule.source.is_any]
    assert len(resolved) == len(snapshot.rules)


def test_serials_are_replaced(panorama_xml):
    scrubbed = scrub_string(panorama_xml, Scrubber(salt="s"))
    assert "001901000000" not in scrubbed


# ---------------------------------------------------------------------------
# Repository data guard
# ---------------------------------------------------------------------------


def run_guard(*paths: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GUARD), *[str(p) for p in paths]],
        capture_output=True, text=True, cwd=REPO_ROOT, check=False,
    )


def test_guard_exists():
    assert GUARD.is_file()


def test_guard_passes_on_this_repository():
    """The guarantee, checked against the actual tree."""
    tracked = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, cwd=REPO_ROOT, check=False
    )
    if tracked.returncode != 0:
        pytest.skip("not a git repository")

    files = [
        REPO_ROOT / name
        for name in tracked.stdout.splitlines()
        if name and (REPO_ROOT / name).is_file()
    ]
    if not files:
        pytest.skip("nothing committed yet")

    result = run_guard(*files)
    assert result.returncode == 0, result.stderr


def test_guard_blocks_a_routable_address(tmp_path):
    path = tmp_path / "leak.txt"
    # Deliberately a routable address: this asserts the guard catches one.
    path.write_text("connect to 93.184.216.34 for the service\n", encoding="utf-8")  # allow-customer-data-check
    result = run_guard(path)
    assert result.returncode == 1
    assert "non-documentation IPv4" in result.stderr


def test_guard_allows_documentation_addresses(tmp_path):
    path = tmp_path / "fine.txt"
    path.write_text(
        "use 192.0.2.1, 198.51.100.5, 203.0.113.9, 10.0.0.1 and 2001:db8::1\n",
        encoding="utf-8",
    )
    assert run_guard(path).returncode == 0


def test_guard_blocks_a_real_hostname(tmp_path):
    path = tmp_path / "host.txt"
    path.write_text("fw01.acmecorp.de is the firewall\n", encoding="utf-8")  # allow-customer-data-check
    result = run_guard(path)
    assert result.returncode == 1
    assert "non-example hostname" in result.stderr


def test_guard_allows_example_hostnames(tmp_path):
    path = tmp_path / "host.txt"
    path.write_text("fw01.example.com and mail@example.org\n", encoding="utf-8")
    assert run_guard(path).returncode == 0


def test_guard_blocks_a_device_serial(tmp_path):
    path = tmp_path / "serial.txt"
    path.write_text('<entry name="012345678901"/>\n', encoding="utf-8")  # allow-customer-data-check
    result = run_guard(path)
    assert result.returncode == 1
    assert "serial" in result.stderr


def test_guard_blocks_an_api_key(tmp_path):
    path = tmp_path / "key.txt"
    path.write_text(
        "key=LUFRPT1abcdefghijklmnopqrstuvwxyz0123456789ABCDEF\n", encoding="utf-8"  # allow-customer-data-check
    )
    result = run_guard(path)
    assert result.returncode == 1
    assert "API key" in result.stderr


def test_guard_blocks_a_private_key(tmp_path):
    path = tmp_path / "id.pem"
    path.write_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n", encoding="utf-8")  # allow-customer-data-check
    assert run_guard(path).returncode == 1


def test_guard_blocks_a_suspicious_filename(tmp_path):
    path = tmp_path / "running-config.xml"
    path.write_text("<config/>\n", encoding="utf-8")
    result = run_guard(path)
    assert result.returncode == 1
    assert "suspicious filename" in result.stderr


def test_guard_override_marker_works(tmp_path):
    path = tmp_path / "ok.txt"
    path.write_text(
        "the vendor endpoint 93.184.216.34  # allow-customer-data-check\n", encoding="utf-8"
    )
    assert run_guard(path).returncode == 0


def test_guard_reports_the_line_number(tmp_path):
    path = tmp_path / "leak.txt"
    path.write_text("clean\nclean\n93.184.216.34\n", encoding="utf-8")
    result = run_guard(path)
    assert ":3:" in result.stderr


# ---------------------------------------------------------------------------
# Generator output must itself pass the guard
# ---------------------------------------------------------------------------


def test_generated_fixtures_pass_the_guard(tmp_path, panorama_xml, firewall_xml):
    """The generator is the only sanctioned source of test data."""
    panorama = tmp_path / "generated-panorama.xml"
    firewall = tmp_path / "generated-firewall.xml"
    panorama.write_text(panorama_xml, encoding="utf-8")
    firewall.write_text(firewall_xml, encoding="utf-8")

    result = run_guard(panorama, firewall)
    # The generator emits device serials, which the guard flags by design.
    # Everything else must be clean.
    non_serial = [
        line for line in result.stderr.splitlines()
        if ": " in line and "serial" not in line and line.startswith(str(tmp_path))
    ]
    assert non_serial == [], non_serial


def test_generator_uses_only_documentation_addresses(panorama_xml):
    offenders = [match for match in IPV4_RE.findall(panorama_xml) if not is_permitted(match)]
    assert offenders == [], f"generator emitted routable addresses: {set(offenders)}"


def test_generator_uses_only_example_domains(panorama_xml, firewall_xml):
    for content in (panorama_xml, firewall_xml):
        for host in re.findall(r"\b[\w-]+(?:\.[\w-]+)+\b", content):
            # Skip anything that is an address, an address range or a version
            # string rather than a name.
            if re.fullmatch(r"[\d.-]+", host):
                continue
            if re.fullmatch(r"ethernet\d+/\d+", host):
                continue
            assert host.endswith(("example.com", "localdomain")), host


def test_guard_blocks_a_serial_attached_to_a_hostname(tmp_path):
    """The way a serial actually reaches a repository like this one.

    Panorama names the members of a backup archive `<hostname>_<serial>.xml`,
    and somebody quotes one in a comment to explain what the parser handles.
    The original pattern was `\\b\\d{12}\\b`, which does not match there: an
    underscore is a word character, so there is no boundary before the digits.
    The guard let through precisely the case it existed for, and one sat in
    `parse/panos.py` until this test was written.
    """
    path = tmp_path / "note.py"
    path.write_text('# member fw-eu-02_012345678901.xml\n', encoding="utf-8")  # allow-customer-data-check
    result = run_guard(path)
    assert result.returncode != 0
    assert "serial" in result.stderr.lower()


def test_guard_blocks_a_member_name_with_any_long_serial(tmp_path):
    """Caught by shape as well as by length, so another width is no free pass."""
    path = tmp_path / "note.py"
    path.write_text('archive member fw-eu-01_9876543210.xml\n', encoding="utf-8")  # allow-customer-data-check
    result = run_guard(path)
    assert result.returncode != 0
    assert "member name" in result.stderr.lower()


def test_guard_allows_an_ordinary_identifier_with_digits(tmp_path):
    """`scope_2` and `rule_12` must not become findings."""
    path = tmp_path / "ok.py"
    path.write_text("scope_2 = rule_12 + offset_42\n", encoding="utf-8")
    result = run_guard(path)
    assert result.returncode == 0, result.stderr


def test_guard_allows_the_reserved_fixture_serial_range(tmp_path):
    """`001901……` is this repository's invented serial range.

    The generated example estate is meant to be committed and read, and it is
    full of them. Without a reserved range it could not pass the guard that
    exists to protect it -- the same bargain the documentation address ranges
    already make.
    """
    path = tmp_path / "estate.xml"
    path.write_text('<entry name="001901000000"/>\n', encoding="utf-8")
    result = run_guard(path)
    assert result.returncode == 0, result.stderr
