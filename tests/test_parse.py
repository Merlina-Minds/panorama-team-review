"""Parsing PAN-OS and Panorama configurations, and loading backup files."""

from __future__ import annotations

import gzip
import tarfile
import time
from datetime import datetime
from pathlib import Path

import pytest

from panorama_team_review.config import InputConfig
from panorama_team_review.errors import BackupNotFoundError, BackupStaleError, ParseError
from panorama_team_review.model import Rulebase
from panorama_team_review.parse import panos
from panorama_team_review.parse.loader import find_backups, load

# ---------------------------------------------------------------------------
# Type detection
# ---------------------------------------------------------------------------


def test_detects_panorama_configuration(panorama_file: Path):
    assert load(panorama_file)[0].detect_type() == "panorama"


def test_detects_firewall_configuration(firewall_file: Path):
    assert load(firewall_file)[0].detect_type() == "firewall"


def test_unrecognisable_xml_is_rejected(tmp_path: Path):
    path = tmp_path / "not-a-config.xml"
    path.write_text("<config><something-else/></config>", encoding="utf-8")
    with pytest.raises(ParseError, match="not recognisable"):
        load(path)[0].detect_type()


def test_malformed_xml_gives_a_readable_error(tmp_path: Path):
    path = tmp_path / "broken.xml"
    path.write_text("<config><unclosed>", encoding="utf-8")
    with pytest.raises(ParseError, match="not well formed"):
        load(path)


# ---------------------------------------------------------------------------
# Panorama structure
# ---------------------------------------------------------------------------


def test_parses_device_groups(panorama_snapshot):
    assert set(panorama_snapshot.device_groups) == {
        "DG-Shared-Services", "DG-Production", "DG-Development",
    }


def test_records_device_group_parent(panorama_snapshot):
    """DG-Development is generated as a child of DG-Shared-Services."""
    assert panorama_snapshot.device_groups["DG-Development"].parent == "DG-Shared-Services"
    assert panorama_snapshot.device_groups["DG-Shared-Services"].parent is None


def test_separates_pre_and_post_rulebases(panorama_snapshot):
    rulebases = {rule.location.rulebase for rule in panorama_snapshot.rules}
    assert Rulebase.PRE in rulebases
    assert Rulebase.POST in rulebases


def test_shared_rules_are_marked_shared(panorama_snapshot):
    shared = [rule for rule in panorama_snapshot.rules if rule.location.shared]
    assert {rule.name for rule in shared} == {"shared-allow-dns", "shared-deny-all"}


def test_rule_order_is_preserved(panorama_snapshot):
    production = [
        rule for rule in panorama_snapshot.rules
        if rule.location.device_group == "DG-Production"
        and rule.location.rulebase is Rulebase.PRE
    ]
    assert [rule.order for rule in production] == list(range(len(production)))


def test_objects_carry_their_defining_scope(panorama_snapshot):
    scopes = {address.location.scope for address in panorama_snapshot.addresses}
    assert "shared" in scopes
    assert "DG-Production" in scopes


def test_parses_zones_from_templates(panorama_snapshot):
    assert {"trust", "untrust", "dmz", "internal"} <= set(panorama_snapshot.zones)


def test_parses_managed_device_serials(panorama_snapshot):
    assert len(panorama_snapshot.devices) == len(panorama_snapshot.device_groups)


# ---------------------------------------------------------------------------
# Rule fields
# ---------------------------------------------------------------------------


def test_parses_rule_fields(panorama_snapshot):
    rule = next(r for r in panorama_snapshot.rules if r.name == "shared-allow-dns")
    assert rule.action.value == "allow"
    assert rule.destination.raw == ["grp-dns-servers"]
    assert rule.source.is_any
    assert rule.applications == ["dns"]
    assert rule.services.raw == ["svc-dns"]
    assert rule.tags == ["owner:platform"]
    assert rule.log_end is True
    assert rule.uuid is not None


def test_parses_disabled_flag(panorama_snapshot):
    disabled = [rule for rule in panorama_snapshot.rules if rule.disabled]
    assert disabled, "the generator produces disabled rules"


def test_any_is_normalised_out_of_raw(panorama_snapshot):
    rule = next(r for r in panorama_snapshot.rules if r.source.is_any)
    assert "any" not in rule.source.raw


def test_deny_action_is_parsed(panorama_snapshot):
    deny = next(r for r in panorama_snapshot.rules if r.name == "shared-deny-all")
    assert deny.action.value == "deny"
    assert not deny.action.permits_traffic


def test_application_default_service_is_flagged(panorama_snapshot):
    rule = next(
        r for r in panorama_snapshot.rules if r.services.is_application_default
    )
    assert not rule.services.raw


# ---------------------------------------------------------------------------
# Firewall structure
# ---------------------------------------------------------------------------


def test_firewall_rules_are_local(firewall_snapshot):
    assert all(rule.location.rulebase is Rulebase.LOCAL for rule in firewall_snapshot.rules)
    assert all(rule.location.vsys == "vsys1" for rule in firewall_snapshot.rules)


def test_firewall_has_no_device_groups(firewall_snapshot):
    assert firewall_snapshot.device_groups == {}


def test_firewall_parses_nat_rules(firewall_snapshot):
    assert len(firewall_snapshot.nat_rules) == 1
    nat = firewall_snapshot.nat_rules[0]
    assert nat.translated_source is not None
    assert nat.translated_source.raw == ["partner-range"]


def test_firewall_parses_zones(firewall_snapshot):
    assert {"trust", "untrust", "dmz"} <= set(firewall_snapshot.zones)


def test_hostname_is_captured(firewall_snapshot):
    assert firewall_snapshot.meta.hostname == "fw-edge-01.example.com"


# ---------------------------------------------------------------------------
# Loader: file discovery
# ---------------------------------------------------------------------------


def test_finds_the_newest_backup(tmp_path: Path, panorama_xml: str):
    for index, name in enumerate(["old.xml", "middle.xml", "newest.xml"]):
        path = tmp_path / name
        path.write_text(panorama_xml, encoding="utf-8")
        # Explicit mtimes: relying on write order is flaky on fast filesystems.
        stamp = time.time() - (10 - index) * 3600
        import os

        os.utime(path, (stamp, stamp))

    found = find_backups(InputConfig(backup_dir=tmp_path, select="latest"))
    assert [path.name for path in found] == ["newest.xml"]


def test_select_all_returns_everything_newest_first(tmp_path: Path, panorama_xml: str):
    import os

    for index, name in enumerate(["a.xml", "b.xml"]):
        path = tmp_path / name
        path.write_text(panorama_xml, encoding="utf-8")
        stamp = time.time() - (5 - index) * 3600
        os.utime(path, (stamp, stamp))

    found = find_backups(InputConfig(backup_dir=tmp_path, select="all"))
    assert [path.name for path in found] == ["b.xml", "a.xml"]


def test_explicit_backup_overrides_the_directory(tmp_path: Path, panorama_file: Path):
    found = find_backups(InputConfig(backup_dir=tmp_path), explicit=panorama_file)
    assert found == [panorama_file]


def test_missing_directory_is_reported(tmp_path: Path):
    with pytest.raises(BackupNotFoundError, match="does not exist"):
        find_backups(InputConfig(backup_dir=tmp_path / "nope"))


def test_empty_directory_is_reported(tmp_path: Path):
    with pytest.raises(BackupNotFoundError, match="no backup matching"):
        find_backups(InputConfig(backup_dir=tmp_path))


def test_no_directory_and_no_explicit_file_is_reported():
    with pytest.raises(BackupNotFoundError, match="no backup specified"):
        find_backups(InputConfig())


def test_stale_backup_is_refused(tmp_path: Path, panorama_xml: str):
    """A broken backup job must not silently feed stale data into a review."""
    import os

    path = tmp_path / "old.xml"
    path.write_text(panorama_xml, encoding="utf-8")
    stamp = time.time() - 30 * 86400
    os.utime(path, (stamp, stamp))

    with pytest.raises(BackupStaleError, match="most likely broken"):
        find_backups(InputConfig(backup_dir=tmp_path, max_age_days=7))


def test_recursive_search(tmp_path: Path, panorama_xml: str):
    nested = tmp_path / "2026" / "07"
    nested.mkdir(parents=True)
    (nested / "config.xml").write_text(panorama_xml, encoding="utf-8")

    with pytest.raises(BackupNotFoundError):
        find_backups(InputConfig(backup_dir=tmp_path, recursive=False))
    assert find_backups(InputConfig(backup_dir=tmp_path, recursive=True))


# ---------------------------------------------------------------------------
# Loader: compressed and archived backups
# ---------------------------------------------------------------------------


def test_reads_gzipped_backup(tmp_path: Path, panorama_xml: str):
    path = tmp_path / "config.xml.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write(panorama_xml)
    assert load(path)[0].detect_type() == "panorama"


def test_reads_tar_archive_with_several_configs(tmp_path: Path, panorama_xml, firewall_xml):
    """Panorama's scheduled backup ships one archive per estate."""
    archive = tmp_path / "backup.tgz"
    panorama_path = tmp_path / "panorama.xml"
    firewall_path = tmp_path / "fw01.xml"
    panorama_path.write_text(panorama_xml, encoding="utf-8")
    firewall_path.write_text(firewall_xml, encoding="utf-8")

    with tarfile.open(archive, "w:gz") as tar:
        tar.add(panorama_path, arcname="panorama.xml")
        tar.add(firewall_path, arcname="devices/fw01.xml")

    documents = load(archive)
    assert len(documents) == 2
    assert {doc.detect_type() for doc in documents} == {"panorama", "firewall"}


def test_archive_without_xml_is_rejected(tmp_path: Path):
    archive = tmp_path / "empty.tgz"
    readme = tmp_path / "README"
    readme.write_text("nothing here", encoding="utf-8")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(readme, arcname="README")

    with pytest.raises(ParseError, match="no .xml member"):
        load(archive)


def test_config_hash_is_stable(panorama_file: Path):
    assert load(panorama_file)[0].config_hash == load(panorama_file)[0].config_hash


def test_external_entities_are_not_resolved(tmp_path: Path):
    """XXE defence: backups are untrusted input and this runs unattended."""
    path = tmp_path / "xxe.xml"
    path.write_text(
        '<?xml version="1.0"?>'
        '<!DOCTYPE config [<!ENTITY secret SYSTEM "file:///etc/passwd">]>'
        "<config><devices><entry><vsys><entry name='vsys1'>"
        "<description>&secret;</description></entry></vsys></entry></devices></config>",
        encoding="utf-8",
    )
    document = load(path)[0]
    text = document.root.findtext(".//description") or ""
    assert "root:" not in text


# ---------------------------------------------------------------------------
# Merging
# ---------------------------------------------------------------------------


def test_merge_combines_documents(panorama_file: Path, firewall_file: Path):
    snapshots = [
        panos.parse(load(panorama_file)[0]),
        panos.parse(load(firewall_file)[0]),
    ]
    merged = panos.merge(snapshots)
    assert merged.meta.source_type == "panorama"
    assert len(merged.rules) == sum(len(s.rules) for s in snapshots)
    assert len(merged.device_groups) == len(snapshots[0].device_groups)


def test_merge_of_one_snapshot_is_identity(panorama_snapshot):
    assert panos.merge([panorama_snapshot]) is panorama_snapshot


def test_merge_deduplicates_devices(panorama_file: Path):
    a = panos.parse(load(panorama_file)[0])
    b = panos.parse(load(panorama_file)[0])
    merged = panos.merge([a, b])
    serials = [device.serial for device in merged.devices]
    assert len(serials) == len(set(serials))


def test_merge_requires_input():
    with pytest.raises(ValueError):
        panos.merge([])


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def test_snapshot_metadata(panorama_snapshot):
    meta = panorama_snapshot.meta
    assert meta.source_type == "panorama"
    assert meta.pan_os_version == "11.1.0"
    assert isinstance(meta.parsed_at, datetime)
    assert len(meta.config_hash) == 64


# ---------------------------------------------------------------------------
# Device-group hierarchy: the readonly block
# ---------------------------------------------------------------------------


def test_hierarchy_is_read_from_the_readonly_block(panorama_snapshot):
    """Panorama keeps the parent links in `readonly`, not on the editable node.

    Regression test for a real failure: the parser looked only under
    /config/devices/.../parent-dg, found nothing on an actual export, and
    treated every device group as a root. Children then could not see their
    parent's objects, so those references resolved to nothing and the report
    understated what the rules permitted.
    """
    assert panorama_snapshot.device_groups["DG-Development"].parent == "DG-Shared-Services"
    assert panorama_snapshot.device_groups["DG-Shared-Services"].parent is None


def test_hierarchy_also_read_from_the_editable_node(tmp_path):
    """Some versions do populate the editable device-group node."""
    from fixtures.generator import GeneratorOptions, generate_panorama

    options = GeneratorOptions(hierarchy_in_readonly_only=False,
                               include_readonly_hierarchy=False)
    path = tmp_path / "editable.xml"
    path.write_text(generate_panorama(options), encoding="utf-8")

    snapshot = panos.parse(load(path)[0])
    assert snapshot.device_groups["DG-Development"].parent == "DG-Shared-Services"


def test_child_resolves_objects_defined_in_its_parent(panorama_snapshot):
    """The consequence of the hierarchy, asserted end to end."""
    from panorama_team_review.model import Location, ResolvedAddresses
    from panorama_team_review.resolve.objects import build_index, resolve_addresses

    index = build_index(panorama_snapshot)
    child = Location(source="t.xml", device_group="DG-Development")
    assert index.scope_chain(child) == ["DG-Development", "DG-Shared-Services", "shared"]

    parent_object = next(
        address.name for address in panorama_snapshot.addresses
        if address.location.scope == "DG-Shared-Services"
    )
    result = resolve_addresses(ResolvedAddresses(raw=[parent_object]), child, index)
    assert result.networks, "a child device group must see its parent's objects"


def test_missing_readonly_block_is_not_fatal(tmp_path):
    from fixtures.generator import GeneratorOptions, generate_panorama

    options = GeneratorOptions(include_readonly_hierarchy=False)
    path = tmp_path / "flat.xml"
    path.write_text(generate_panorama(options), encoding="utf-8")

    snapshot = panos.parse(load(path)[0])
    assert len(snapshot.device_groups) == 3
    assert all(group.parent is None for group in snapshot.device_groups.values())


# ---------------------------------------------------------------------------
# Namespace isolation when merging a multi-device archive
# ---------------------------------------------------------------------------


def test_merged_firewalls_keep_separate_namespaces(tmp_path):
    """`shared` and `vsys1` are per device, not estate-wide.

    A Panorama backup archive holds one configuration per managed firewall, and
    every one of them has its own `shared` and `vsys1`. Merging them without a
    device qualifier collapses those namespaces, so an object named
    `edge-host-01` on one firewall answers lookups meant for the identically
    named object on another — and the report shows the wrong addresses for a
    rule. Regression test for exactly that.
    """
    from fixtures.generator import GeneratorOptions, generate_firewall

    first = tmp_path / "fw-a.xml"
    second = tmp_path / "fw-b.xml"
    first.write_text(
        generate_firewall(GeneratorOptions(seed=1, firewall_hostname="fw-a.example.com")),
        encoding="utf-8",
    )
    second.write_text(
        generate_firewall(GeneratorOptions(seed=2, firewall_hostname="fw-b.example.com")),
        encoding="utf-8",
    )

    merged = panos.merge([panos.parse(load(first)[0]), panos.parse(load(second)[0])])

    scopes = {address.location.scope for address in merged.addresses}
    assert "fw-a.example.com:vsys1" in scopes
    assert "fw-b.example.com:vsys1" in scopes

    from panorama_team_review.resolve.objects import build_index
    index = build_index(merged)
    assert [w for w in index.warnings if "duplicate" in w] == []

    # The same object name exists on both devices and must stay distinct.
    shared_names = {a.name for a in merged.addresses if a.location.device == "fw-a.example.com"}
    other_names = {a.name for a in merged.addresses if a.location.device == "fw-b.example.com"}
    assert shared_names & other_names, "the fixture should produce colliding names"

    a_object = index.addresses[("fw-a.example.com:vsys1", "edge-host-01")]
    b_object = index.addresses[("fw-b.example.com:vsys1", "edge-host-01")]
    assert a_object is not b_object


def test_firewall_rule_resolves_against_its_own_device(tmp_path):
    from fixtures.generator import GeneratorOptions, generate_firewall

    from panorama_team_review.resolve.objects import build_index

    first = tmp_path / "fw-a.xml"
    second = tmp_path / "fw-b.xml"
    first.write_text(
        generate_firewall(GeneratorOptions(seed=1, firewall_hostname="fw-a.example.com")),
        encoding="utf-8",
    )
    second.write_text(
        generate_firewall(GeneratorOptions(seed=2, firewall_hostname="fw-b.example.com")),
        encoding="utf-8",
    )
    merged = panos.merge([panos.parse(load(first)[0]), panos.parse(load(second)[0])])
    index = build_index(merged)

    rule = next(r for r in merged.rules if r.location.device == "fw-a.example.com")
    chain = index.scope_chain(rule.location)
    assert chain[0] == "fw-a.example.com:vsys1"
    assert chain[-1] == "shared", "Panorama-pushed objects must remain reachable"
    assert not any(scope.startswith("fw-b") for scope in chain)


def test_single_firewall_scope_stays_readable(firewall_snapshot):
    """The device qualifier must not clutter the common single-device case."""
    label = firewall_snapshot.rules[0].location.label()
    assert label.startswith("fw-edge-01.example.com:vsys1")


# ---------------------------------------------------------------------------
# Choosing the newest backup by filename rather than mtime
# ---------------------------------------------------------------------------


def _touch(path: Path, xml: str, when: str) -> Path:
    """Write a file and set its mtime explicitly."""
    import os
    from datetime import datetime as dt

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(xml, encoding="utf-8")
    stamp = dt.fromisoformat(when).timestamp()
    os.utime(path, (stamp, stamp))
    return path


def test_filename_date_beats_a_rewritten_mtime(tmp_path, panorama_xml):
    """Copying a backup rewrites its mtime; the name still tells the truth.

    An estate that mirrors backups into rotating directories can end up with an
    old configuration carrying a fresh timestamp. Selecting on mtime would then
    report on stale policy while looking perfectly healthy.
    """
    _touch(tmp_path / "A" / "panorama-20260728.tgz", panorama_xml, "2026-07-28T16:15")
    old = _touch(tmp_path / "B" / "panorama-20260901.tgz", panorama_xml, "2026-07-28T14:15")

    by_mtime = find_backups(InputConfig(backup_dir=tmp_path, recursive=True, patterns=["*.tgz"]))
    assert by_mtime[0].name == "panorama-20260728.tgz"

    by_name = find_backups(
        InputConfig(backup_dir=tmp_path, recursive=True, patterns=["*.tgz"],
                    select_by="filename")
    )
    assert by_name[0] == old


def test_filename_selection_searches_rotating_directories(tmp_path, panorama_xml):
    """The A/B rotation case: newest across both, not newest within one."""
    for day in (26, 27, 28):
        _touch(tmp_path / "A" / f"panorama-202607{day}.tgz", panorama_xml,
               f"2026-07-{day}T20:15")
        _touch(tmp_path / "B" / f"panorama-202607{day}.tgz", panorama_xml,
               f"2026-07-{day}T22:15")

    found = find_backups(
        InputConfig(backup_dir=tmp_path, recursive=True, patterns=["*.tgz"],
                    select_by="filename")
    )
    assert "20260728" in found[0].name


def test_files_without_a_date_sort_below_dated_ones(tmp_path, panorama_xml):
    _touch(tmp_path / "manual-export.tgz", panorama_xml, "2026-09-01T10:00")
    dated = _touch(tmp_path / "panorama-20260728.tgz", panorama_xml, "2026-07-28T10:00")

    found = find_backups(
        InputConfig(backup_dir=tmp_path, patterns=["*.tgz"], select_by="filename")
    )
    assert found[0] == dated


def test_iso_dates_in_filenames_are_understood(tmp_path, panorama_xml):
    _touch(tmp_path / "backup-2026-07-20.tgz", panorama_xml, "2026-07-20T10:00")
    newer = _touch(tmp_path / "backup-2026-07-28.tgz", panorama_xml, "2026-07-20T09:00")

    found = find_backups(
        InputConfig(backup_dir=tmp_path, patterns=["*.tgz"], select_by="filename")
    )
    assert found[0] == newer


def test_filename_pattern_needs_a_date_group():
    with pytest.raises(ValueError, match="named group"):
        InputConfig(filename_date_pattern=r"\d{8}")
