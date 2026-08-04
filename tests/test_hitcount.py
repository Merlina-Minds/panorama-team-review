"""Hit-count enrichment.

Two properties matter more than the parsing details:

* it must never run unless explicitly enabled, and
* it must never issue anything but a read-only ``show`` command.

Both are asserted directly. Everything here runs against fakes -- no test in
this suite touches a network.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest
from lxml import etree

from panorama_team_review.config import HitCountConfig
from panorama_team_review.enrich import hitcount
from panorama_team_review.errors import EnrichmentError
from panorama_team_review.model import (
    DeviceGroup,
    HitCount,
    Location,
    ManagedDevice,
    Rulebase,
    SecurityRule,
    Snapshot,
    SnapshotMeta,
)

SAMPLE_RESPONSE = """<response status="success"><result><rule-hit-count>
  <vsys><entry name="vsys1"><rule-base><entry name="security"><rules>
    <entry name="allow-web">
      <latest>yes</latest>
      <hit-count>4711</hit-count>
      <last-hit-timestamp>1780000000</last-hit-timestamp>
      <first-hit-timestamp>1700000000</first-hit-timestamp>
      <rule-creation-timestamp>1690000000</rule-creation-timestamp>
    </entry>
    <entry name="never-used">
      <hit-count>0</hit-count>
      <last-hit-timestamp>0</last-hit-timestamp>
    </entry>
  </rules></entry></rule-base></entry></vsys>
</rule-hit-count></result></response>"""


def parse_result(xml: str) -> etree._Element:
    return etree.fromstring(xml.encode("utf-8")).find("result")


def make_rule(name: str, vsys: str = "vsys1") -> SecurityRule:
    return SecurityRule(
        name=name,
        location=Location(source="t.xml", vsys=vsys, rulebase=Rulebase.LOCAL),
    )


# ---------------------------------------------------------------------------
# The off switch
# ---------------------------------------------------------------------------


def test_disabled_by_default():
    assert HitCountConfig().enabled is False


def test_disabled_config_does_nothing(panorama_snapshot):
    notes = hitcount.enrich_snapshot(panorama_snapshot, HitCountConfig())
    assert notes == []
    assert all(rule.hits is None for rule in panorama_snapshot.rules)


def test_enabled_but_offline_only_does_not_collect(panorama_snapshot, monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("collect() must not run with offline_only=True")

    monkeypatch.setattr(hitcount, "collect", explode)
    config = HitCountConfig(enabled=True, devices=["fw.example.com"])
    hitcount.enrich_snapshot(panorama_snapshot, config, offline_only=True)


# ---------------------------------------------------------------------------
# Read-only guarantee
# ---------------------------------------------------------------------------


def test_non_show_command_is_refused():
    """Defence in depth: this module must not be able to change a device."""
    with pytest.raises(EnrichmentError, match="refusing to send"):
        hitcount._operational(
            object(), "fw.example.com", "key",
            "<set><deviceconfig/></set>", HitCountConfig(),
        )


def test_commit_command_is_refused():
    with pytest.raises(EnrichmentError, match="refusing to send"):
        hitcount._operational(
            object(), "fw.example.com", "key", "<commit/>", HitCountConfig()
        )


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def test_parses_hit_counts():
    counters = hitcount._parse_hit_counts(
        parse_result(SAMPLE_RESPONSE), scope="vsys1", rulebase="local",
        source="api:fw", collected_at=datetime(2026, 7, 28),
    )
    assert counters["vsys1|local|allow-web"].hit_count == 4711
    assert counters["vsys1|local|never-used"].hit_count == 0


def test_zero_timestamp_means_never():
    counters = hitcount._parse_hit_counts(
        parse_result(SAMPLE_RESPONSE), "vsys1", "local", "api:fw", datetime(2026, 7, 28)
    )
    assert counters["vsys1|local|never-used"].last_hit is None
    assert counters["vsys1|local|allow-web"].last_hit is not None


def test_missing_fields_default_safely():
    xml = """<response status="success"><result><rule-hit-count><vsys><entry name="vsys1">
      <rule-base><entry name="security"><rules><entry name="r"/></rules></entry></rule-base>
    </entry></vsys></rule-hit-count></result></response>"""
    counters = hitcount._parse_hit_counts(
        parse_result(xml), "vsys1", "local", "api:fw", datetime(2026, 7, 28)
    )
    assert counters["vsys1|local|r"].hit_count == 0


@pytest.mark.parametrize(
    ("raw", "expected_none"),
    [("0", True), ("", True), (None, True), ("not-a-number", True), ("1780000000", False)],
)
def test_timestamp_parsing(raw, expected_none):
    assert (hitcount._timestamp(raw) is None) is expected_none


def test_error_response_is_reported():
    class FakeSession:
        def post(self, url, **kwargs):
            class Response:
                status_code = 200
                content = (
                    b'<response status="error"><msg>Invalid credentials</msg></response>'
                )

            return Response()

    with pytest.raises(EnrichmentError, match="Invalid credentials"):
        hitcount._operational(
            FakeSession(), "fw.example.com", "k", "<show><x/></show>", HitCountConfig()
        )


def test_http_error_is_reported():
    class FakeSession:
        def post(self, url, **kwargs):
            class Response:
                status_code = 403
                content = b""

            return Response()

    with pytest.raises(EnrichmentError, match="HTTP 403"):
        hitcount._operational(
            FakeSession(), "fw.example.com", "k", "<show><x/></show>", HitCountConfig()
        )


def test_malformed_xml_is_reported():
    class FakeSession:
        def post(self, url, **kwargs):
            class Response:
                status_code = 200
                content = b"<response status=success"

            return Response()

    with pytest.raises(EnrichmentError, match="malformed XML"):
        hitcount._operational(
            FakeSession(), "fw.example.com", "k", "<show><x/></show>", HitCountConfig()
        )


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def test_api_key_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("PAN_API_KEY", "secret-key")
    assert hitcount._api_key(HitCountConfig()) == "secret-key"


def test_api_key_from_a_file(tmp_path, monkeypatch):
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    key_file = tmp_path / "api.key"
    key_file.write_text("file-key\n", encoding="utf-8")
    assert hitcount._api_key(HitCountConfig(api_key_file=key_file)) == "file-key"


def test_missing_api_key_gives_an_actionable_message(monkeypatch):
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    with pytest.raises(EnrichmentError, match="never read from the configuration file"):
        hitcount._api_key(HitCountConfig())


def test_empty_key_file_is_rejected(tmp_path, monkeypatch):
    monkeypatch.delenv("PAN_API_KEY", raising=False)
    key_file = tmp_path / "api.key"
    key_file.write_text("   \n", encoding="utf-8")
    with pytest.raises(EnrichmentError, match="empty"):
        hitcount._api_key(HitCountConfig(api_key_file=key_file))


# ---------------------------------------------------------------------------
# Applying counters to rules
# ---------------------------------------------------------------------------


def test_counters_attach_by_qualified_key():
    rule = make_rule("allow-web")
    counters = {"vsys1|local|allow-web": HitCount(hit_count=99, source="api:fw")}
    assert hitcount._apply([rule], counters) == 1
    assert rule.hits is not None and rule.hits.hit_count == 99


def test_unambiguous_bare_name_falls_back():
    rule = make_rule("allow-web", vsys="vsys2")
    counters = {"vsys1|local|allow-web": HitCount(hit_count=99, source="api:fw")}
    assert hitcount._apply([rule], counters) == 1


def test_ambiguous_bare_name_is_not_guessed():
    """Attaching the wrong counter would produce a confidently wrong verdict."""
    rule = make_rule("dup", vsys="vsys9")
    counters = {
        "vsys1|local|dup": HitCount(hit_count=1, source="api:a"),
        "vsys2|local|dup": HitCount(hit_count=2, source="api:b"),
    }
    assert hitcount._apply([rule], counters) == 0
    assert rule.hits is None


def test_rules_without_counters_stay_none():
    rule = make_rule("unmatched")
    assert hitcount._apply([rule], {}) == 0
    assert rule.hits is None


# ---------------------------------------------------------------------------
# Sidecar cache
# ---------------------------------------------------------------------------


def test_cache_round_trips(tmp_path):
    config = HitCountConfig(enabled=True, cache_dir=tmp_path)
    counters = {
        "vsys1|local|r": HitCount(
            hit_count=5, collected_at=datetime.now(), source="api:fw"
        )
    }
    hitcount._write_cache(config, counters)
    loaded, notes = hitcount._load_cache(config)
    assert loaded["vsys1|local|r"].hit_count == 5
    assert any("cached hit counts" in note for note in notes)


def test_unreadable_cache_is_ignored_not_fatal(tmp_path):
    (tmp_path / "hitcounts.json").write_text("{not json", encoding="utf-8")
    loaded, notes = hitcount._load_cache(HitCountConfig(cache_dir=tmp_path))
    assert loaded == {}
    assert any("unreadable" in note for note in notes)


def test_absent_cache_is_not_an_error(tmp_path):
    assert hitcount._load_cache(HitCountConfig(cache_dir=tmp_path)) == ({}, [])


def test_fresh_cache_is_not_stale(tmp_path):
    config = HitCountConfig(cache_dir=tmp_path, cache_max_age_hours=24)
    counters = {"k": HitCount(collected_at=datetime.now(), source="api:fw")}
    assert hitcount._cache_is_stale(config, counters) is False


def test_old_cache_is_stale(tmp_path):
    config = HitCountConfig(cache_dir=tmp_path, cache_max_age_hours=1)
    counters = {
        "k": HitCount(collected_at=datetime.now() - timedelta(hours=5), source="api:fw")
    }
    assert hitcount._cache_is_stale(config, counters) is True


def test_empty_cache_counts_as_stale(tmp_path):
    assert hitcount._cache_is_stale(HitCountConfig(cache_dir=tmp_path), {}) is True


def test_cache_file_is_json(tmp_path):
    config = HitCountConfig(cache_dir=tmp_path)
    hitcount._write_cache(config, {"k": HitCount(hit_count=1, source="api:fw")})
    data = json.loads((tmp_path / "hitcounts.json").read_text(encoding="utf-8"))
    assert "collected_at" in data and "counters" in data


# ---------------------------------------------------------------------------
# Failure never breaks the report
# ---------------------------------------------------------------------------


def test_collection_failure_is_a_note_not_an_exception(panorama_snapshot, monkeypatch):
    """A cron job that aborts because one firewall was unreachable is useless."""

    def fail(config, progress=None):
        raise EnrichmentError("device unreachable")

    monkeypatch.setattr(hitcount, "collect", fail)
    config = HitCountConfig(enabled=True, devices=["fw.example.com"])
    notes = hitcount.enrich_snapshot(panorama_snapshot, config)
    assert any("failed" in note for note in notes)
    assert all(rule.hits is None for rule in panorama_snapshot.rules)


def test_xml_escaping_of_device_names():
    assert hitcount._xml_escape("a<b>&'\"") == "a&lt;b&gt;&amp;&apos;&quot;"


# ---------------------------------------------------------------------------
# Panorama: per-device counters aggregated onto device-group rules
# ---------------------------------------------------------------------------


def _snapshot(rules, device_groups=None, devices=None) -> Snapshot:
    return Snapshot(
        meta=SnapshotMeta(source_file="t", parsed_at=datetime.now()),
        device_groups=device_groups or {},
        devices=devices or [],
        rules=rules,
    )


def _device_counter(serial: str, name: str, **fields) -> tuple[str, HitCount]:
    return f"{hitcount._DEVICE_KEY_PREFIX}{serial}{hitcount._SEP}{name}", HitCount(**fields)


def test_device_group_rule_sums_its_firewalls_hits():
    rule = SecurityRule(
        name="allow-web", location=Location(source="t", device_group="DG", rulebase=Rulebase.PRE)
    )
    snapshot = _snapshot(
        [rule],
        device_groups={"DG": DeviceGroup(name="DG", devices=["S1", "S2"])},
        devices=[
            ManagedDevice(serial="S1", hostname="fw1", device_group="DG"),
            ManagedDevice(serial="S2", hostname="fw2", device_group="DG"),
        ],
    )
    counters = dict(
        [
            _device_counter("S1", "allow-web", hit_count=10, last_hit=datetime(2026, 7, 1)),
            _device_counter("S2", "allow-web", hit_count=5, last_hit=datetime(2026, 7, 20)),
        ]
    )

    assert hitcount._apply(snapshot.rules, counters, snapshot) == 1
    assert rule.hits is not None
    assert rule.hits.hit_count == 15
    assert rule.hits.last_hit == datetime(2026, 7, 20)
    # Breakdown kept, newest first.
    assert [d.device for d in rule.hits.per_device] == ["fw2", "fw1"]


def test_parent_device_group_rule_reaches_child_firewalls():
    """A pre-rule in a parent DG is pushed to firewalls in child DGs too."""
    rule = SecurityRule(
        name="allow-dns", location=Location(source="t", device_group="parent", rulebase=Rulebase.PRE)
    )
    snapshot = _snapshot(
        [rule],
        device_groups={
            "parent": DeviceGroup(name="parent", devices=["SP"]),
            "child": DeviceGroup(name="child", parent="parent", devices=["SC"]),
        },
        devices=[
            ManagedDevice(serial="SP", hostname="fw-parent", device_group="parent"),
            ManagedDevice(serial="SC", hostname="fw-child", device_group="child"),
        ],
    )
    counters = dict(
        [
            _device_counter("SP", "allow-dns", hit_count=1, last_hit=datetime(2026, 7, 1)),
            _device_counter("SC", "allow-dns", hit_count=2, last_hit=datetime(2026, 7, 2)),
        ]
    )

    hitcount._apply(snapshot.rules, counters, snapshot)
    assert rule.hits is not None and rule.hits.hit_count == 3
    assert {d.device for d in rule.hits.per_device} == {"fw-parent", "fw-child"}


def test_local_rule_takes_its_own_firewalls_counter():
    rule = SecurityRule(
        name="local-only",
        location=Location(source="t", device="fw3", vsys="vsys1", rulebase=Rulebase.LOCAL),
    )
    snapshot = _snapshot(
        [rule], devices=[ManagedDevice(serial="S3", hostname="fw3", device_group="DG")]
    )
    counters = dict([_device_counter("S3", "local-only", hit_count=7, last_hit=datetime(2026, 7, 3))])

    assert hitcount._apply(snapshot.rules, counters, snapshot) == 1
    assert rule.hits is not None and rule.hits.hit_count == 7


def test_device_group_rule_with_no_collected_firewalls_stays_unmatched():
    rule = SecurityRule(
        name="allow-web", location=Location(source="t", device_group="DG", rulebase=Rulebase.PRE)
    )
    snapshot = _snapshot(
        [rule],
        device_groups={"DG": DeviceGroup(name="DG", devices=["S1"])},
        devices=[ManagedDevice(serial="S1", hostname="fw1", device_group="DG")],
    )
    # A counter for a different rule name only.
    counters = dict([_device_counter("S1", "something-else", hit_count=3)])
    assert hitcount._apply(snapshot.rules, counters, snapshot) == 0
    assert rule.hits is None


# ---------------------------------------------------------------------------
# Panorama: collection proxies to each managed firewall via target
# ---------------------------------------------------------------------------

_SYSTEM_INFO_PANORAMA = (
    '<response status="success"><result><system><model>Panorama</model>'
    "</system></result></response>"
)
_DEVICES_CONNECTED = (
    '<response status="success"><result><devices>'
    '<entry name="S1"><serial>S1</serial><hostname>fw1</hostname><connected>yes</connected>'
    '<vsys><entry name="vsys1"/></vsys></entry>'
    '<entry name="S2"><serial>S2</serial><hostname>fw2</hostname><connected>yes</connected>'
    '<vsys><entry name="vsys1"/></vsys></entry>'
    "</devices></result></response>"
)


def _rule_hits_response(hit_count: int) -> str:
    return (
        '<response status="success"><result><rule-hit-count><vsys><entry name="vsys1">'
        '<rule-base><entry name="security"><rules>'
        f'<entry name="allow-web"><hit-count>{hit_count}</hit-count>'
        "<last-hit-timestamp>1780000000</last-hit-timestamp></entry>"
        "</rules></entry></rule-base></entry></vsys></rule-hit-count></result></response>"
    )


class _PanoramaSession:
    """Answers the sequence of op commands a Panorama collection issues."""

    def post(self, url, data=None, timeout=None, verify=None):
        cmd = (data or {}).get("cmd", "")
        target = (data or {}).get("target")
        if "system><info" in cmd:
            body = _SYSTEM_INFO_PANORAMA
        elif "devices><connected" in cmd:
            body = _DEVICES_CONNECTED
        elif "rule-hit-count" in cmd:
            body = _rule_hits_response(10 if target == "S1" else 0)
        else:
            body = '<response status="success"><result/></response>'

        class _Response:
            status_code = 200
            content = body.encode("utf-8")

        return _Response()


def test_collect_queries_each_firewall_through_panorama(monkeypatch):
    monkeypatch.setenv("PAN_API_KEY", "secret")
    monkeypatch.setattr(hitcount, "_session", lambda config: _PanoramaSession())

    counters = hitcount.collect(HitCountConfig(enabled=True, devices=["panorama.example.com"]))

    assert counters[f"{hitcount._DEVICE_KEY_PREFIX}S1{hitcount._SEP}allow-web"].hit_count == 10
    assert counters[f"{hitcount._DEVICE_KEY_PREFIX}S2{hitcount._SEP}allow-web"].hit_count == 0


def test_collect_rule_hit_command_is_read_only(monkeypatch):
    """Even proxied through Panorama, only 'show' commands may be sent."""
    monkeypatch.setenv("PAN_API_KEY", "secret")
    sent: list[str] = []

    class _Recorder(_PanoramaSession):
        def post(self, url, data=None, timeout=None, verify=None):
            sent.append((data or {}).get("cmd", ""))
            return super().post(url, data=data, timeout=timeout, verify=verify)

    monkeypatch.setattr(hitcount, "_session", lambda config: _Recorder())
    hitcount.collect(HitCountConfig(enabled=True, devices=["panorama.example.com"]))

    assert sent, "expected commands to be issued"
    assert all(cmd.startswith("<show>") for cmd in sent)


def test_collect_reports_progress(monkeypatch):
    monkeypatch.setenv("PAN_API_KEY", "secret")
    monkeypatch.setattr(hitcount, "_session", lambda config: _PanoramaSession())

    messages: list[str] = []
    hitcount.collect(
        HitCountConfig(enabled=True, devices=["panorama.example.com"]), progress=messages.append
    )

    assert any("collecting hit counts" in m for m in messages)
    assert any("S1" in m for m in messages)

