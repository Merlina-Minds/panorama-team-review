"""CLI behaviour, including the exit codes cron depends on."""

from __future__ import annotations

import gzip
import json
from datetime import datetime
from pathlib import Path

import pytest
from click.testing import CliRunner

from panorama_team_review.cli import EXIT_CONFIG, EXIT_NO_BACKUP, EXIT_OK, Context, main
from panorama_team_review.config import Config, OutputConfig

# What the cross-team overview is called, taken from the configuration rather
# than repeated here: the name is deliberately distinct so it does not vanish
# among a hundred team reports, and a test hard-coding it drifts the moment it
# is made more distinct again.
OVERVIEW_MARK = OutputConfig().combined_filename_template.format(date="").strip("_")


def _report_text(path: Path) -> str:
    """The decompressed text of a gzipped ``.json.gz`` report."""
    return gzip.decompress(path.read_bytes()).decode("utf-8")


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def estate(tmp_path: Path, panorama_xml: str) -> Path:
    """A complete working directory: backups, inventory and configuration."""
    backups = tmp_path / "backups"
    backups.mkdir()
    (backups / "2026-07-28-panorama.xml").write_text(panorama_xml, encoding="utf-8")

    (tmp_path / "inventory.yaml").write_text(
        """
teams:
  - id: platform
    name: Platform Services
    contact: platform@example.com
    assets:
      - cidr: 10.10.0.0/16
        label: Management network
    tags: [owner:platform]
  - id: payments
    name: Payments Platform
    assets: ["10.20.0.0/16"]
""",
        encoding="utf-8",
    )

    (tmp_path / "config.yaml").write_text(
        """
input:
  backup_dir: ./backups
teams_file: inventory.yaml
output:
  directory: ./reports
  formats: [json]
  timestamped_subdir: false
report:
  title: "Test Review"
""",
        encoding="utf-8",
    )
    return tmp_path


# ---------------------------------------------------------------------------
# validate
# ---------------------------------------------------------------------------


def test_validate_accepts_a_good_configuration(runner, estate):
    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "validate"])
    assert result.exit_code == EXIT_OK
    assert "Configuration is valid" in result.output
    assert "2 teams" in result.output


def test_validate_reports_a_missing_backup_directory(runner, tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("input:\n  backup_dir: /nonexistent/path\n", encoding="utf-8")
    result = runner.invoke(main, ["-c", str(config), "validate"])
    assert result.exit_code == EXIT_CONFIG
    assert "does not exist" in result.output


def test_validate_reports_an_unknown_check(runner, tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text(
        "analysis:\n  enabled_checks: [ANY_ANY, MADE_UP_CHECK]\n", encoding="utf-8"
    )
    result = runner.invoke(main, ["-c", str(config), "validate"])
    assert result.exit_code == EXIT_CONFIG
    assert "MADE_UP_CHECK" in result.output


def test_validate_warns_about_an_unusable_team(runner, tmp_path):
    """A team with no matching criteria can never receive a rule."""
    (tmp_path / "inventory.yaml").write_text(
        "teams:\n  - id: ghost\n    name: Ghost Team\n", encoding="utf-8"
    )
    config = tmp_path / "config.yaml"
    config.write_text("teams_file: inventory.yaml\n", encoding="utf-8")
    result = runner.invoke(main, ["-c", str(config), "validate"])
    assert result.exit_code == EXIT_CONFIG
    assert "no rule can ever be attributed" in result.output


def test_validate_states_that_hit_counts_are_off(runner, estate):
    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "validate"])
    assert "fully offline" in result.output


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def test_run_produces_reports(runner, estate):
    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "run"])
    assert result.exit_code == EXIT_OK
    written = sorted(p.name for p in (estate / "reports").glob("*.json.gz"))
    assert any("platform" in name for name in written)
    assert any(OVERVIEW_MARK in name for name in written)


def test_run_with_an_explicit_backup(runner, estate, panorama_file):
    result = runner.invoke(
        main, ["-c", str(estate / "config.yaml"), "run", "--backup", str(panorama_file)]
    )
    assert result.exit_code == EXIT_OK


def test_run_without_any_backup_source_exits_three(runner, tmp_path):
    """Exit code 3 lets monitoring tell 'backup job broken' from 'tool broken'."""
    config = tmp_path / "config.yaml"
    config.write_text("output:\n  formats: [json]\n", encoding="utf-8")
    result = runner.invoke(main, ["-c", str(config), "run"])
    assert result.exit_code == EXIT_NO_BACKUP
    assert "no backup specified" in result.output


def test_run_with_an_empty_backup_directory_exits_three(runner, tmp_path):
    (tmp_path / "backups").mkdir()
    config = tmp_path / "config.yaml"
    config.write_text("input:\n  backup_dir: ./backups\n", encoding="utf-8")
    result = runner.invoke(main, ["-c", str(config), "run"])
    assert result.exit_code == EXIT_NO_BACKUP


def test_run_quiet_prints_nothing_on_success(runner, estate):
    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "-q", "run"])
    assert result.exit_code == EXIT_OK
    assert result.output.strip() == ""


def test_run_format_override(runner, estate):
    result = runner.invoke(
        main, ["-c", str(estate / "config.yaml"), "run", "-f", "html"]
    )
    assert result.exit_code == EXIT_OK
    assert list((estate / "reports").glob("*.html"))
    assert not list((estate / "reports").glob("*.json.gz"))


def test_run_writes_an_html_index(runner, estate):
    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "run", "-f", "html"])
    assert result.exit_code == EXIT_OK
    index = estate / "reports" / "index.html"
    assert index.is_file()
    body = index.read_text(encoding="utf-8")
    assert 'platform_firewall-review.html"' in body
    assert 'payments_firewall-review.html"' in body
    assert f'{OVERVIEW_MARK}.html"' in body


def test_run_without_html_writes_no_index(runner, estate):
    """The index is a table of contents for the HTML reports; JSON-only has none."""
    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "run"])
    assert result.exit_code == EXIT_OK
    assert not (estate / "reports" / "index.html").exists()


def test_run_output_override(runner, estate, tmp_path):
    target = tmp_path / "elsewhere"
    result = runner.invoke(
        main, ["-c", str(estate / "config.yaml"), "run", "-o", str(target)]
    )
    assert result.exit_code == EXIT_OK
    assert list(target.glob("*.json.gz"))


def test_run_team_filter(runner, estate):
    result = runner.invoke(
        main, ["-c", str(estate / "config.yaml"), "run", "--team", "platform"]
    )
    assert result.exit_code == EXIT_OK
    names = [p.name for p in (estate / "reports").glob("*.json.gz")]
    assert not any("payments" in name for name in names)


def test_run_sample_limits_the_number_of_team_reports(runner, estate):
    result = runner.invoke(
        main, ["-c", str(estate / "config.yaml"), "run", "--sample", "1"]
    )
    assert result.exit_code == EXIT_OK
    team_reports = [
        p for p in (estate / "reports").glob("*.json.gz") if OVERVIEW_MARK not in p.name
    ]
    assert len(team_reports) == 1
    assert "Sampling 1 of" in result.output


def test_run_sample_leaves_the_overview_complete(runner, estate):
    """Sampling limits the files written, not the analysis behind them."""
    result = runner.invoke(
        main, ["-c", str(estate / "config.yaml"), "run", "--sample", "1"]
    )
    assert result.exit_code == EXIT_OK
    overview = next((estate / "reports").glob(f"*{OVERVIEW_MARK}*.json.gz"))
    assert len(json.loads(_report_text(overview))["teams"]) == 2


def test_sample_prefers_teams_that_have_rules_to_review():
    """A report saying "nothing touches your systems" proves nothing about the run."""
    from panorama_team_review.cli import _sample_teams
    from panorama_team_review.model import Location, RuleView, SecurityRule, Team, TeamReport

    def report(team_id: str, own: int, covered: int) -> TeamReport:
        location = Location(source="x")
        return TeamReport(
            team=Team(id=team_id, name=team_id),
            inbound=[
                RuleView(
                    rule=SecurityRule(name=f"{team_id}-{i}", location=location),
                    direction="inbound",
                    coverage="own" if i < own else "covered",
                )
                for i in range(own + covered)
            ],
        )

    empty = [report(f"empty-{i}", 0, 0) for i in range(20)]
    real = [report("alpha", 40, 5), report("beta", 9, 5), report("gamma", 1, 5)]
    picked = _sample_teams([*empty, *real], 3)
    assert {r.team.id for r in picked} == {"alpha", "beta", "gamma"}


def test_sample_does_not_fill_up_with_one_naming_family():
    """The real complaint: an estate where a convention produced 'nonstandard-*'."""
    from panorama_team_review.cli import _sample_teams
    from panorama_team_review.model import Location, RuleView, SecurityRule, Team, TeamReport

    def report(team_id: str, rules: int) -> TeamReport:
        location = Location(source="x")
        return TeamReport(
            team=Team(id=team_id, name=team_id),
            inbound=[
                RuleView(
                    rule=SecurityRule(name=f"{team_id}-{i}", location=location),
                    direction="inbound",
                )
                for i in range(rules)
            ],
        )

    # The nonstandard family is both the largest and the most numerous, so a
    # naive sample would be nothing else.
    crowd = [report(f"nonstandard-{i}", 100 - i) for i in range(30)]
    others = [report(f"real-{i}", 40 - i) for i in range(10)]
    picked = _sample_teams([*crowd, *others], 6)

    families = [r.team.id.split("-", 1)[0] for r in picked]
    assert families.count("nonstandard") <= 3, families
    assert families.count("real") >= 3, families


def test_sample_is_deterministic():
    from panorama_team_review.cli import _sample_teams
    from panorama_team_review.model import Location, RuleView, SecurityRule, Team, TeamReport

    reports = [
        TeamReport(
            team=Team(id=f"t{i}", name=f"t{i}"),
            inbound=[
                RuleView(
                    rule=SecurityRule(name=f"r{i}-{j}", location=Location(source="x")),
                    direction="inbound",
                )
                for j in range(i + 1)
            ],
        )
        for i in range(25)
    ]
    first = [r.team.id for r in _sample_teams(reports, 5)]
    second = [r.team.id for r in _sample_teams(list(reversed(reports)), 5)]
    assert first == second


def test_run_unknown_team_filter_exits_config(runner, estate):
    result = runner.invoke(
        main, ["-c", str(estate / "config.yaml"), "run", "--team", "nope"]
    )
    assert result.exit_code == EXIT_CONFIG
    assert "unknown team ids" in result.output


def test_run_as_of_changes_expiry_evaluation(runner, estate):
    """--as-of makes the report reproducible for a past review date."""
    runner.invoke(
        main, ["-c", str(estate / "config.yaml"), "run", "--as-of", "2020-01-01"]
    )
    overview = next((estate / "reports").glob(f"*{OVERVIEW_MARK}*.json.gz"))
    data = json.loads(_report_text(overview))
    assert data["stats"].get("check_EXPIRED_RULE", 0) == 0


def test_run_creates_a_timestamped_directory(runner, estate):
    config = estate / "config.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "timestamped_subdir: false", "timestamped_subdir: true"
        ),
        encoding="utf-8",
    )
    result = runner.invoke(main, ["-c", str(config), "run"])
    assert result.exit_code == EXIT_OK
    subdirs = [p for p in (estate / "reports").iterdir() if p.is_dir()]
    assert len(subdirs) == 1
    assert list(subdirs[0].glob("*.json.gz"))


def test_run_timestamped_subdir_format_can_include_a_time(runner, estate):
    """A format with a time keeps several runs on the same day apart."""
    config = estate / "config.yaml"
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "timestamped_subdir: false",
            'timestamped_subdir: true\n  timestamped_subdir_format: "%Y-%m-%d_%H-%M-%S"',
        ),
        encoding="utf-8",
    )
    result = runner.invoke(main, ["-c", str(config), "run"])
    assert result.exit_code == EXIT_OK, result.output
    subdirs = [p for p in (estate / "reports").iterdir() if p.is_dir()]
    assert len(subdirs) == 1
    datetime.strptime(subdirs[0].name, "%Y-%m-%d_%H-%M-%S")


def test_run_without_teams_warns(runner, tmp_path, panorama_xml):
    backups = tmp_path / "backups"
    backups.mkdir()
    (backups / "c.xml").write_text(panorama_xml, encoding="utf-8")
    config = tmp_path / "config.yaml"
    config.write_text(
        "input:\n  backup_dir: ./backups\noutput:\n  directory: ./out\n"
        "  formats: [json]\n  timestamped_subdir: false\n",
        encoding="utf-8",
    )
    result = runner.invoke(main, ["-c", str(config), "run"])
    assert result.exit_code == EXIT_OK
    assert "no teams configured" in result.output


# ---------------------------------------------------------------------------
# inspect, checks, init
# ---------------------------------------------------------------------------


def test_inspect_summarises_a_backup(runner, estate):
    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "inspect"])
    assert result.exit_code == EXIT_OK
    assert "security rules" in result.output
    assert "Device groups:" in result.output


def test_checks_lists_the_available_codes(runner):
    result = runner.invoke(main, ["checks"])
    assert result.exit_code == EXIT_OK
    assert "ANY_ANY" in result.output
    assert "UNUSED_RULE" in result.output


def test_init_writes_example_files(runner, tmp_path):
    result = runner.invoke(main, ["init", str(tmp_path)])
    assert result.exit_code == EXIT_OK
    assert (tmp_path / "config.yaml").is_file()
    assert (tmp_path / "inventory.yaml").is_file()


def test_init_does_not_overwrite_without_force(runner, tmp_path):
    (tmp_path / "config.yaml").write_text("mine: true", encoding="utf-8")
    runner.invoke(main, ["init", str(tmp_path)])
    assert (tmp_path / "config.yaml").read_text(encoding="utf-8") == "mine: true"


def test_generated_example_config_is_valid(runner, tmp_path):
    """The shipped example must itself pass validation, minus the paths."""
    runner.invoke(main, ["init", str(tmp_path)])
    from panorama_team_review.config import load_config

    config = load_config(tmp_path / "config.yaml")
    assert config.report.title
    assert "html" in config.output.formats


def test_generated_example_inventory_is_valid(runner, tmp_path):
    runner.invoke(main, ["init", str(tmp_path)])
    from panorama_team_review.resolve.inventory import load_inventory

    teams = load_inventory(tmp_path / "inventory.yaml")
    assert len(teams) >= 3
    assert all(team.id for team in teams)


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


def test_diff_reports_no_change_for_identical_input(runner, estate):
    runner.invoke(main, ["-c", str(estate / "config.yaml"), "run"])
    overview = next((estate / "reports").glob(f"*{OVERVIEW_MARK}*.json.gz"))
    result = runner.invoke(main, ["diff", str(overview), str(overview)])
    assert result.exit_code == EXIT_OK
    assert "No rule changes" in result.output


def test_diff_detects_changes(runner, estate, panorama_xml, tmp_path):
    from lxml import etree

    runner.invoke(main, ["-c", str(estate / "config.yaml"), "run"])
    first = next((estate / "reports").glob(f"*{OVERVIEW_MARK}*.json.gz"))
    baseline = tmp_path / "baseline.json.gz"
    baseline.write_bytes(first.read_bytes())

    tree = etree.fromstring(panorama_xml.encode("utf-8"))
    rule = tree.find(".//device-group/entry/pre-rulebase/security/rules/entry")
    rule.find("action").text = "deny"
    modified = estate / "backups" / "2026-07-29-panorama.xml"
    modified.write_bytes(etree.tostring(tree))

    runner.invoke(main, ["-c", str(estate / "config.yaml"), "run", "--backup", str(modified)])
    second = next((estate / "reports").glob(f"*{OVERVIEW_MARK}*.json.gz"))

    result = runner.invoke(main, ["diff", str(baseline), str(second)])
    assert result.exit_code == EXIT_OK
    assert "Changed" in result.output
    assert "action" in result.output


def test_diff_json_output(runner, estate):
    runner.invoke(main, ["-c", str(estate / "config.yaml"), "run"])
    overview = next((estate / "reports").glob(f"*{OVERVIEW_MARK}*.json.gz"))
    result = runner.invoke(main, ["diff", str(overview), str(overview), "--json"])
    data = json.loads(result.output)
    assert data["summary"] == {"added": 0, "removed": 0, "changed": 0}


def test_diff_rejects_a_non_report_file(runner, tmp_path):
    bad = tmp_path / "not-a-report.json"
    bad.write_text('{"hello": "world"}', encoding="utf-8")
    result = runner.invoke(main, ["diff", str(bad), str(bad)])
    assert result.exit_code != EXIT_OK
    assert "does not look like a report" in result.output


# ---------------------------------------------------------------------------
# scrub
# ---------------------------------------------------------------------------


def test_scrub_writes_a_pseudonymised_file(runner, panorama_file, tmp_path):
    target = tmp_path / "scrubbed.xml"
    result = runner.invoke(
        main, ["scrub", str(panorama_file), str(target), "--salt", "s"]
    )
    assert result.exit_code == EXIT_OK
    assert target.is_file()
    assert "pseudonymised, not anonymised" in result.output


def test_scrub_refuses_to_overwrite_without_force(runner, panorama_file, tmp_path):
    target = tmp_path / "existing.xml"
    target.write_text("keep me", encoding="utf-8")
    result = runner.invoke(main, ["scrub", str(panorama_file), str(target)])
    assert result.exit_code != EXIT_OK
    assert target.read_text(encoding="utf-8") == "keep me"


# ---------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------


def test_version_is_reported(runner):
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == EXIT_OK
    assert "0.1.0" in result.output


def test_invalid_yaml_exits_config(runner, tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("input: [unclosed\n", encoding="utf-8")
    result = runner.invoke(main, ["-c", str(config), "validate"])
    assert result.exit_code == EXIT_CONFIG
    assert "invalid YAML" in result.output


def test_unknown_config_key_is_rejected(runner, tmp_path):
    """extra=forbid: a typo must fail loudly, not be silently ignored."""
    config = tmp_path / "config.yaml"
    config.write_text("outputt:\n  formats: [json]\n", encoding="utf-8")
    result = runner.invoke(main, ["-c", str(config), "validate"])
    assert result.exit_code == EXIT_CONFIG


def test_missing_config_file_exits_config(runner, tmp_path):
    result = runner.invoke(main, ["-c", str(tmp_path / "nope.yaml"), "validate"])
    assert result.exit_code == EXIT_CONFIG
    assert "not found" in result.output


def test_collect_hitcounts_refuses_when_disabled(runner, estate):
    """The network-facing command must never run by accident."""
    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "collect-hitcounts"])
    assert result.exit_code == EXIT_CONFIG
    assert "disabled" in result.output


def test_fetch_backup_refuses_when_disabled(runner, estate):
    """The network-facing command must never run by accident."""
    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "fetch-backup"])
    assert result.exit_code == EXIT_CONFIG
    assert "disabled" in result.output


def test_validate_flags_a_missing_credential_file(runner, estate):
    """A password/key file named in the config but missing is caught offline."""
    (estate / "config.yaml").write_text(
        "input:\n"
        "  backup_dir: ./backups\n"
        "  fetch:\n"
        "    enabled: true\n"
        "teams_file: inventory.yaml\n"
        "hitcounts:\n"
        "  devices: [fw.example.com]\n"
        "  username: readonly-api\n"
        "  password_file: ./nope.pass\n"
        "output:\n"
        "  directory: ./reports\n"
        "  formats: [json]\n"
        "  timestamped_subdir: false\n",
        encoding="utf-8",
    )
    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "validate"])
    assert result.exit_code == EXIT_CONFIG
    assert "password_file does not exist" in result.output
    assert "Credentials:" in result.output


def test_fetch_cert_writes_a_bundle(runner, estate, tmp_path, monkeypatch):
    from panorama_team_review import panos_api

    monkeypatch.setattr(
        panos_api,
        "fetch_certificate",
        lambda host, port=443, timeout=30: (f"PEM-{host}\n", "AA:BB:CC"),
    )
    out = tmp_path / "ca.pem"
    result = runner.invoke(
        main,
        ["-c", str(estate / "config.yaml"), "fetch-cert",
         "fw1.example.com", "fw2.example.com", "-o", str(out)],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert out.read_text(encoding="utf-8") == "PEM-fw1.example.com\nPEM-fw2.example.com\n"
    assert "AA:BB:CC" in result.output


def test_fetch_cert_needs_devices(runner, estate):
    """Without hosts and without hitcounts.devices there is nothing to fetch."""
    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "fetch-cert"])
    assert result.exit_code == EXIT_CONFIG


def test_progress_is_shown_only_in_a_terminal(capsys):
    """Cron (no TTY) must stay quiet; a terminal gets live progress on stderr."""
    ctx = Context(Config(), None, quiet=False, verbose=False)
    assert ctx.interactive is False  # pytest's captured stderr is not a TTY

    ctx.step("working…")
    assert "working" not in capsys.readouterr().err

    ctx.interactive = True
    ctx.step("working…")
    assert "working" in capsys.readouterr().err


def test_quiet_disables_progress_even_in_a_terminal(monkeypatch):
    class _FakeTTY:
        def isatty(self):
            return True

        def write(self, *args):
            pass

        def flush(self):
            pass

    monkeypatch.setattr("sys.stderr", _FakeTTY())
    assert Context(Config(), None, quiet=False, verbose=False).interactive is True
    assert Context(Config(), None, quiet=True, verbose=False).interactive is False


def test_fetch_backup_writes_into_the_backup_directory(runner, estate, firewall_xml, monkeypatch):
    from panorama_team_review import panos_api

    monkeypatch.setenv("PAN_API_KEY", "secret")
    monkeypatch.setattr(panos_api, "open_session", lambda conn: object())
    monkeypatch.setattr(
        panos_api, "export_configuration", lambda *a, **k: firewall_xml.encode("utf-8")
    )

    (estate / "config.yaml").write_text(
        "input:\n"
        "  backup_dir: ./backups\n"
        "  fetch:\n"
        "    enabled: true\n"
        "teams_file: inventory.yaml\n"
        "hitcounts:\n"
        "  devices: [panorama.example.com]\n"
        "output:\n"
        "  directory: ./reports\n"
        "  formats: [json]\n"
        "  timestamped_subdir: false\n",
        encoding="utf-8",
    )

    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "fetch-backup"])
    assert result.exit_code == EXIT_OK, result.output
    fetched = list((estate / "backups").glob("panorama.example.com_*.xml"))
    assert fetched, "the fetched configuration should be written into backup_dir"


def test_run_fetches_configuration_when_enabled(runner, estate, firewall_xml, monkeypatch):
    from panorama_team_review import panos_api

    monkeypatch.setenv("PAN_API_KEY", "secret")
    monkeypatch.setattr(panos_api, "open_session", lambda conn: object())
    captured: dict = {}

    def fake_export(session, device, key, conn):
        captured["device"] = device
        return firewall_xml.encode("utf-8")

    monkeypatch.setattr(panos_api, "export_configuration", fake_export)

    (estate / "config.yaml").write_text(
        "input:\n"
        "  backup_dir: ./backups\n"
        "  fetch:\n"
        "    enabled: true\n"
        "teams_file: inventory.yaml\n"
        "hitcounts:\n"
        "  devices: [panorama.example.com]\n"
        "output:\n"
        "  directory: ./reports\n"
        "  formats: [json]\n"
        "  timestamped_subdir: false\n",
        encoding="utf-8",
    )

    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "run"])
    assert result.exit_code == EXIT_OK, result.output
    assert captured["device"] == "panorama.example.com"
    assert list((estate / "backups").glob("panorama.example.com_*.xml"))


def test_run_skips_fetch_with_no_network(runner, estate, monkeypatch):
    """--no-network must force offline operation even with fetch enabled."""
    from panorama_team_review import panos_api

    def explode(*args, **kwargs):
        raise AssertionError("fetch must not run with --no-network")

    monkeypatch.setattr(panos_api, "export_configuration", explode)

    (estate / "config.yaml").write_text(
        "input:\n"
        "  backup_dir: ./backups\n"
        "  fetch:\n"
        "    enabled: true\n"
        "teams_file: inventory.yaml\n"
        "hitcounts:\n"
        "  devices: [panorama.example.com]\n"
        "output:\n"
        "  directory: ./reports\n"
        "  formats: [json]\n"
        "  timestamped_subdir: false\n",
        encoding="utf-8",
    )

    result = runner.invoke(main, ["-c", str(estate / "config.yaml"), "run", "--no-network"])
    assert result.exit_code == EXIT_OK, result.output



# ---------------------------------------------------------------------------
# Multi-tenant operation
# ---------------------------------------------------------------------------


def make_estate(root: Path, name: str, xml: str, network: str) -> Path:
    """Build a self-contained estate directory: backup, inventory, config."""
    backups = root / name / "backups"
    backups.mkdir(parents=True)
    (backups / "config.xml").write_text(xml, encoding="utf-8")
    (root / name / "inventory.yaml").write_text(
        f"teams:\n  - id: platform\n    name: Platform {name}\n"
        f"    assets: ['{network}']\n",
        encoding="utf-8",
    )
    (root / name / "config.yaml").write_text(
        "input:\n  backup_dir: ./backups\nteams_file: inventory.yaml\n"
        "output:\n  directory: ./reports\n  formats: [json]\n"
        "  timestamped_subdir: false\n"
        f'report:\n  title: "Review {name}"\n  organisation: "{name}"\n',
        encoding="utf-8",
    )
    return root / name / "config.yaml"


def test_separate_estates_stay_isolated(runner, tmp_path, panorama_xml, firewall_xml):
    """One configuration file per estate is the multi-tenant model.

    Nothing is shared between runs: no global state, no shared cache path, no
    cross-estate lookups. For anyone running this for several customers, a
    report that mentioned another customer's team would be the worst possible
    failure, so it is asserted rather than assumed.
    """
    first = make_estate(tmp_path, "estate-a", panorama_xml, "10.10.0.0/16")
    second = make_estate(tmp_path, "estate-b", firewall_xml, "10.20.0.0/16")

    assert runner.invoke(main, ["-c", str(first), "run"]).exit_code == EXIT_OK
    assert runner.invoke(main, ["-c", str(second), "run"]).exit_code == EXIT_OK

    a_text = "\n".join(
        _report_text(p) for p in (tmp_path / "estate-a" / "reports").glob("*.json.gz")
    )
    b_text = "\n".join(
        _report_text(p) for p in (tmp_path / "estate-b" / "reports").glob("*.json.gz")
    )

    assert "estate-b" not in a_text
    assert "estate-a" not in b_text
    assert "Platform estate-a" in a_text
    assert "Platform estate-b" in b_text


def test_estate_output_stays_in_its_own_directory(runner, tmp_path, panorama_xml):
    config = make_estate(tmp_path, "estate-a", panorama_xml, "10.10.0.0/16")
    runner.invoke(main, ["-c", str(config), "run"])
    assert list((tmp_path / "estate-a" / "reports").glob("*.json.gz"))
    assert not list(tmp_path.glob("*.json.gz"))


def test_resolver_state_does_not_leak_between_runs(panorama_snapshot, panorama_file):
    """The any/any budget is per run; a stale counter would silently truncate."""
    from panorama_team_review.config import Config
    from panorama_team_review.model import Team
    from panorama_team_review.report.build import build_report

    teams_a = [Team(id="a", name="A", assets=["10.10.0.0/16"])]
    teams_b = [Team(id="b", name="B", assets=["10.10.0.0/16"])]

    from panorama_team_review.parse import panos
    from panorama_team_review.parse.loader import load

    first = build_report(panos.parse(load(panorama_file)[0]), teams_a, Config())
    second = build_report(panos.parse(load(panorama_file)[0]), teams_b, Config())

    assert first.teams[0].rule_count == second.teams[0].rule_count
