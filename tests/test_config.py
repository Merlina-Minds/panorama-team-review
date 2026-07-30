"""Configuration and inventory loading.

Validation is meant to fail immediately and legibly. A typo that produces a
subtly wrong report three minutes later is the failure mode being designed out
here, so the tests are mostly about *rejection* being correct.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from panorama_team_review.config import Config, load_config
from panorama_team_review.errors import ConfigError
from panorama_team_review.resolve.inventory import inventory_warnings, load_inventory


def write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def test_defaults_are_usable_without_a_file():
    config = load_config(None)
    assert config.output.formats
    assert config.ownership.order[0] == "inventory"
    assert config.hitcounts.enabled is False


def test_hit_counts_are_off_by_default():
    """The offline guarantee, asserted."""
    assert Config().hitcounts.enabled is False


def test_minimal_config_loads(tmp_path):
    path = write(tmp_path / "c.yaml", "input:\n  backup_dir: /tmp\n")
    assert load_config(path).input.backup_dir == Path("/tmp")


def test_empty_config_file_loads(tmp_path):
    assert load_config(write(tmp_path / "c.yaml", "")).output.formats


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


def test_invalid_yaml_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(write(tmp_path / "c.yaml", "a: [1,\n"))


def test_non_mapping_top_level_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="must be a mapping"):
        load_config(write(tmp_path / "c.yaml", "- one\n- two\n"))


def test_unknown_key_is_rejected(tmp_path):
    """A silently ignored typo produces a wrong report, so it must fail."""
    with pytest.raises(ConfigError):
        load_config(write(tmp_path / "c.yaml", "unknown_section:\n  a: 1\n"))


def test_error_message_names_the_field(tmp_path):
    path = write(tmp_path / "c.yaml", "output:\n  formats: [not-a-format]\n")
    with pytest.raises(ConfigError) as exc:
        load_config(path)
    assert "output.formats" in str(exc.value)


def test_relative_paths_resolve_against_the_config_file(tmp_path):
    (tmp_path / "backups").mkdir()
    path = write(
        tmp_path / "c.yaml",
        "input:\n  backup_dir: ./backups\nteams_file: ./inv.yaml\n"
        "output:\n  directory: ./out\n",
    )
    config = load_config(path)
    assert config.input.backup_dir == tmp_path / "backups"
    assert config.teams_file == tmp_path / "inv.yaml"
    assert config.output.directory == tmp_path / "out"


def test_absolute_paths_are_left_alone(tmp_path):
    path = write(tmp_path / "c.yaml", "output:\n  directory: /var/reports\n")
    assert load_config(path).output.directory == Path("/var/reports")


def test_environment_variables_are_expanded(tmp_path, monkeypatch):
    monkeypatch.setenv("REPORT_BASE", str(tmp_path))
    path = write(tmp_path / "c.yaml", "output:\n  directory: $REPORT_BASE/out\n")
    assert load_config(path).output.directory == tmp_path / "out"


def test_empty_list_key_is_accepted(tmp_path):
    """Commenting out every entry leaves a null key; that must not fail."""
    path = write(
        tmp_path / "c.yaml",
        "hitcounts:\n  enabled: false\n  devices:\n    # - fw01.example.com\n",
    )
    assert load_config(path).hitcounts.devices == []


def test_shipped_example_config_is_valid():
    example = Path(__file__).resolve().parent.parent / "config" / "config.example.yaml"
    config = load_config(example)
    assert config.report.title
    assert config.hitcounts.enabled is False


def test_invalid_ticket_regex_is_rejected(tmp_path):
    path = write(
        tmp_path / "c.yaml",
        "metadata:\n  ticket_patterns:\n"
        "    - name: broken\n      regex: '(?P<id>[unclosed'\n",
    )
    with pytest.raises(ConfigError):
        load_config(path)


def test_ticket_pattern_without_id_group_is_rejected(tmp_path):
    path = write(
        tmp_path / "c.yaml",
        "metadata:\n  ticket_patterns:\n    - name: bad\n      regex: '\\d+'\n",
    )
    with pytest.raises(ConfigError, match="named group"):
        load_config(path)


def test_ownership_pattern_without_team_group_is_rejected(tmp_path):
    path = write(tmp_path / "c.yaml", "ownership:\n  name_patterns: ['^PAY-']\n")
    with pytest.raises(ConfigError, match="team"):
        load_config(path)


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


def test_inventory_loads(tmp_path):
    path = write(
        tmp_path / "inv.yaml",
        """
teams:
  - id: payments
    name: Payments
    contact: pay@example.com
    assets:
      - cidr: 10.20.0.0/16
        label: Production
      - 10.21.0.0/16
""",
    )
    teams = load_inventory(path)
    assert len(teams) == 1
    assert teams[0].assets == ["10.20.0.0/16", "10.21.0.0/16"]
    assert teams[0].asset_labels == {"10.20.0.0/16": "Production"}


def test_inventory_accepts_a_bare_list(tmp_path):
    path = write(tmp_path / "inv.yaml", "- id: a\n  name: A\n")
    assert load_inventory(path)[0].id == "a"


def test_no_inventory_is_allowed():
    """Tag- and zone-based attribution work without an address inventory."""
    assert load_inventory(None) == []


def test_missing_inventory_file_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_inventory(tmp_path / "nope.yaml")


def test_invalid_cidr_is_rejected(tmp_path):
    path = write(tmp_path / "inv.yaml", "teams:\n  - id: a\n    assets: ['10.0.0.0/99']\n")
    with pytest.raises(ConfigError, match="valid IP network"):
        load_inventory(path)


def test_host_address_without_prefix_is_normalised(tmp_path):
    path = write(tmp_path / "inv.yaml", "teams:\n  - id: a\n    assets: ['10.1.2.3']\n")
    assert load_inventory(path)[0].assets == ["10.1.2.3/32"]


def test_non_canonical_network_is_normalised(tmp_path):
    """10.1.2.3/24 is what people actually write; accept and correct it."""
    path = write(tmp_path / "inv.yaml", "teams:\n  - id: a\n    assets: ['10.1.2.3/24']\n")
    assert load_inventory(path)[0].assets == ["10.1.2.0/24"]


def test_duplicate_team_ids_are_rejected(tmp_path):
    path = write(tmp_path / "inv.yaml", "teams:\n  - id: a\n  - id: a\n")
    with pytest.raises(ConfigError, match="duplicate team ids"):
        load_inventory(path)


def test_unknown_team_key_is_rejected(tmp_path):
    path = write(tmp_path / "inv.yaml", "teams:\n  - id: a\n    contacts: x@example.com\n")
    with pytest.raises(ConfigError):
        load_inventory(path)


def test_name_defaults_to_the_id(tmp_path):
    path = write(tmp_path / "inv.yaml", "teams:\n  - id: payments\n")
    assert load_inventory(path)[0].name == "payments"


def test_overlapping_assets_are_reported_not_rejected(tmp_path):
    """A shared management network genuinely belongs to several teams."""
    path = write(
        tmp_path / "inv.yaml",
        "teams:\n  - id: a\n    assets: ['10.0.0.0/8']\n"
        "  - id: b\n    assets: ['10.1.0.0/16']\n",
    )
    teams = load_inventory(path)
    assert len(teams) == 2
    warnings = inventory_warnings(teams)
    assert any("overlaps" in warning for warning in warnings)


def test_non_overlapping_assets_produce_no_warning(tmp_path):
    path = write(
        tmp_path / "inv.yaml",
        "teams:\n  - id: a\n    assets: ['10.1.0.0/16']\n"
        "  - id: b\n    assets: ['10.2.0.0/16']\n",
    )
    assert inventory_warnings(load_inventory(path)) == []


def test_ipv6_assets_load(tmp_path):
    path = write(tmp_path / "inv.yaml", "teams:\n  - id: a\n    assets: ['2001:db8::/32']\n")
    assert load_inventory(path)[0].assets == ["2001:db8::/32"]


def test_shipped_example_inventory_is_valid():
    example = Path(__file__).resolve().parent.parent / "config" / "inventory.example.yaml"
    teams = load_inventory(example)
    assert len(teams) >= 3
    assert all(team.id and team.name for team in teams)


# ---------------------------------------------------------------------------
# Scale
# ---------------------------------------------------------------------------


def test_large_inventory_loads_quickly(tmp_path):
    """A generated inventory can hold tens of thousands of networks.

    Regression test for a pairwise overlap check that was O(n^2): on a real
    inventory of 11 500 networks it took over two minutes, so most of a run was
    spent building a warning list. The bound is deliberately loose -- this
    catches a return to quadratic behaviour, not a small slowdown.
    """
    import time

    lines = ["teams:"]
    for team in range(200):
        lines.append(f"  - id: team-{team}")
        lines.append("    assets:")
        for net in range(50):
            lines.append(f"      - 10.{team % 250}.{net}.0/24")
    write(tmp_path / "big.yaml", "\n".join(lines))

    start = time.monotonic()
    teams = load_inventory(tmp_path / "big.yaml")
    elapsed = time.monotonic() - start

    assert len(teams) == 200
    assert elapsed < 15, f"loading 10 000 networks took {elapsed:.1f}s"


def test_overlap_warnings_are_capped(tmp_path):
    """Thousands of near-identical warnings are the same as none."""
    lines = ["teams:"]
    for team in range(60):
        lines.append(f"  - id: team-{team}")
        lines.append("    assets: ['10.1.0.0/16']")   # all overlap each other
    write(tmp_path / "overlap.yaml", "\n".join(lines))

    warnings = inventory_warnings(load_inventory(tmp_path / "overlap.yaml"))
    assert len(warnings) <= 51
    assert any("further asset overlaps" in warning for warning in warnings)


def test_a_contested_tag_is_reported():
    """A tag mapping to one team means a shared tag silently picks a winner."""
    from panorama_team_review.model import Team
    from panorama_team_review.resolve.inventory import inventory_warnings

    teams = [
        Team(id="alpha", name="Alpha", tags=["shared-classification"]),
        Team(id="beta", name="Beta", tags=["shared-classification"]),
        Team(id="gamma", name="Gamma", tags=["owner:gamma"]),
    ]
    warnings = [w for w in inventory_warnings(teams) if "claimed by" in w]
    assert len(warnings) == 1
    assert "shared-classification" in warnings[0]
    assert "alpha" in warnings[0] and "beta" in warnings[0]
    assert "classification tag" in warnings[0]


def test_an_uncontested_tag_is_not_reported():
    from panorama_team_review.model import Team
    from panorama_team_review.resolve.inventory import inventory_warnings

    teams = [Team(id="alpha", name="Alpha", tags=["owner:alpha"])]
    assert [w for w in inventory_warnings(teams) if "claimed by" in w] == []
