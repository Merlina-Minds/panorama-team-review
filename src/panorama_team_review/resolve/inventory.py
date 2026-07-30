"""Loading the team / asset inventory.

The inventory is the one piece of knowledge the firewall configuration cannot
supply: which network belongs to which team.  It is deliberately a separate
file so it can be generated from a CMDB and kept under different access control
than the tool's configuration.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

from ..errors import ConfigError
from ..model import Team


class AssetEntry(BaseModel):
    """One network or host owned by a team."""

    cidr: str
    label: str = ""
    description: str = ""

    @field_validator("cidr")
    @classmethod
    def _valid_network(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"{value!r} is not a valid IP network: {exc}") from exc


class TeamEntry(BaseModel):
    """A team as written in the inventory file."""

    id: str
    name: str = ""
    contact: str | None = None
    description: str = ""
    assets: list[AssetEntry] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    device_groups: list[str] = Field(default_factory=list)
    zones: list[str] = Field(default_factory=list)
    name_patterns: list[str] = Field(default_factory=list)

    model_config = {"extra": "forbid"}

    @field_validator("assets", mode="before")
    @classmethod
    def _accept_bare_strings(cls, value: Any) -> Any:
        """Allow the short form ``assets: ["10.0.0.0/8"]`` alongside the full form."""
        if isinstance(value, list):
            return [{"cidr": item} if isinstance(item, str) else item for item in value]
        return value

    def to_team(self) -> Team:
        return Team(
            id=self.id,
            name=self.name or self.id,
            contact=self.contact,
            description=self.description,
            assets=[asset.cidr for asset in self.assets],
            asset_labels={asset.cidr: asset.label for asset in self.assets if asset.label},
            tags=self.tags,
            device_groups=self.device_groups,
            zones=self.zones,
            name_patterns=self.name_patterns,
        )


class Inventory(BaseModel):
    teams: list[TeamEntry] = Field(default_factory=list)

    model_config = {"extra": "forbid"}


def load_inventory(path: Path | None) -> list[Team]:
    """Load and validate the inventory, returning an empty list if unconfigured.

    Running without an inventory is legitimate: tag-, zone- and device-group
    based attribution work on their own, and it is a reasonable first step
    before an estate has mapped its networks to owners.
    """
    if path is None:
        return []
    if not path.is_file():
        raise ConfigError(f"inventory file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc

    # Accept both a bare list of teams and a mapping with a 'teams' key.
    if isinstance(raw, list):
        raw = {"teams": raw}
    if not isinstance(raw, dict):
        raise ConfigError(f"{path}: expected a mapping or a list of teams")

    try:
        inventory = Inventory.model_validate(raw)
    except ValidationError as exc:
        lines = [
            f"  {'.'.join(str(p) for p in err.get('loc', ()))}: {err.get('msg', '')}"
            for err in exc.errors()
        ]
        raise ConfigError(f"{path}: inventory is invalid:\n" + "\n".join(lines)) from exc

    teams = [entry.to_team() for entry in inventory.teams]
    _check_unique_ids(teams, path)
    _warn_overlapping_assets(teams)
    return teams


def _check_unique_ids(teams: list[Team], path: Path) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for team in teams:
        if team.id in seen:
            duplicates.add(team.id)
        seen.add(team.id)
    if duplicates:
        raise ConfigError(f"{path}: duplicate team ids: {', '.join(sorted(duplicates))}")


# Reporting every overlap in a large generated inventory produces thousands of
# near-identical lines nobody reads. The cap keeps the signal.
MAX_OVERLAP_WARNINGS = 50


def _warn_overlapping_assets(teams: list[Team]) -> list[str]:
    """Report assets claimed by more than one team.

    Overlap is not an error -- a shared management network genuinely belongs to
    several teams -- but it is worth surfacing, because it is just as often a
    copy-paste mistake in the inventory.

    Uses a prefix trie rather than comparing every pair. An inventory derived
    from a network plan can hold tens of thousands of networks, and the pairwise
    version took over two minutes on a real one, which is most of a run spent
    producing a warning list.
    """
    from .nettrie import NetworkTrie

    warnings: list[str] = []
    trie: NetworkTrie[str] = NetworkTrie()
    truncated = 0

    for team in teams:
        for cidr in team.assets:
            net = ipaddress.ip_network(cidr)
            for other_net, other_team in trie.find_overlaps(net):
                if other_team == team.id:
                    continue
                if len(warnings) < MAX_OVERLAP_WARNINGS:
                    warnings.append(
                        f"asset {net} of team {team.id!r} overlaps {other_net} of "
                        f"team {other_team!r}"
                    )
                else:
                    truncated += 1
            trie.insert(net, team.id)

    if truncated:
        warnings.append(
            f"...and {truncated} further asset overlaps, not listed. A large number "
            "usually means the inventory describes a plan rather than actual "
            "allocations."
        )
    return warnings


def inventory_warnings(teams: list[Team]) -> list[str]:
    """Public accessor for overlap warnings, surfaced in the report."""
    return _warn_overlapping_assets(teams)


def expand_path(value: str | os.PathLike[str]) -> Path:
    return Path(os.path.expandvars(str(value))).expanduser()
