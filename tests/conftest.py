"""Shared test fixtures.

All test data comes from ``fixtures.generator``. No real configuration, from
any source, is ever committed to this repository -- see ``docs/PRIVACY.md``.
"""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fixtures.generator import (  # noqa: E402
    GeneratorOptions,
    generate_firewall,
    generate_panorama,
)

from panorama_team_review.config import Config, OutputConfig, ReportConfig  # noqa: E402
from panorama_team_review.model import Team  # noqa: E402
from panorama_team_review.parse import panos  # noqa: E402
from panorama_team_review.parse.loader import load  # noqa: E402

# The date the generator's descriptions are written relative to. Pinning it
# keeps expiry-related assertions stable no matter when the suite runs.
REFERENCE_DATE = date(2026, 7, 28)


@pytest.fixture(scope="session")
def options() -> GeneratorOptions:
    return GeneratorOptions()


@pytest.fixture(scope="session")
def panorama_xml(options: GeneratorOptions) -> str:
    return generate_panorama(options)


@pytest.fixture(scope="session")
def firewall_xml(options: GeneratorOptions) -> str:
    return generate_firewall(options)


@pytest.fixture(scope="session")
def panorama_file(tmp_path_factory, panorama_xml: str) -> Path:
    path = tmp_path_factory.mktemp("backups") / "panorama-running-config.xml"
    path.write_text(panorama_xml, encoding="utf-8")
    return path


@pytest.fixture(scope="session")
def firewall_file(tmp_path_factory, firewall_xml: str) -> Path:
    path = tmp_path_factory.mktemp("backups-fw") / "fw-running-config.xml"
    path.write_text(firewall_xml, encoding="utf-8")
    return path


@pytest.fixture
def panorama_snapshot(panorama_file: Path):
    """A freshly parsed snapshot.

    Deliberately function-scoped and re-parsed each time: resolution mutates
    the snapshot in place, so sharing one across tests would let them leak
    state into each other.
    """
    return panos.parse(load(panorama_file)[0])


@pytest.fixture
def firewall_snapshot(firewall_file: Path):
    return panos.parse(load(firewall_file)[0])


@pytest.fixture
def teams() -> list[Team]:
    """An inventory matching the networks the generator produces.

    Device group index decides the network: DG-Shared-Services gets 10.10/16,
    DG-Production 10.20/16, DG-Development 10.30/16.
    """
    return [
        Team(
            id="platform",
            name="Platform Services",
            contact="platform@example.com",
            assets=["10.10.0.0/16"],
            asset_labels={"10.10.0.0/16": "Management network"},
            tags=["owner:platform"],
            device_groups=["DG-Shared-Services"],
        ),
        Team(
            id="payments",
            name="Payments Platform",
            contact="payments@example.com",
            assets=["10.20.0.0/16", "10.20.1.5/32"],
            asset_labels={"10.20.1.5/32": "payment-gw01"},
            tags=["owner:payments"],
        ),
        Team(
            id="development",
            name="Development",
            contact="dev@example.com",
            assets=["10.30.0.0/16"],
        ),
        Team(
            id="partners",
            name="Partner Integration",
            contact="partners@example.com",
            assets=["198.51.100.0/24"],
        ),
    ]


@pytest.fixture
def config(tmp_path: Path) -> Config:
    """A configuration suitable for tests: fast formats, deterministic paths."""
    return Config(
        output=OutputConfig(
            directory=tmp_path / "out",
            formats=["json"],
            timestamped_subdir=False,
        ),
        report=ReportConfig(title="Test Firewall Review", organisation="Example Org"),
    )
