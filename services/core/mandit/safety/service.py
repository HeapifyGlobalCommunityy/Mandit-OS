"""Safety service wiring (modules/02). Logic lives in the sub-packages; this module builds them."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import cast

from .site_scan import (
    FixtureMerchantRegistry,
    FixtureReputationStore,
    SiteScanner,
    SocketTlsProbe,
    load_config,
)
from .site_scan.config import FIXTURES_DIR as FIXTURES
from .site_scan.scanner import Profile

PROFILES: tuple[Profile, ...] = ("local", "test", "demo", "cloud")
ABLATION_PROFILES: frozenset[Profile] = frozenset({"test", "demo"})


def current_profile() -> Profile:
    profile = os.environ.get("MANDIT_PROFILE", "local")
    if profile not in PROFILES:
        raise RuntimeError(f"MANDIT_PROFILE must be one of {PROFILES}, got {profile!r}")
    return cast(Profile, profile)


@lru_cache(maxsize=4)
def build_site_scanner(profile: Profile) -> SiteScanner:
    """Phase 1 wiring: fixture registry and reputation, real TLS handshakes.

    The cloud profile is refused until the Team 3 registry adapter and the domain_reputation table
    adapter exist, so a deployment can never silently scan against fixture data.
    """
    if profile == "cloud":
        raise RuntimeError("site scanner has no production registry adapter yet")
    return SiteScanner(
        config=load_config(),
        registry=FixtureMerchantRegistry.from_yaml(FIXTURES / "registry.yaml"),
        reputation=FixtureReputationStore.from_yaml(FIXTURES / "reputation.yaml"),
        tls_probe=SocketTlsProbe(),
        profile=profile,
    )
