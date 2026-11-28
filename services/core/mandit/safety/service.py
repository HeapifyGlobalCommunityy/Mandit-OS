"""Safety service wiring (modules/02). Logic lives in the sub-packages; this module builds them."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import cast

from mandit.grounding.service import build_merchant_directory

from .content import InMemoryContentStore, InMemoryEventSink, SafetyServiceImpl
from .injection import InjectionFirewall, load_firewall_config
from .site_scan import (
    FixtureReputationStore,
    LiveReputationStore,
    RdapProvider,
    SafeBrowsingProvider,
    SiteScanner,
    SocketTlsProbe,
    VirusTotalProvider,
    load_config,
)
from .site_scan.config import FIXTURES_DIR as FIXTURES
from .site_scan.live_reputation import ReputationProvider
from .site_scan.netguard import EgressPolicy
from .site_scan.registry_adapter import DirectoryRegistry
from .site_scan.scanner import Profile

PROFILES: tuple[Profile, ...] = ("local", "test", "demo", "cloud")
ABLATION_PROFILES: frozenset[Profile] = frozenset({"test", "demo"})

# Compose mock merchants live on private addresses; only non-cloud profiles may reach them.
MOCK_PRIVATE_SUFFIXES = ("mock.mandit.local",)


def egress_policy(profile: Profile) -> EgressPolicy:
    if profile == "cloud":
        return EgressPolicy()
    return EgressPolicy(private_host_suffixes=MOCK_PRIVATE_SUFFIXES)


def current_profile() -> Profile:
    profile = os.environ.get("MANDIT_PROFILE", "local")
    if profile not in PROFILES:
        raise RuntimeError(f"MANDIT_PROFILE must be one of {PROFILES}, got {profile!r}")
    return cast(Profile, profile)


def build_providers() -> list[ReputationProvider]:
    """RDAP needs no key; the other two are used only when their key is set.

    A missing key is not an error: that provider is skipped and the scan runs on the rest.
    MANDIT_LIVE_LOOKUPS=off disables all outbound lookups.
    """
    mode = os.environ.get("MANDIT_LIVE_LOOKUPS", "on").lower()
    if mode not in ("on", "off"):
        raise RuntimeError(f"MANDIT_LIVE_LOOKUPS must be 'on' or 'off', got {mode!r}")
    if mode == "off":
        return []
    providers: list[ReputationProvider] = [RdapProvider()]
    if key := os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY"):
        providers.append(SafeBrowsingProvider(key))
    if key := os.environ.get("VIRUS_TOTAL_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY"):
        providers.append(VirusTotalProvider(key))
    return providers


@lru_cache(maxsize=1)
def build_reputation_store() -> LiveReputationStore:
    return LiveReputationStore(
        build_providers(),
        local=FixtureReputationStore.from_yaml(FIXTURES / "reputation.yaml"),
    )


@lru_cache(maxsize=4)
def build_site_scanner(profile: Profile) -> SiteScanner:
    """Phase 1 wiring: file registry, fixture plus live reputation, real TLS handshakes.

    The cloud profile is refused until the table-backed registry and domain_reputation adapters
    exist, so a deployment can never silently scan against fixture data.
    """
    if profile == "cloud":
        raise RuntimeError("site scanner has no production registry adapter yet")
    return SiteScanner(
        config=load_config(),
        registry=DirectoryRegistry(build_merchant_directory()),
        reputation=build_reputation_store(),
        tls_probe=SocketTlsProbe(policy=egress_policy(profile)),
        profile=profile,
    )


@lru_cache(maxsize=1)
def build_firewall() -> InjectionFirewall:
    return InjectionFirewall(load_firewall_config())


@lru_cache(maxsize=4)
def build_safety_service(profile: Profile) -> SafetyServiceImpl:
    """Phase 1 wiring: in-memory content store and event sink.

    Refused in the cloud profile until the SQLAlchemy store (migration 0002 tables) and the Team 5
    evidence adapter exist: records and ledger events must not silently live in process memory.
    """
    if profile == "cloud":
        raise RuntimeError("safety service has no persistent store or evidence adapter yet")
    return SafetyServiceImpl(
        site_scanner=build_site_scanner(profile),
        firewall=build_firewall(),
        store=InMemoryContentStore(),
        events=InMemoryEventSink(),
    )
