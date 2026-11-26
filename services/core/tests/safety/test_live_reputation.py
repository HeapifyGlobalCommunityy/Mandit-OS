import asyncio
from datetime import date

import httpx
import pytest

from mandit.safety.site_scan import (
    FixtureReputationStore,
    LiveReputationStore,
    RdapProvider,
    SafeBrowsingProvider,
    SiteScanner,
    StaticTlsProbe,
    TlsResult,
    VirusTotalProvider,
    is_public_domain,
    load_config,
)
from mandit.safety.site_scan.config import FIXTURES_DIR
from mandit.safety.site_scan.ports import FixtureMerchantRegistry

RDAP_BODY = {
    "events": [{"eventAction": "registration", "eventDate": "2026-11-20T04:00:00Z"}],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Reg Co"]]]}],
}


def vt_body(malicious):
    stats = {"malicious": malicious, "suspicious": 0}
    return {"data": {"attributes": {"last_analysis_stats": stats, "reputation": -5}}}


def make_store(handler, providers=None, **kwargs):
    requests = []

    def record(request):
        requests.append(request)
        return handler(request)

    store = LiveReputationStore(
        providers or [RdapProvider(), SafeBrowsingProvider("sb-key"), VirusTotalProvider("vt-key")],
        client_factory=lambda: httpx.AsyncClient(transport=httpx.MockTransport(record)),
        **kwargs,
    )
    return store, requests


def answer(*, sb=None, vt=0):
    def handler(request):
        host = request.url.host
        if host == "rdap.org":
            if request.url.path == "/domain/shop.evil-store.com":
                return httpx.Response(404)
            return httpx.Response(200, json=RDAP_BODY)
        if host == "safebrowsing.googleapis.com":
            return httpx.Response(200, json={"matches": [{"threatType": sb}]} if sb else {})
        return httpx.Response(200, json=vt_body(vt))

    return handler


@pytest.mark.parametrize(
    "host",
    ["localhost", "127.0.0.1", "::1", "croma.mock.mandit.local", "scamdeals.example",
     "fastlaptopdeals.example.com", "shop.test"],
)  # fmt: skip
def test_synthetic_and_private_names_are_never_sent(host):
    assert not is_public_domain(host)
    store, requests = make_store(answer())
    assert asyncio.run(store.get(host)) is None
    assert requests == []


def test_combines_providers_and_walks_up_to_the_registered_domain():
    store, requests = make_store(answer(sb="SOCIAL_ENGINEERING", vt=4))
    row = asyncio.run(store.get("shop.evil-store.com"))
    assert row.reputation == "BAD"
    assert row.source == "google_safe_browsing, virustotal"
    assert row.first_seen == date(2026, 11, 20)
    assert row.registrar == "Reg Co"
    assert [c.status for c in row.checks] == ["OK", "OK", "OK"]
    # Keys travel in headers only.
    assert not any("key" in str(r.url) for r in requests)


@pytest.mark.parametrize(("malicious", "expected"), [(0, "UNKNOWN"), (1, "UNKNOWN"), (2, "BAD")])
def test_virustotal_threshold(malicious, expected):
    store, _ = make_store(answer(vt=malicious), [VirusTotalProvider("k")])
    assert asyncio.run(store.get("some-shop.com")).reputation == expected


@pytest.mark.parametrize(
    "handler",
    [
        lambda r: httpx.Response(429),
        lambda r: httpx.Response(200, text="<html>not json</html>"),
        lambda r: (_ for _ in ()).throw(httpx.ConnectTimeout("slow")),
    ],
    ids=["rate-limited", "garbage", "timeout"],
)
def test_outage_is_reported_and_not_cached(handler):
    store, requests = make_store(handler, [RdapProvider()])
    first = asyncio.run(store.get("some-shop.com"))
    asyncio.run(store.get("some-shop.com"))
    assert first.reputation == "UNKNOWN"
    assert first.checks[0].status == "UNAVAILABLE"
    assert len(requests) == 2


def test_successful_lookup_is_cached():
    store, requests = make_store(answer(), [RdapProvider()])
    asyncio.run(store.get("some-shop.com"))
    asyncio.run(store.get("some-shop.com"))
    assert len(requests) == 1


def test_local_row_wins_over_live_lookup():
    local = FixtureReputationStore.from_yaml(FIXTURES_DIR / "reputation.yaml")
    store, requests = make_store(answer(), local=local)
    assert asyncio.run(store.get("scamdeals.example")).reputation == "BAD"
    assert requests == []


def test_scanner_scores_live_results():
    store, _ = make_store(answer(vt=5))
    scanner = SiteScanner(
        config=load_config(),
        registry=FixtureMerchantRegistry.from_yaml(FIXTURES_DIR / "registry.yaml"),
        reputation=store,
        tls_probe=StaticTlsProbe({"evil-store.com": TlsResult(valid=True)}),
        today=lambda: date(2026, 11, 26),
    )
    result = asyncio.run(scanner.scan("https://evil-store.com/checkout"))
    assert set(result.codes) == {"DOMAIN_NOT_IN_REGISTRY", "DOMAIN_NEW", "DOMAIN_REPUTATION_BAD"}
    assert result.site_risk_level == "HIGH"
    assert [c["provider"] for c in result.to_dict()["reputation_lookups"]] == [
        "rdap", "google_safe_browsing", "virustotal",
    ]  # fmt: skip


def test_provider_selection_follows_environment(monkeypatch):
    from mandit.safety.service import build_providers

    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
    monkeypatch.setenv("MANDIT_LIVE_LOOKUPS", "on")
    assert [p.name for p in build_providers()] == ["rdap", "virustotal"]
    monkeypatch.setenv("MANDIT_LIVE_LOOKUPS", "off")
    assert build_providers() == []
