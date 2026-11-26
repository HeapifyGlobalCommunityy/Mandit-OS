from datetime import date

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from mandit.safety import api
from mandit.safety.site_scan import (
    FixtureMerchantRegistry,
    FixtureReputationStore,
    SiteScanner,
    StaticTlsProbe,
    TlsResult,
    load_config,
)
from mandit.safety.site_scan.config import FIXTURES_DIR

FAKE_CHECKOUT = (FIXTURES_DIR / "pages" / "fake_checkout.html").read_text()


def make_client(profile: str) -> TestClient:
    scanner = SiteScanner(
        config=load_config(),
        registry=FixtureMerchantRegistry.from_yaml(FIXTURES_DIR / "registry.yaml"),
        reputation=FixtureReputationStore.from_yaml(FIXTURES_DIR / "reputation.yaml"),
        tls_probe=StaticTlsProbe({"fastlaptopdeals.example.com": TlsResult(valid=True)}),
        profile=profile,
        today=lambda: date(2026, 11, 24),
    )
    app = FastAPI()
    app.include_router(api.router)
    app.dependency_overrides[api.get_site_scanner] = lambda: scanner
    app.dependency_overrides[api.get_profile] = lambda: profile
    return TestClient(app)


@pytest.fixture
def client():
    return make_client("test")


def test_site_scan_fake_checkout(client):
    resp = client.post("/v1/safety/site-scan", json={
        "url": "https://fastlaptopdeals.example.com/checkout", "html": FAKE_CHECKOUT,
        "transaction_id": "txn_01JD3XA1B2C3D4E5F6G7H8J9K0",
    })  # fmt: skip
    assert resp.status_code == 200
    body = resp.json()
    assert body["site_risk_level"] == "HIGH"
    assert body["site_risk_score"] == 0.95
    assert {s["code"] for s in body["signals"]} == {
        "DOMAIN_NOT_IN_REGISTRY",
        "DOMAIN_NEW",
        "CHECKOUT_PAYEE_MISMATCH",
        "EXTERNAL_PAYMENT_IFRAME",
    }


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"url": "https://a.example", "extra": 1},
        {"url": "https://a.example", "transaction_id": "bad"},
    ],
)
def test_validation_errors_use_envelope(client, body):
    resp = client.post("/v1/safety/site-scan", json=body)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


def test_unscannable_url(client):
    resp = client.post("/v1/safety/site-scan", json={"url": "ftp://files.example/"},
                       headers={"X-Request-ID": "req_abc"})  # fmt: skip
    assert resp.status_code == 400
    assert resp.json()["error"]["request_id"] == "req_abc"


def test_ablation_header_disables_signals(client):
    resp = client.post(
        "/v1/safety/site-scan",
        json={"url": "https://fastlaptopdeals.example.com/checkout", "html": FAKE_CHECKOUT},
        headers={"X-Mandit-Ablation": "checkout_payee_mismatch=off, external_payment_iframe=off"},
    )
    body = resp.json()
    assert resp.status_code == 200
    assert {s["code"] for s in body["signals"]} == {"DOMAIN_NOT_IN_REGISTRY", "DOMAIN_NEW"}
    assert "CHECKOUT_PAYEE_MISMATCH" not in body["detectors_enabled"]


@pytest.mark.parametrize("profile", ["cloud", "local"])
def test_ablation_refused_outside_test_and_demo(profile):
    resp = make_client(profile).post(
        "/v1/safety/site-scan", json={"url": "https://fastlaptopdeals.example.com/"},
        headers={"X-Mandit-Ablation": "domain_new=off"},
    )  # fmt: skip
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "ABLATION_NOT_PERMITTED"


@pytest.mark.parametrize("header", ["unknown_signal=off", "domain_new=on", "domain_new"])
def test_bad_ablation_header(client, header):
    resp = client.post("/v1/safety/site-scan", json={"url": "https://a.example/"},
                       headers={"X-Mandit-Ablation": header})  # fmt: skip
    assert resp.status_code == 400
