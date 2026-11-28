import asyncio

import pytest
from fastapi.testclient import TestClient

from mandit.devserver import app
from mandit.grounding.registry.yaml_directory import (
    DEFAULT_REGISTRY_PATH,
    YamlMerchantDirectory,
)
from mandit.safety import api as safety_api
from mandit.safety.site_scan import FixtureReputationStore
from mandit.safety.site_scan.config import FIXTURES_DIR


@pytest.fixture
def client():
    app.dependency_overrides[safety_api.get_reputation_store] = lambda: (
        FixtureReputationStore.from_yaml(FIXTURES_DIR / "reputation.yaml")
    )
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_get_merchant(client):
    body = client.get("/v1/merchants/mer_croma_demo").json()
    assert body["legal_name"] == "Croma Demo Retail (synthetic)"
    assert body["payees"]["upi_vpas"] == ["croma.demo@mockbank"]


@pytest.mark.parametrize(
    "domain", ["croma.mock.mandit.local", "pay.croma.mock.mandit.local", "CROMA.mock.mandit.local."]
)
def test_resolve_domain(client, domain):
    resp = client.get("/v1/merchants", params={"domain": domain})
    assert resp.json()["merchant_id"] == "mer_croma_demo"


@pytest.mark.parametrize(
    "path",
    ["/v1/merchants/mer_nobody", "/v1/merchants?domain=croma.mock.mandit.local.evil.example"],
)
def test_unknown_merchant(client, path):
    resp = client.get(path)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "MERCHANT_NOT_IN_REGISTRY"


def test_domain_info(client):
    resp = client.get("/v1/safety/domain-info", params={"domain": "croma.mock.mandit.local"})
    body = resp.json()
    assert body["merchant"]["merchant_id"] == "mer_croma_demo"
    assert body["registration"]["registered_on"] == "2019-03-01"
    assert body["reputation"] == "GOOD"


@pytest.mark.parametrize("domain", ["a.com/path", "user@a.com", "a.com:8080"])
def test_domain_info_rejects_urls(client, domain):
    assert client.get("/v1/safety/domain-info", params={"domain": domain}).status_code == 400


def test_two_merchants_cannot_claim_overlapping_domains():
    croma = asyncio.run(
        YamlMerchantDirectory.from_yaml(DEFAULT_REGISTRY_PATH).get_merchant("mer_croma_demo")
    )
    from dataclasses import replace

    thief = replace(croma, merchant_id="mer_thief", domains=("pay.croma.mock.mandit.local",))
    with pytest.raises(ValueError, match="both claim"):
        YamlMerchantDirectory([croma, thief])
