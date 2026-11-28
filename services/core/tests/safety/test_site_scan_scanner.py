import asyncio
import ssl
from datetime import date
from decimal import Decimal

import pytest
import yaml

from mandit.safety.site_scan import (
    FixtureMerchantRegistry,
    FixtureReputationStore,
    InvalidScanTarget,
    RegistryMerchant,
    SiteScanner,
    StaticTlsProbe,
    TlsResult,
    load_config,
)
from mandit.safety.site_scan.config import DEFAULT_CONFIG_PATH, parse_config
from mandit.safety.site_scan.tls import result_from_peercert

MERCHANT = RegistryMerchant(
    "mer_croma_demo", ("croma.mock.mandit.local",), ("croma.demo@mockbank",), "VERIFIED"
)


def scanner(tls=None, profile="test", config=None):
    return SiteScanner(
        config=config or load_config(),
        registry=FixtureMerchantRegistry([MERCHANT]),
        reputation=FixtureReputationStore([]),
        tls_probe=StaticTlsProbe(tls or {}),
        profile=profile,
        today=lambda: date(2026, 11, 24),
    )


def scan(s, url, html=None, **kw):
    return asyncio.run(s.scan(url, html, **kw))


def test_score_is_capped_at_one():
    raw = yaml.safe_load(DEFAULT_CONFIG_PATH.read_text())
    for sig in raw["signals"].values():
        sig["weight"] = 0.9
    s = scanner(config=parse_config(raw))
    result = scan(
        s, "https://cr0ma.mock.mandit.local/"
    )  # NOT_IN_REGISTRY + LOOKALIKE + TLS_INVALID
    assert result.site_risk_score == Decimal("1.000")
    assert result.site_risk_level == "HIGH"


def test_tls_probe_failure_fails_closed():
    result = scan(scanner(), "https://croma.mock.mandit.local/")  # no TLS fixture for the host
    assert result.codes == ["TLS_INVALID"]


def test_tls_probe_gets_port_from_url():
    seen = []

    class Probe:
        async def probe(self, host, port=443):
            seen.append((host, port))
            return TlsResult(valid=True)

    s = scanner()
    s._tls = Probe()
    scan(s, "https://croma.mock.mandit.local:8443/x")
    assert seen == [("croma.mock.mandit.local", 8443)]


def test_disabled_signal_skips_tls_probe():
    class Boom:
        async def probe(self, host, port=443):
            raise AssertionError("probe must not run")

    s = scanner()
    s._tls = Boom()
    assert (
        scan(s, "https://croma.mock.mandit.local/", disabled=frozenset({"TLS_INVALID"})).codes == []
    )


def test_invalid_url_raises():
    with pytest.raises(InvalidScanTarget):
        scan(scanner(), "file:///etc/passwd")
    with pytest.raises(InvalidScanTarget):
        scan(scanner(), "https://croma.mock.mandit.local:99999/")


def test_detectors_enabled_reflects_config_and_ablation():
    result = scan(scanner(profile="local"), "http://croma.mock.mandit.local/",
                  disabled=frozenset({"DOMAIN_LOOKALIKE"}))  # fmt: skip
    assert "DOMAIN_LOOKALIKE" not in result.detectors_enabled
    assert (
        "SUSPICIOUS_SCRIPT" not in result.detectors_enabled
    )  # disabled in config (needs Playwright)
    assert "DOMAIN_NOT_IN_REGISTRY" in result.detectors_enabled


def test_to_dict_matches_spec_shape():
    tls = {"croma.mock.mandit.local": TlsResult(valid=True, issuer="Demo CA", days_to_expiry=80)}
    body = scan(scanner(tls), "https://croma.mock.mandit.local/").to_dict()
    assert body["tls"] == {"valid": True, "issuer": "Demo CA", "days_to_expiry": 80}
    assert body["scanner_version"] == "site-scan-1.0.0"
    assert body["site_risk_score"] == 0.0 and body["signals"] == []


def test_config_rejects_unknown_signal_and_bad_thresholds():
    raw = yaml.safe_load(DEFAULT_CONFIG_PATH.read_text())
    raw["signals"]["MADE_UP"] = {"weight": 0.1}
    with pytest.raises(ValueError):
        parse_config(raw)
    raw = yaml.safe_load(DEFAULT_CONFIG_PATH.read_text())
    raw["thresholds"] = {"medium": 0.7, "high": 0.6}
    with pytest.raises(ValueError):
        parse_config(raw)


def test_result_from_peercert():
    now = ssl.cert_time_to_seconds("Nov 24 00:00:00 2026 GMT")
    cert = {"issuer": ((("organizationName", "Demo CA"),),), "notAfter": "Dec  4 00:00:00 2026 GMT"}
    assert result_from_peercert(cert, now) == TlsResult(
        valid=True, issuer="Demo CA", days_to_expiry=10
    )
    expired = {"issuer": (), "notAfter": "Nov 20 00:00:00 2026 GMT"}
    assert result_from_peercert(expired, now).valid is False
