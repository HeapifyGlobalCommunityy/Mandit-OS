"""Live domain-reputation and domain-age lookups, behind the ``DomainReputationStore`` protocol.

Providers:

- RDAP (https://rdap.org): domain registration date and registrar. No API key.
- Google Safe Browsing Lookup API v4: known malware/phishing URLs. Needs an API key and is for
  non-commercial use only.
- VirusTotal API v3: how many engines flag the domain. Needs an API key. Queried domains become
  visible to the VirusTotal community.

Only a host name ever leaves the machine, never a page path, query string or content. Synthetic and
private names (``*.local``, ``*.test``, ``*.example``, IP addresses, ...) are never sent anywhere.

A provider that fails is reported as ``UNAVAILABLE`` in the scan result. It does not mark the
domain as bad or good.
"""

from __future__ import annotations

import ipaddress
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from .ports import DomainReputation, DomainReputationStore, ProviderCheck

_PRIVATE_SUFFIXES = frozenset(
    {"local", "localhost", "test", "example", "invalid", "internal", "lan", "home", "arpa"}
)
_RESERVED_DOMAINS = ("example.com", "example.net", "example.org")


def is_public_domain(host: str) -> bool:
    """True if ``host`` is a name that a public lookup service could know about."""
    host = host.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    if "." not in host or host.rsplit(".", 1)[1] in _PRIVATE_SUFFIXES:
        return False
    return not any(host == d or host.endswith("." + d) for d in _RESERVED_DOMAINS)


@dataclass(frozen=True)
class ProviderResult:
    check: ProviderCheck
    bad: bool = False
    registered_on: date | None = None
    registrar: str | None = None


class ReputationProvider(Protocol):
    name: str

    async def lookup(self, client: httpx.AsyncClient, host: str) -> ProviderResult: ...


def _result(name: str, status: str, detail: str, **kwargs: Any) -> ProviderResult:
    return ProviderResult(ProviderCheck(name, status, detail), **kwargs)  # type: ignore[arg-type]


def _registrar_name(body: dict[str, Any]) -> str | None:
    for entity in body.get("entities") or []:
        if "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray") or []
        for field in vcard[1] if len(vcard) > 1 else []:
            if field and field[0] == "fn":
                return str(field[3])
    return None


class RdapProvider:
    name = "rdap"

    def __init__(self, base_url: str = "https://rdap.org") -> None:
        self._base = base_url.rstrip("/")

    async def lookup(self, client: httpx.AsyncClient, host: str) -> ProviderResult:
        labels = host.split(".")
        # Registries only know the registered name, so walk up: a.b.co.uk -> b.co.uk.
        candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)][-3:]
        for domain in candidates:
            resp = await client.get(
                f"{self._base}/domain/{quote(domain)}",
                headers={"Accept": "application/rdap+json"},
                follow_redirects=True,  # rdap.org redirects to the authoritative registry
            )
            if resp.status_code == 404:
                continue
            if resp.status_code != 200:
                return _result(self.name, "UNAVAILABLE", f"HTTP {resp.status_code}")
            body = resp.json()
            registered = None
            for event in body.get("events") or []:
                if event.get("eventAction") == "registration":
                    registered = datetime.fromisoformat(
                        event["eventDate"].replace("Z", "+00:00")
                    ).date()
            detail = f"{domain} registered {registered or 'on an unpublished date'}"
            return _result(
                self.name,
                "OK",
                detail,
                registered_on=registered,
                registrar=_registrar_name(body),
            )
        return _result(self.name, "NOT_FOUND", "no RDAP record (unregistered or unsupported TLD)")


class SafeBrowsingProvider:
    name = "google_safe_browsing"
    URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def __init__(self, api_key: str) -> None:
        self._key = api_key

    async def lookup(self, client: httpx.AsyncClient, host: str) -> ProviderResult:
        resp = await client.post(
            self.URL,
            # A header, not ?key=, so the key never appears in request logs.
            headers={"x-goog-api-key": self._key},
            json={
                "client": {"clientId": "mandit-os", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION",
                    ],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": f"http://{host}/"}, {"url": f"https://{host}/"}],
                },
            },
        )
        if resp.status_code != 200:
            return _result(self.name, "UNAVAILABLE", f"HTTP {resp.status_code}")
        threats = sorted({m["threatType"] for m in resp.json().get("matches") or []})
        if threats:
            return _result(self.name, "OK", "listed as " + ", ".join(threats), bad=True)
        return _result(self.name, "OK", "not listed")


class VirusTotalProvider:
    name = "virustotal"
    URL = "https://www.virustotal.com/api/v3/domains/"

    def __init__(self, api_key: str, *, min_malicious: int = 2) -> None:
        self._key = api_key
        self._min_malicious = min_malicious  # one engine alone is often a false positive

    async def lookup(self, client: httpx.AsyncClient, host: str) -> ProviderResult:
        resp = await client.get(self.URL + quote(host), headers={"x-apikey": self._key})
        if resp.status_code == 404:
            return _result(self.name, "NOT_FOUND", "domain unknown to VirusTotal")
        if resp.status_code != 200:
            return _result(self.name, "UNAVAILABLE", f"HTTP {resp.status_code}")
        attributes = resp.json()["data"]["attributes"]
        stats = attributes["last_analysis_stats"]
        malicious = int(stats["malicious"])
        detail = (
            f"{malicious} malicious, {int(stats['suspicious'])} suspicious engine verdicts, "
            f"community score {attributes.get('reputation', 0)}"
        )
        return _result(self.name, "OK", detail, bad=malicious >= self._min_malicious)


class LiveReputationStore:
    """Asks every provider about public domains; falls back to ``local`` for everything else.

    A row in ``local`` (the fixture or ``domain_reputation`` table) always wins, so synthetic test
    domains behave the same with live lookups switched on.
    """

    def __init__(
        self,
        providers: list[ReputationProvider],
        *,
        local: DomainReputationStore | None = None,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
        cache_ttl_s: float = 3600.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._providers = providers
        self._local = local
        self._client_factory = client_factory or (lambda: httpx.AsyncClient(timeout=5.0))
        self._ttl = cache_ttl_s
        self._clock = clock
        self._cache: dict[str, tuple[float, DomainReputation]] = {}

    async def get(self, domain: str) -> DomainReputation | None:
        if self._local is not None:
            row = await self._local.get(domain)
            if row is not None:
                return row
        if not self._providers or not is_public_domain(domain):
            return None
        cached = self._cache.get(domain)
        if cached is not None and self._clock() - cached[0] < self._ttl:
            return cached[1]

        async with self._client_factory() as client:
            results = [await self._ask(p, client, domain) for p in self._providers]

        bad = [r.check.provider for r in results if r.bad]
        row = DomainReputation(
            domain=domain,
            first_seen=next((r.registered_on for r in results if r.registered_on), None),
            reputation="BAD" if bad else "UNKNOWN",
            source=", ".join(bad) if bad else "live lookup",
            registrar=next((r.registrar for r in results if r.registrar), None),
            checks=tuple(r.check for r in results),
        )
        # Never cache an outage: the next scan should try again.
        if all(r.check.status != "UNAVAILABLE" for r in results):
            self._cache[domain] = (self._clock(), row)
        return row

    @staticmethod
    async def _ask(
        provider: ReputationProvider, client: httpx.AsyncClient, domain: str
    ) -> ProviderResult:
        try:
            return await provider.lookup(client, domain)
        except (
            httpx.HTTPError,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
            IndexError,
        ) as exc:
            # Only the exception type: messages can contain request URLs.
            return _result(provider.name, "UNAVAILABLE", type(exc).__name__)
