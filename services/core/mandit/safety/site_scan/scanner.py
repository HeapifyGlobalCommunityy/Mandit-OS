"""Web Safety Scanner (modules/02 section 6): is this website or checkout risky?"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any, Literal
from urllib.parse import urlsplit

from .config import SIGNAL_CODES, SiteScanConfig
from .domains import Host, InvalidScanTarget, find_lookalike, host_of, is_owned_by_any, parse_target
from .html_checks import extract_page_structure
from .ports import (
    DomainReputationStore,
    MerchantRegistry,
    ProviderCheck,
    RegistryMerchant,
)
from .tls import TlsProbe, TlsResult

RiskLevel = Literal["LOW", "MEDIUM", "HIGH"]
Profile = Literal["local", "test", "demo", "cloud"]


@dataclass(frozen=True)
class Signal:
    code: str
    weight: Decimal
    detail: str


@dataclass(frozen=True)
class SiteScanResult:
    domain: str
    site_risk_score: Decimal
    site_risk_level: RiskLevel
    signals: tuple[Signal, ...]
    tls: TlsResult | None
    merchant_id: str | None
    scanner_version: str
    detectors_enabled: tuple[str, ...]
    reputation_lookups: tuple[ProviderCheck, ...] = ()

    @property
    def codes(self) -> list[str]:
        return [s.code for s in self.signals]

    def to_dict(self) -> dict[str, Any]:
        """The response body of POST /v1/safety/site-scan (modules/02 section 6.1)."""
        tls = None
        if self.tls is not None:
            tls = {"valid": self.tls.valid, "issuer": self.tls.issuer,
                   "days_to_expiry": self.tls.days_to_expiry}  # fmt: skip
            if self.tls.error:
                tls["error"] = self.tls.error
        return {
            "domain": self.domain,
            "site_risk_score": float(self.site_risk_score),
            "site_risk_level": self.site_risk_level,
            "signals": [
                {"code": s.code, "weight": float(s.weight), "detail": s.detail}
                for s in self.signals
            ],
            "tls": tls,
            "merchant_id": self.merchant_id,
            "scanner_version": self.scanner_version,
            "detectors_enabled": list(self.detectors_enabled),
            "reputation_lookups": [
                {"provider": c.provider, "status": c.status, "detail": c.detail}
                for c in self.reputation_lookups
            ],
        }


def _utc_today() -> date:
    return datetime.now(UTC).date()


class SiteScanner:
    def __init__(
        self,
        *,
        config: SiteScanConfig,
        registry: MerchantRegistry,
        reputation: DomainReputationStore,
        tls_probe: TlsProbe,
        profile: Profile = "local",
        today: Callable[[], date] = _utc_today,
    ) -> None:
        self._cfg = config
        self._registry = registry
        self._reputation = reputation
        self._tls = tls_probe
        self._profile = profile
        self._today = today

    async def scan(
        self, url: str, html: str | None = None, *, disabled: frozenset[str] = frozenset()
    ) -> SiteScanResult:
        """Scan ``url`` (and its HTML, when given). Raises InvalidScanTarget if unscannable."""
        scheme, host = parse_target(url)
        try:
            port = urlsplit(url.strip()).port or (443 if scheme == "https" else 80)
        except ValueError as exc:
            raise InvalidScanTarget(f"invalid port: {exc}") from exc

        enabled = self._cfg.enabled_signals - disabled
        found: dict[str, str] = {}  # code -> detail; one entry per code, so weights add once

        merchant = await self._registry.resolve_domain(host.ascii)
        verified = merchant if merchant is not None and merchant.status == "VERIFIED" else None
        lookups = await self._check_domain(host, merchant, verified, found)

        tls: TlsResult | None = None
        if scheme == "http":
            if self._profile != "local":
                found["NO_TLS"] = "Plain HTTP outside the local profile"
        elif "TLS_INVALID" in enabled:
            tls = await self._tls.probe(host.ascii, port)
            if not tls.valid:
                found["TLS_INVALID"] = tls.error or "TLS validation failed"

        if html:
            self._check_checkout(html, url, host.ascii, verified, found)

        signals = tuple(
            Signal(code, self._cfg.signals[code].weight, found[code])
            for code in SIGNAL_CODES
            if code in found and code in enabled
        )
        score = min(Decimal(1), sum((s.weight for s in signals), Decimal(0)))
        return SiteScanResult(
            domain=host.ascii,
            site_risk_score=score.quantize(Decimal("0.001")),
            site_risk_level=self._level(score),
            signals=signals,
            tls=tls,
            merchant_id=verified.merchant_id if verified else None,
            scanner_version=self._cfg.scanner_version,
            detectors_enabled=tuple(c for c in SIGNAL_CODES if c in enabled),
            reputation_lookups=lookups,
        )

    async def _check_domain(
        self,
        host: Host,
        merchant: RegistryMerchant | None,
        verified: RegistryMerchant | None,
        found: dict[str, str],
    ) -> tuple[ProviderCheck, ...]:
        if verified is None:
            found["DOMAIN_NOT_IN_REGISTRY"] = (
                f"Merchant {merchant.merchant_id} owning this domain is {merchant.status}"
                if merchant is not None
                else "No registered merchant owns this domain"
            )
            match = find_lookalike(
                host,
                await self._registry.list_domains(),
                max_edit_distance=self._cfg.max_edit_distance,
                min_brand_label_length=self._cfg.min_brand_label_length,
            )
            if match is not None:
                found["DOMAIN_LOOKALIKE"] = match.detail

        rep = await self._reputation.get(host.ascii)
        if rep is not None:
            if rep.reputation == "BAD":
                found["DOMAIN_REPUTATION_BAD"] = f"Reputation BAD for {rep.domain} ({rep.source})"
            if rep.first_seen is not None:
                age = (self._today() - rep.first_seen).days
                if age < self._cfg.domain_new_days:
                    found["DOMAIN_NEW"] = f"First seen {age} days ago ({rep.source})"
        return rep.checks if rep is not None else ()

    def _check_checkout(
        self,
        html: str,
        url: str,
        page_host: str,
        verified: RegistryMerchant | None,
        found: dict[str, str],
    ) -> None:
        page = extract_page_structure(html, url)
        # An unregistered site owns only its own host; a registered merchant owns all its domains.
        owned = verified.domains if verified is not None else (page_host,)
        allowed = (*owned, *self._cfg.payment_processor_domains)

        payee_problems: list[str] = []
        for form in page.payment_forms:
            for target_url in form.target_urls:
                if target_url is None:
                    payee_problems.append("Payment form submits to an unparseable URL")
                    continue
                target = host_of(target_url)
                if target is not None and not is_owned_by_any(target.ascii, allowed):
                    payee_problems.append(f"Payment form posts to {target.ascii}")
        for vpa in page.all_vpas:
            if verified is None:
                payee_problems.append(f"UPI payee {vpa} cannot be tied to a registered merchant")
            elif vpa not in verified.upi_vpas:
                payee_problems.append(f"UPI payee {vpa} is not a payee of {verified.merchant_id}")
        if payee_problems:
            found["CHECKOUT_PAYEE_MISMATCH"] = "; ".join(dict.fromkeys(payee_problems))

        frame_origins: set[str] = set()
        for frame in page.frames:
            if not frame.is_payment:
                continue
            if frame.src_url is None:
                frame_origins.add("<unparseable URL>")
                continue
            h = host_of(frame.src_url)
            if h is not None and not is_owned_by_any(h.ascii, allowed):
                frame_origins.add(h.ascii)
        if frame_origins:
            found["EXTERNAL_PAYMENT_IFRAME"] = "Payment iframe from " + ", ".join(
                sorted(frame_origins)
            )

    def _level(self, score: Decimal) -> RiskLevel:
        if score >= self._cfg.high_threshold:
            return "HIGH"
        if score >= self._cfg.medium_threshold:
            return "MEDIUM"
        return "LOW"
