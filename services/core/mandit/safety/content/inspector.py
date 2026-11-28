"""SafetyService implementation: content intake, provenance and risk aggregation.

modules/02 R4 (content records) and R10 (aggregated risk API).

``inspect`` is the single intake path: every piece of external content becomes an immutable,
``UNTRUSTED`` content record with a hash of the exact bytes, a site scan and an injection scan.

``get_risk`` is what Team 3 (Trust Score component P) and Team 4 (HG-14, HG-15, SU-03, SU-04) read.
It is computed **only** from server-side state: stored scan reports of the referenced content and a
fresh domain scan of the merchant. Nothing a caller or agent supplies (a score, a level, HTML for
the merchant) can lower it. Unknown content IDs fail closed (``ContentNotFound``).
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime

from ..ids import new_id
from ..injection import InjectionFirewall, InjectionReport
from ..injection.firewall import SEVERITY_ORDER
from ..interface import (
    ContentNotFound,
    ContentRecord,
    ContentReport,
    InjectionSeverity,
    InspectRequest,
    RiskLevel,
    RiskSignal,
    RiskSummary,
)
from ..site_scan import SiteScanner, SiteScanResult
from ..site_scan.domains import InvalidScanTarget, is_owned, normalize_host, parse_target
from .classify import classify
from .store import ContentStore, EventSink, ScanReport

MAX_RAW_BYTES = 5 * 1024 * 1024
HTML_MIME = ("text/html", "application/xhtml+xml")


def _utcnow() -> datetime:
    return datetime.now(UTC)


class SafetyServiceImpl:
    def __init__(
        self,
        *,
        site_scanner: SiteScanner,
        firewall: InjectionFirewall,
        store: ContentStore,
        events: EventSink,
        now: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._site = site_scanner
        self._fw = firewall
        self._store = store
        self._events = events
        self._now = now

    @property
    def scanner_version(self) -> str:
        return f"{self._site.scanner_version}+{self._fw.config.firewall_version}"

    # --- intake -----------------------------------------------------------------------------------
    async def inspect(
        self,
        req: InspectRequest,
        *,
        disabled_site: frozenset[str] = frozenset(),
        disabled_detectors: frozenset[str] = frozenset(),
    ) -> ContentReport:
        if len(req.raw) > MAX_RAW_BYTES:
            raise ValueError(f"raw content exceeds {MAX_RAW_BYTES} bytes")
        _, host = parse_target(req.url)  # raises InvalidScanTarget
        mime = req.mime_type.split(";", 1)[0].strip().lower()
        text = req.raw.decode("utf-8", errors="replace")

        # CPU-bound and potentially slow on hostile input: keep it off the event loop.
        injection: InjectionReport = await asyncio.to_thread(
            self._fw.scan, text, mime, disabled=disabled_detectors
        )
        # Checkout-integrity checks need page HTML; other sources still get the domain-level checks.
        html = text if req.source_type == "WEB_PAGE" and mime in HTML_MIME else None
        site: SiteScanResult = await self._site.scan(req.url, html, disabled=disabled_site)

        content_id = new_id("cnt")
        scan_id = new_id("scn")
        content_hash = "sha256:" + _sha256(req.raw)
        fetched_at = self._now()
        record = ContentRecord(
            content_id=content_id,
            transaction_id=req.transaction_id,
            tool_call_id=req.tool_call_id,
            source_type=req.source_type,
            source_url=req.url,
            domain=host.ascii,
            content_hash=content_hash,
            blob_ref=f"blob:{content_hash}",
            classification=classify(req.source_type, req.url, injection.visible_text),
            fetched_at=fetched_at,
            scan_id=scan_id,
            visible_text=injection.visible_text,
        )
        site_dict = site.to_dict()
        report = ScanReport(
            scan_id=scan_id,
            content_id=content_id,
            domain=host.ascii,
            site_risk_score=float(site.site_risk_score),
            site_risk_level=site.site_risk_level,
            site_signals=tuple(site_dict["signals"]),
            injection_detected=injection.injection_detected,
            injection_severity=injection.severity,
            findings=tuple(f.to_dict() for f in injection.findings),
            scanner_version=self.scanner_version,
            detectors_enabled=(*site.detectors_enabled, *injection.detectors_enabled),
            created_at=fetched_at,
        )
        await self._store.put(record, report, req.raw)

        # Payloads follow the event catalogue (modules/05 section 12).
        await self._events.emit(
            "CONTENT_SEEN",
            req.transaction_id,
            {
                "content_id": content_id,
                "tool_call_id": req.tool_call_id,
                "source_type": req.source_type,
                "source_url": req.url,
                "domain": host.ascii,
                "content_hash": content_hash,
                "classification": record.classification,
                "fetched_at": fetched_at.isoformat().replace("+00:00", "Z"),
            },
        )
        await self._events.emit(
            "SITE_SCANNED",
            req.transaction_id,
            {
                "content_id": content_id,
                "scan_id": scan_id,
                "domain": host.ascii,
                "site_risk_score": report.site_risk_score,
                "site_risk_level": report.site_risk_level,
                "signals": [s["code"] for s in report.site_signals],
                "scanner_version": report.scanner_version,
            },
        )
        if injection.injection_detected:
            await self._events.emit(
                "INJECTION_DETECTED",
                req.transaction_id,
                {
                    "content_id": content_id,
                    "scan_id": scan_id,
                    "severity": injection.severity,
                    "findings": [
                        {
                            "technique": f.technique,
                            "severity": f.severity,
                            "targets": list(f.targets),
                            "finding_id": f.finding_id,
                        }
                        for f in injection.findings
                    ],
                    "detectors_enabled": list(injection.detectors_enabled),
                },
            )

        return ContentReport(
            record=record,
            site_risk=site_dict,
            injection=injection.to_dict(),
            sanitized_chunks=tuple(c.to_dict() for c in injection.chunks),
            scanner_version=self.scanner_version,
        )

    async def get_content(self, content_id: str) -> ContentRecord:
        record = await self._store.get_record(content_id)
        if record is None:
            raise ContentNotFound(content_id)
        return record

    # --- risk ------------------------------------------------------------------------------------
    async def get_risk(self, content_ids: list[str], merchant_domain: str) -> RiskSummary:
        try:
            domain = normalize_host(merchant_domain).ascii
        except InvalidScanTarget as exc:
            raise ValueError(f"invalid merchant_domain: {exc}") from exc
        if "/" in domain or ":" in domain or " " in domain:
            raise ValueError("merchant_domain must be a bare host name")

        reports: list[ScanReport] = []
        for cid in dict.fromkeys(content_ids):  # de-duplicate, keep order
            record = await self.get_content(cid)  # ContentNotFound fails the whole call
            report = await self._store.get_report(record.scan_id)
            if report is None:
                raise ContentNotFound(f"scan report missing for {cid}")
            reports.append(report)

        max_sev: InjectionSeverity = "NONE"
        injection_ids: list[str] = []
        signals: list[RiskSignal] = []
        for rep in reports:
            if rep.injection_severity != "NONE":
                injection_ids.append(rep.content_id)
                signals.extend(
                    RiskSignal(
                        code=t,
                        weight=0.0,
                        detail=f"{rep.injection_severity} injection",
                        source=rep.content_id,
                    )  # fmt: skip
                    for t in sorted({f["technique"] for f in rep.findings})
                )
            if SEVERITY_ORDER[rep.injection_severity] > SEVERITY_ORDER[max_sev]:
                max_sev = rep.injection_severity

        # Site risk: the worse of a fresh merchant-domain scan and any stored scan of referenced
        # content on the merchant's own domain (which includes checkout-integrity signals).
        fresh = await self._site.scan(f"https://{domain}/")
        candidates: list[tuple[float, RiskLevel, list[RiskSignal]]] = [
            (
                float(fresh.site_risk_score),
                fresh.site_risk_level,
                [
                    RiskSignal(s.code, float(s.weight), s.detail, "domain_scan")
                    for s in fresh.signals
                ],
            )
        ]
        for rep in reports:
            if is_owned(rep.domain, domain):
                candidates.append(
                    (
                        rep.site_risk_score,
                        rep.site_risk_level,
                        [RiskSignal(s["code"], float(s["weight"]), s["detail"], rep.content_id)
                         for s in rep.site_signals],
                    )
                )  # fmt: skip
        score, level, site_signals = max(candidates, key=lambda c: c[0])

        return RiskSummary(
            merchant_domain=domain,
            site_risk_score=score,
            site_risk_level=level,
            max_injection_severity=max_sev,
            injection_content_ids=tuple(injection_ids),
            signals=tuple(site_signals + signals),
            scanner_version=self.scanner_version,
        )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
