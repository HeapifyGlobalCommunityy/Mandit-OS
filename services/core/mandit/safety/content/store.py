"""Persistence ports for content records, scan reports and raw blobs (modules/02 section 4).

Phase 1 ships an in-memory implementation used by tests, the demo profile and Team 6's harness.
The SQLAlchemy adapter over ``content_records``/``scan_reports``/``injection_findings`` (migration
0002) is tracked separately; the cloud profile refuses to start without it (``service.py``).
Raw blobs are stored apart from metadata so they can be purged without breaking hash references
(modules/02 section 9).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from ..interface import ContentRecord, InjectionSeverity, RiskLevel


@dataclass(frozen=True)
class ScanReport:
    """Row of ``scan_reports`` plus its ``injection_findings`` (modules/02 section 4)."""

    scan_id: str
    content_id: str
    domain: str
    site_risk_score: float
    site_risk_level: RiskLevel
    site_signals: tuple[dict[str, Any], ...]
    injection_detected: bool
    injection_severity: InjectionSeverity
    findings: tuple[dict[str, Any], ...]
    scanner_version: str
    detectors_enabled: tuple[str, ...]
    created_at: datetime


class ContentStore(Protocol):
    async def put(self, record: ContentRecord, report: ScanReport, raw: bytes) -> None: ...

    async def get_record(self, content_id: str) -> ContentRecord | None: ...

    async def get_report(self, scan_id: str) -> ScanReport | None: ...


class InMemoryContentStore:
    def __init__(self) -> None:
        self.records: dict[str, ContentRecord] = {}
        self.reports: dict[str, ScanReport] = {}
        self.blobs: dict[str, bytes] = {}

    async def put(self, record: ContentRecord, report: ScanReport, raw: bytes) -> None:
        if record.content_id in self.records:
            raise ValueError(f"duplicate content_id {record.content_id}")  # append-only
        self.blobs[record.blob_ref] = raw
        self.reports[report.scan_id] = report
        self.records[record.content_id] = record

    async def get_record(self, content_id: str) -> ContentRecord | None:
        return self.records.get(content_id)

    async def get_report(self, scan_id: str) -> ScanReport | None:
        return self.reports.get(scan_id)


class EventSink(Protocol):
    """Ledger event emission. Team 5's EvidenceService adapter implements this once published."""

    async def emit(self, event_type: str, transaction_id: str, payload: dict[str, Any]) -> None: ...


class InMemoryEventSink:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    async def emit(self, event_type: str, transaction_id: str, payload: dict[str, Any]) -> None:
        self.events.append((event_type, transaction_id, payload))
