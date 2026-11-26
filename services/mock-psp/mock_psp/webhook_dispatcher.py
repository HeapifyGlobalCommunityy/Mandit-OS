"""Webhook event generator, outbox persistence, and HTTP dispatcher for Mock PSP.

Implements reliable signed webhooks per docs/modules/04-policy-and-payments.md §8.3 and §9.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select

from mock_psp.crypto import PspKeyManager
from mock_psp.faults import FaultManager
from mock_psp.models import PspWebhookOutboxModel


class WebhookDispatcher:
    """Manages transactional webhook creation, signing, and dispatching to Mandit Core."""

    def __init__(
        self,
        key_manager: PspKeyManager,
        core_base_url: str = "http://localhost:8000",
        fault_manager: FaultManager | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.key_manager = key_manager
        self.core_base_url = core_base_url.rstrip("/")
        self.fault_manager = fault_manager
        self._client = http_client

    async def record_and_dispatch(
        self,
        session: Any,
        *,
        event_type: str,
        psp_payment_id: str,
        payment_ref: str | None,
        amount_minor: int,
        currency: str,
        status: str,
        merchant_id: str | None = None,
    ) -> str:
        """Create, sign, persist in outbox, and attempt delivery of webhook event."""
        now = datetime.now(UTC)
        event_id = f"pspevt_{uuid.uuid4().hex}"

        payload: dict[str, Any] = {
            "psp_event_id": event_id,
            "type": event_type,
            "psp_payment_id": psp_payment_id,
            "payment_ref": payment_ref,
            "amount_minor": amount_minor,
            "currency": currency,
            "status": status,
            "occurred_at": now.isoformat(),
        }

        # Check for FORGED_CALLBACK fault
        is_forged = False
        if self.fault_manager is not None:
            fault = self.fault_manager.get_fault("FORGED_CALLBACK", merchant_id)
            if fault is not None:
                is_forged = True

        sig_header = self.key_manager.sign_webhook_payload(payload)
        if is_forged:
            sig_header = sig_header[:-5] + "AAAAA"

        # Persist to webhook outbox
        outbox_entry = PspWebhookOutboxModel(
            event_id=event_id,
            event_type=event_type,
            psp_payment_id=psp_payment_id,
            payment_ref=payment_ref,
            payload=payload,
            signature_header=sig_header,
            status="PENDING",
            attempts=0,
            created_at=now,
            delivered_at=None,
        )

        if session is not None and hasattr(session, "add"):
            session.add(outbox_entry)
            if hasattr(session, "flush"):
                fl = session.flush()
                if hasattr(fl, "__await__"):
                    await fl

        # Check for DUPLICATE_WEBHOOK fault
        repeat_count = 1
        if self.fault_manager is not None:
            fault = self.fault_manager.get_fault("DUPLICATE_WEBHOOK", merchant_id)
            if fault is not None:
                repeat_count = fault.get("count", 2)

        # Dispatch HTTP POST to Mandit Core
        await self._dispatch_http(outbox_entry, repeat_count=repeat_count)
        return event_id

    async def _dispatch_http(
        self,
        entry: PspWebhookOutboxModel,
        repeat_count: int = 1,
    ) -> None:
        url = f"{self.core_base_url}/v1/payments/webhooks/mock-psp"
        headers = {
            "Content-Type": "application/json",
            "Mock-PSP-Signature": entry.signature_header,
        }

        for _ in range(repeat_count):
            try:
                entry.attempts += 1
                if self._client is not None:
                    resp = await self._client.post(url, json=entry.payload, headers=headers)
                else:
                    async with httpx.AsyncClient(timeout=5.0) as client:
                        resp = await client.post(url, json=entry.payload, headers=headers)

                if resp.status_code in (200, 202):
                    entry.status = "DELIVERED"
                    entry.delivered_at = datetime.now(UTC)
                else:
                    entry.status = "FAILED"
            except Exception:
                # Keep status as PENDING / FAILED for retry worker
                entry.status = "FAILED"

    async def retry_pending_webhooks(self, session: Any) -> int:
        """Retry delivery for pending or failed webhook outbox items."""
        if session is None or not hasattr(session, "execute"):
            return 0

        stmt = select(PspWebhookOutboxModel).where(
            PspWebhookOutboxModel.status.in_(["PENDING", "FAILED"])
        )
        res = await session.execute(stmt)
        entries = res.scalars().all()
        delivered = 0

        for entry in entries:
            await self._dispatch_http(entry)
            if entry.status == "DELIVERED":
                delivered += 1

        return delivered
