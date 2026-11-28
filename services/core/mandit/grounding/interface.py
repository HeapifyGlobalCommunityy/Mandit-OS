"""Published interface of grounding (modules/03). Only the registry part exists so far."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol


@dataclass(frozen=True)
class Merchant:
    """A row of the ``merchants`` table (modules/03 section 5)."""

    merchant_id: str
    legal_name: str
    domains: tuple[str, ...]
    upi_vpas: tuple[str, ...]
    card_acquirer_id: str | None
    categories: tuple[str, ...]
    base_url: str
    status: Literal["VERIFIED", "SUSPENDED"]
    onboarded_at: datetime


class MerchantDirectory(Protocol):
    async def get_merchant(self, merchant_id: str) -> Merchant | None: ...

    async def resolve_domain(self, domain: str) -> Merchant | None:
        """The merchant owning ``domain`` or a parent of it, whatever its status."""
        ...

    async def list_domains(self) -> list[str]:
        """Every domain of every VERIFIED merchant."""
        ...
