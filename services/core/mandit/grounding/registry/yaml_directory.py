"""File-backed merchant registry for Phase 1 and local testing.

The file is the source of truth for who owns which domain and payee. Nothing here proves that
ownership: whoever edits the file asserts it. Validation is strict, because a wrong or duplicated
entry would let one merchant be paid as another.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

from ..interface import Merchant

DEFAULT_REGISTRY_PATH = Path(__file__).with_name("merchants.yaml")


def _owns(domain: str, host: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    raise ValueError(f"onboarded_at must be a date, got {value!r}")


def _parse(raw: dict[str, Any]) -> Merchant:
    status = raw["status"]
    if status not in ("VERIFIED", "SUSPENDED"):
        raise ValueError(f"{raw['merchant_id']}: invalid status {status!r}")
    domains = tuple(str(d).lower().rstrip(".") for d in raw["domains"])
    if not domains or not all(domains):
        raise ValueError(f"{raw['merchant_id']}: at least one non-empty domain is required")
    payees = raw.get("payees") or {}
    return Merchant(
        merchant_id=str(raw["merchant_id"]),
        legal_name=str(raw["legal_name"]),
        domains=domains,
        upi_vpas=tuple(str(v).lower() for v in payees.get("upi_vpas") or ()),
        card_acquirer_id=payees.get("card_acquirer_id"),
        categories=tuple(raw.get("categories") or ()),
        base_url=str(raw["base_url"]),
        status=status,
        onboarded_at=_timestamp(raw["onboarded_at"]),
    )


class YamlMerchantDirectory:
    def __init__(self, merchants: list[Merchant]) -> None:
        ids: set[str] = set()
        owners: list[tuple[str, str]] = []
        for m in merchants:
            if m.merchant_id in ids:
                raise ValueError(f"duplicate merchant_id {m.merchant_id}")
            ids.add(m.merchant_id)
            for domain in m.domains:
                for other_domain, other_id in owners:
                    if other_id != m.merchant_id and (
                        _owns(domain, other_domain) or _owns(other_domain, domain)
                    ):
                        raise ValueError(
                            f"{m.merchant_id} and {other_id} both claim {domain}/{other_domain}"
                        )
                owners.append((domain, m.merchant_id))
        self._merchants = {m.merchant_id: m for m in merchants}

    @classmethod
    def from_yaml(cls, path: Path) -> YamlMerchantDirectory:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls([_parse(m) for m in raw.get("merchants") or []])

    async def get_merchant(self, merchant_id: str) -> Merchant | None:
        return self._merchants.get(merchant_id)

    async def resolve_domain(self, domain: str) -> Merchant | None:
        host = domain.lower().rstrip(".")
        for merchant in self._merchants.values():
            if any(_owns(d, host) for d in merchant.domains):
                return merchant
        return None

    async def list_domains(self) -> list[str]:
        return [d for m in self._merchants.values() if m.status == "VERIFIED" for d in m.domains]
