"""Data the scanner needs from outside the safety module, behind small Protocols.

- ``MerchantRegistry``: Team 3 owns the registry; production wiring goes through
  ``mandit.grounding.interface`` once it exists. ``list_domains`` is needed for look-alike
  detection and is not yet in Team 3's published interface.
- ``DomainReputationStore``: the ``domain_reputation`` table, fixture-backed in Phase 1.

The ``Fixture*`` classes load YAML fixtures and back the tests and the offline examples.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal, Protocol

import yaml

from .domains import is_owned


@dataclass(frozen=True)
class RegistryMerchant:
    merchant_id: str
    domains: tuple[str, ...]
    upi_vpas: tuple[str, ...]
    status: Literal["VERIFIED", "SUSPENDED"]


@dataclass(frozen=True)
class DomainReputation:
    domain: str
    first_seen: date | None
    reputation: Literal["GOOD", "UNKNOWN", "BAD"]
    source: str


class MerchantRegistry(Protocol):
    async def resolve_domain(self, domain: str) -> RegistryMerchant | None:
        """The merchant owning ``domain`` or a parent of it, whatever its status."""
        ...

    async def list_domains(self) -> list[str]:
        """Every domain of every VERIFIED merchant."""
        ...


class DomainReputationStore(Protocol):
    async def get(self, domain: str) -> DomainReputation | None:
        """Reputation of ``domain`` or its closest listed parent."""
        ...


class FixtureMerchantRegistry:
    def __init__(self, merchants: list[RegistryMerchant]) -> None:
        self._merchants = merchants

    @classmethod
    def from_yaml(cls, path: Path) -> FixtureMerchantRegistry:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls(
            [
                RegistryMerchant(
                    merchant_id=m["merchant_id"],
                    domains=tuple(d.lower() for d in m["domains"]),
                    upi_vpas=tuple(v.lower() for v in m.get("payees", {}).get("upi_vpas", [])),
                    status=m.get("status", "VERIFIED"),
                )
                for m in raw.get("merchants", [])
            ]
        )

    async def resolve_domain(self, domain: str) -> RegistryMerchant | None:
        for merchant in self._merchants:
            if any(is_owned(domain, d) for d in merchant.domains):
                return merchant
        return None

    async def list_domains(self) -> list[str]:
        return [d for m in self._merchants if m.status == "VERIFIED" for d in m.domains]


class FixtureReputationStore:
    def __init__(self, rows: list[DomainReputation]) -> None:
        self._rows = {r.domain: r for r in rows}

    @classmethod
    def from_yaml(cls, path: Path) -> FixtureReputationStore:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls(
            [
                DomainReputation(
                    domain=r["domain"].lower(),
                    first_seen=r.get("first_seen"),  # YAML parses ISO dates to datetime.date
                    reputation=r["reputation"],
                    source=r.get("source", "fixture"),
                )
                for r in raw.get("domains", [])
            ]
        )

    async def get(self, domain: str) -> DomainReputation | None:
        labels = domain.split(".")
        for i in range(len(labels) - 1):  # pay.evil.example -> evil.example (never the bare TLD)
            row = self._rows.get(".".join(labels[i:]))
            if row is not None:
                return row
        return None
