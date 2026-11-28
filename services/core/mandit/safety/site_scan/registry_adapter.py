"""Gives the scanner its view of Team 3's merchant registry."""

from __future__ import annotations

from mandit.grounding.interface import MerchantDirectory

from .ports import RegistryMerchant


class DirectoryRegistry:
    def __init__(self, directory: MerchantDirectory) -> None:
        self._directory = directory

    async def resolve_domain(self, domain: str) -> RegistryMerchant | None:
        m = await self._directory.resolve_domain(domain)
        if m is None:
            return None
        return RegistryMerchant(m.merchant_id, m.domains, m.upi_vpas, m.status)

    async def list_domains(self) -> list[str]:
        return await self._directory.list_domains()
