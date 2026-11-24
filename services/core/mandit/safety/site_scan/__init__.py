"""Web Safety Scanner (modules/02 section 6)."""

from .config import SiteScanConfig, load_config
from .domains import InvalidScanTarget
from .ports import (
    DomainReputation,
    DomainReputationStore,
    FixtureMerchantRegistry,
    FixtureReputationStore,
    MerchantRegistry,
    RegistryMerchant,
)
from .scanner import Signal, SiteScanner, SiteScanResult
from .tls import SocketTlsProbe, StaticTlsProbe, TlsProbe, TlsResult

__all__ = [
    "DomainReputation",
    "DomainReputationStore",
    "FixtureMerchantRegistry",
    "FixtureReputationStore",
    "InvalidScanTarget",
    "MerchantRegistry",
    "RegistryMerchant",
    "Signal",
    "SiteScanConfig",
    "SiteScanResult",
    "SiteScanner",
    "SocketTlsProbe",
    "StaticTlsProbe",
    "TlsProbe",
    "TlsResult",
    "load_config",
]
