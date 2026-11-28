"""Loads the versioned site-scan configuration (safety/config/site-scan-<version>.yaml)."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
DEFAULT_CONFIG_PATH = CONFIG_DIR / "site-scan-1.0.0.yaml"
FIXTURES_DIR = (
    CONFIG_DIR.parent / "fixtures" / "site_scan"
)  # synthetic registry, reputation, examples

SIGNAL_CODES = (
    "DOMAIN_NOT_IN_REGISTRY",
    "DOMAIN_LOOKALIKE",
    "DOMAIN_NEW",
    "DOMAIN_REPUTATION_BAD",
    "TLS_INVALID",
    "NO_TLS",
    "CHECKOUT_PAYEE_MISMATCH",
    "EXTERNAL_PAYMENT_IFRAME",
    "SUSPICIOUS_SCRIPT",
    "DRIP_PRICING",
)


@dataclass(frozen=True)
class SignalConfig:
    weight: Decimal
    enabled: bool


@dataclass(frozen=True)
class SiteScanConfig:
    scanner_version: str
    medium_threshold: Decimal
    high_threshold: Decimal
    max_edit_distance: int
    min_brand_label_length: int
    domain_new_days: int
    payment_processor_domains: tuple[str, ...]
    signals: dict[str, SignalConfig]

    @property
    def enabled_signals(self) -> frozenset[str]:
        return frozenset(code for code, sig in self.signals.items() if sig.enabled)


def _decimal(value: Any, field: str) -> Decimal:
    # str() first so 0.1 in YAML becomes Decimal("0.1"), not the binary float.
    try:
        result = Decimal(str(value))
    except Exception as exc:  # noqa: BLE001 - re-raised with context
        raise ValueError(f"{field} is not a number: {value!r}") from exc
    if not Decimal(0) <= result <= Decimal(1):
        raise ValueError(f"{field} must be between 0 and 1, got {result}")
    return result


def parse_config(raw: dict[str, Any]) -> SiteScanConfig:
    signals_raw = raw.get("signals") or {}
    unknown = set(signals_raw) - set(SIGNAL_CODES)
    missing = set(SIGNAL_CODES) - set(signals_raw)
    if unknown or missing:
        raise ValueError(
            f"signal set mismatch: unknown={sorted(unknown)} missing={sorted(missing)}"
        )

    signals = {
        code: SignalConfig(
            weight=_decimal(cfg["weight"], f"signals.{code}.weight"),
            enabled=bool(cfg.get("enabled", True)),
        )
        for code, cfg in signals_raw.items()
    }
    medium = _decimal(raw["thresholds"]["medium"], "thresholds.medium")
    high = _decimal(raw["thresholds"]["high"], "thresholds.high")
    if medium >= high:
        raise ValueError("thresholds.medium must be below thresholds.high")

    return SiteScanConfig(
        scanner_version=str(raw["scanner_version"]),
        medium_threshold=medium,
        high_threshold=high,
        max_edit_distance=int(raw["lookalike"]["max_edit_distance"]),
        min_brand_label_length=int(raw["lookalike"]["min_brand_label_length"]),
        domain_new_days=int(raw["domain_new_days"]),
        payment_processor_domains=tuple(
            d.lower().rstrip(".") for d in raw.get("payment_processor_domains") or ()
        ),
        signals=signals,
    )


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> SiteScanConfig:
    with path.open(encoding="utf-8") as fh:
        return parse_config(yaml.safe_load(fh))
