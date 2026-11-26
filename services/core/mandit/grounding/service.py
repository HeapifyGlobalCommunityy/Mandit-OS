"""Grounding wiring (modules/03). Only the merchant registry exists so far."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from .interface import MerchantDirectory
from .registry.yaml_directory import DEFAULT_REGISTRY_PATH, YamlMerchantDirectory


@lru_cache(maxsize=1)
def build_merchant_directory() -> MerchantDirectory:
    """Phase 1 wiring: a YAML file. The cloud profile is refused until the table adapter exists."""
    if os.environ.get("MANDIT_PROFILE", "local") == "cloud":
        raise RuntimeError("merchant registry has no production adapter yet")
    path = os.environ.get("MANDIT_REGISTRY_FILE")
    return YamlMerchantDirectory.from_yaml(Path(path) if path else DEFAULT_REGISTRY_PATH)
