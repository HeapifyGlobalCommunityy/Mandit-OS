"""Configuration and settings for Mock PSP Service.

Follows docs/REFERENCE.md §3.3 and §9.4.
"""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class PspSettings:
    """Runtime configuration for Mock PSP."""

    profile: str = os.getenv("MANDIT_PROFILE", "test")
    port: int = int(os.getenv("MOCK_PSP_PORT", "8200"))
    host: str = os.getenv("MOCK_PSP_HOST", "0.0.0.0")
    database_url: str = os.getenv("PSP_DATABASE_URL", "sqlite:///:memory:")
    core_base_url: str = os.getenv("MANDIT_CORE_URL", "http://localhost:8000")
    admin_api_key: str = os.getenv("MOCK_PSP_ADMIN_KEY", "psp_admin_secret_key_demo")
    key_id: str = "psp-2026-11"

    @property
    def allows_fault_injection(self) -> bool:
        """Fault injection is strictly restricted to test and demo profiles (REFERENCE §9.4)."""
        return self.profile.lower() in ("test", "demo")


SETTINGS = PspSettings()
