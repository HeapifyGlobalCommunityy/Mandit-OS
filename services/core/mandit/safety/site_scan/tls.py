"""TLS validity probe. Behind a Protocol so tests and offline examples can use fixed results."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import time
from dataclasses import dataclass
from typing import Any, Protocol

from .netguard import EgressPolicy, EgressRefused, resolve_checked


@dataclass(frozen=True)
class TlsResult:
    valid: bool
    issuer: str | None = None
    days_to_expiry: int | None = None
    error: str | None = None


class TlsProbe(Protocol):
    async def probe(self, host: str, port: int = 443) -> TlsResult: ...


class SocketTlsProbe:
    """Real handshake with certificate and hostname verification against the system trust store.

    The destination is vetted by :mod:`netguard` first (port allowlist, public addresses only, and
    the connection pinned to the vetted address). Any failure is reported as invalid: the scanner
    fails closed rather than treating an unverifiable site as safe.

    Error strings are coarse, stable codes. Connection-level detail (refused, reset, timed out) is
    deliberately merged into ``UNREACHABLE`` so the probe cannot be used as a port scanner.
    """

    def __init__(
        self,
        timeout_s: float = 5.0,
        context: ssl.SSLContext | None = None,
        policy: EgressPolicy | None = None,
    ) -> None:
        self._timeout = timeout_s
        self._ctx = context or ssl.create_default_context()
        self._policy = policy or EgressPolicy()

    async def probe(self, host: str, port: int = 443) -> TlsResult:
        try:
            return await asyncio.wait_for(self._probe(host, port), timeout=self._timeout)
        except TimeoutError:
            return TlsResult(valid=False, error="UNREACHABLE")

    async def _probe(self, host: str, port: int) -> TlsResult:
        try:
            addr = await resolve_checked(host, port, self._policy)
        except EgressRefused as exc:
            return TlsResult(valid=False, error=exc.code)
        try:
            _, writer = await asyncio.open_connection(
                addr, port, ssl=self._ctx, server_hostname=host
            )
        except ssl.SSLCertVerificationError:
            return TlsResult(valid=False, error="CERTIFICATE_INVALID")
        except (OSError, ssl.SSLError):
            return TlsResult(valid=False, error="UNREACHABLE")
        try:
            cert = writer.get_extra_info("peercert") or {}
        finally:
            writer.close()
            with contextlib.suppress(OSError, ssl.SSLError):
                await writer.wait_closed()
        return result_from_peercert(cert)


def result_from_peercert(cert: dict[str, Any], now: float | None = None) -> TlsResult:
    """Build a TlsResult from ``getpeercert()`` output (already verified by the SSL context)."""
    issuer = None
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            if key in ("organizationName", "commonName") and issuer is None:
                issuer = value
    days = None
    if "notAfter" in cert:
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        days = int((expires - (now if now is not None else time.time())) // 86400)
    if days is not None and days < 0:
        return TlsResult(
            valid=False, issuer=issuer, days_to_expiry=days, error="CERTIFICATE_EXPIRED"
        )
    return TlsResult(valid=True, issuer=issuer, days_to_expiry=days)


class StaticTlsProbe:
    """Returns pre-set results per host. Unknown hosts fail closed."""

    def __init__(self, results: dict[str, TlsResult]) -> None:
        self._results = results

    async def probe(self, host: str, port: int = 443) -> TlsResult:
        return self._results.get(host, TlsResult(valid=False, error="UNREACHABLE"))
