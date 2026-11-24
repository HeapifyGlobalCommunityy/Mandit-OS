"""TLS validity probe. Behind a Protocol so tests and offline examples can use fixed results."""

from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass
from typing import Protocol


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

    Any failure (DNS, refused connection, timeout, bad certificate) is reported as invalid: the
    scanner fails closed rather than treating an unverifiable site as safe.
    """

    def __init__(self, timeout_s: float = 5.0, context: ssl.SSLContext | None = None) -> None:
        self._timeout = timeout_s
        self._ctx = context or ssl.create_default_context()

    async def probe(self, host: str, port: int = 443) -> TlsResult:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=self._ctx, server_hostname=host),
                timeout=self._timeout,
            )
        except ssl.SSLCertVerificationError as exc:
            return TlsResult(valid=False, error=f"certificate rejected: {exc.verify_message}")
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            return TlsResult(valid=False, error=f"handshake failed: {type(exc).__name__}: {exc}")
        try:
            cert = writer.get_extra_info("peercert") or {}
        finally:
            writer.close()
        return result_from_peercert(cert)


def result_from_peercert(cert: dict, now: float | None = None) -> TlsResult:  # type: ignore[type-arg]
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
            valid=False, issuer=issuer, days_to_expiry=days, error="certificate expired"
        )
    return TlsResult(valid=True, issuer=issuer, days_to_expiry=days)


class StaticTlsProbe:
    """Returns pre-set results per host. Unknown hosts fail closed."""

    def __init__(self, results: dict[str, TlsResult]) -> None:
        self._results = results

    async def probe(self, host: str, port: int = 443) -> TlsResult:
        return self._results.get(host, TlsResult(valid=False, error="no fixture for host"))
