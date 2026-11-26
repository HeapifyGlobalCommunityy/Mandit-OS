"""Outbound connection guard for the scanner (SSRF and DNS-rebinding defence).

The site scanner is the only part of the safety module that opens network connections (the TLS
probe). A scan target comes from a caller, so without a guard the probe is a server-side request
forgery primitive: it would connect to ``127.0.0.1``, ``169.254.169.254`` (cloud metadata) or any
internal service, on any port, and its error text would reveal whether a port is open.

Rules, applied before any connection is made:

1. The port must be in an explicit allowlist (default: 443 only).
2. The host is resolved once. **Every** resolved address must be globally routable
   (``ipaddress.is_global`` and not multicast). One private address fails the whole host, so
   a name that resolves to both a public and a private address cannot reach the private one.
3. The connection is made to the address that was checked, not to the name, so a second DNS answer
   (DNS rebinding) cannot redirect it. The original name is still sent as SNI and used for
   certificate hostname verification.

Profiles other than ``cloud`` may allow named private hosts (the Compose mock merchants under
``mock.mandit.local``) through ``private_host_suffixes``. The cloud profile must pass none.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass

from .domains import is_owned_by_any


class EgressRefused(Exception):
    """The destination is not permitted. ``code`` is a stable, coarse reason."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class EgressPolicy:
    allowed_ports: frozenset[int] = frozenset({443})
    private_host_suffixes: tuple[str, ...] = ()

    def allows_private(self, host: str) -> bool:
        return bool(self.private_host_suffixes) and is_owned_by_any(
            host, self.private_host_suffixes
        )


def is_public_address(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])  # drop an IPv6 zone id
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is loopback, not a public v6 address
    return ip.is_global and not ip.is_multicast


async def resolve_checked(host: str, port: int, policy: EgressPolicy) -> str:
    """Return one vetted IP address for ``host``; raise EgressRefused otherwise."""
    if port not in policy.allowed_ports:
        raise EgressRefused("PORT_NOT_PERMITTED")
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise EgressRefused("DNS_FAILED") from exc
    addrs = [str(info[4][0]) for info in infos]
    if not addrs:
        raise EgressRefused("DNS_FAILED")
    if not policy.allows_private(host) and not all(is_public_address(a) for a in addrs):
        raise EgressRefused("DESTINATION_NOT_PERMITTED")
    return addrs[0]
