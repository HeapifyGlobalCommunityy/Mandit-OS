"""Prefixed ULID identifiers (REFERENCE.md section 7.1).

Swap for mandit.common's helper once it exists.
"""

from __future__ import annotations

import secrets
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def ulid(now_ms: int | None = None) -> str:
    ts = int(time.time() * 1000) if now_ms is None else now_ms
    value = (ts << 80) | secrets.randbits(80)
    return "".join(_CROCKFORD[(value >> (5 * i)) & 31] for i in reversed(range(26)))


def new_id(prefix: str) -> str:
    return f"{prefix}_{ulid()}"
