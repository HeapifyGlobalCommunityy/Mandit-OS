"""Hashing helpers for Mandit OS.

Per docs/REFERENCE.md §8:
digest(obj) -> str returns "sha256:<64-char-hex>"
"""

import hashlib
from typing import Any

from mandit.common import jcs


def digest(obj: Any) -> str:
    """Compute sha256 digest of an object.

    If obj is bytes, hashes bytes directly.
    Otherwise, canonicalizes via JCS and hashes.
    Returns format "sha256:<hex>".
    """
    if isinstance(obj, (bytes, bytearray)):
        raw = bytes(obj)
    elif isinstance(obj, str):
        raw = obj.encode("utf-8")
    else:
        raw = jcs.canonicalize(obj)

    h = hashlib.sha256(raw).hexdigest()
    return f"sha256:{h}"
