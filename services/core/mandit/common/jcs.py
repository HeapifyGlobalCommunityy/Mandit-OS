"""RFC 8785 JSON Canonicalization Scheme (JCS) implementation.

Per docs/REFERENCE.md §8 and RFC 8785:
- UTF-8 representation of JSON with strict key sorting
- No whitespace outside strings (separators=(',', ':'))
"""

import json
from typing import Any


def canonicalize(obj: Any) -> bytes:
    """Canonicalize a JSON-serializable Python object to RFC 8785 canonical bytes."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
