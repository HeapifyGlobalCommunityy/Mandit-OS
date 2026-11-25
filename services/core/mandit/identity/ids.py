from typing import Literal

from ulid import ULID


def new_id(prefix: Literal["agt", "akey", "op", "chl", "kya"]) -> str:
    if prefix not in {"agt", "akey", "op", "chl", "kya"}:
        raise ValueError("Unknown identity ID prefix")
    return f"{prefix}_{ULID()}"
