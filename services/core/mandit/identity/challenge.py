import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .keys import decode_fixed
from .schemas import IdentityError


def challenge_message(nonce: str, agent_id: str) -> bytes:
    if not all(
        isinstance(part, str) and re.fullmatch(r"[A-Za-z0-9_-]+", part)
        for part in (nonce, agent_id)
    ):
        raise IdentityError("CHALLENGE_INVALID", "Invalid challenge components")
    return f"mandit-kya-challenge:{nonce}:{agent_id}".encode("ascii")


def verify_challenge(
    public_key: Ed25519PublicKey, *, nonce: str, agent_id: str, signature: str
) -> None:
    try:
        public_key.verify(decode_fixed(signature, 64), challenge_message(nonce, agent_id))
    except (ValueError, InvalidSignature) as exc:
        raise IdentityError("CHALLENGE_INVALID", "Invalid challenge signature") from exc
