import base64
import hashlib
import json
import re
from collections.abc import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from nacl.bindings import crypto_core_ed25519_is_valid_point

from .schemas import IdentityError


def base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_fixed(value: object, size: int) -> bytes:
    if (not isinstance(value, str) or len(value) != (size * 8 + 5) // 6
            or not re.fullmatch(r"[A-Za-z0-9_-]+", value)):
        raise ValueError("Invalid base64url length or alphabet")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64url(raw) != value:
        raise ValueError("Noncanonical base64url")
    return raw


def public_key_from_jwk(jwk: Mapping[str, object]) -> Ed25519PublicKey:
    if (not isinstance(jwk, Mapping) or jwk.get("kty") != "OKP"
            or jwk.get("crv") != "Ed25519" or "d" in jwk):
        raise IdentityError("VALIDATION_ERROR", "Expected a public Ed25519 JWK")
    try:
        raw = decode_fixed(jwk.get("x"), 32)
        if not crypto_core_ed25519_is_valid_point(raw):
            raise ValueError("Invalid Ed25519 group element")
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise IdentityError("VALIDATION_ERROR", "Invalid Ed25519 public key") from exc


def jwk_thumbprint(jwk: Mapping[str, object]) -> str:
    public_key = public_key_from_jwk(jwk)
    members = {"crv": "Ed25519", "kty": "OKP", "x": base64url(public_key.public_bytes_raw())}
    canonical = json.dumps(members, sort_keys=True, separators=(",", ":")).encode("ascii")
    return base64url(hashlib.sha256(canonical).digest())
