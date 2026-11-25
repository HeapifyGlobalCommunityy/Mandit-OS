"""Mandit credential verification, not HTTP request authentication."""

import re
import time
from collections.abc import Collection, Mapping
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .ids import new_id
from .keys import decode_fixed
from .schemas import IdentityError

ISSUER = "https://mandit.local/kya"
AUDIENCE = "mandit-gateway"
TTL = 900
LEEWAY = 60
MAX_TOKEN_LENGTH = 16_384
REQUIRED = ("iss", "sub", "op", "aud", "scope", "cnf", "iat", "nbf", "exp", "jti")
SCOPE = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+")


def issue_kya_jwt(
    signing_key: Ed25519PrivateKey,
    *,
    kid: str,
    agent_id: str,
    operator_id: str,
    key_thumbprint: str,
    scopes: Collection[str],
    issuer: str = ISSUER,
) -> str:
    """Pass registry-derived identity and granted scopes, never client-requested grants."""
    if not all(
        isinstance(field, str) and field.strip() for field in (kid, agent_id, operator_id, issuer)
    ):
        raise IdentityError("VALIDATION_ERROR", "Missing issuer or identity")
    if isinstance(scopes, str) or not all(
        isinstance(s, str) and SCOPE.fullmatch(s) for s in scopes
    ):
        raise IdentityError("VALIDATION_ERROR", "Invalid scope")
    try:
        decode_fixed(key_thumbprint, 32)
    except ValueError as exc:
        raise IdentityError("VALIDATION_ERROR", "Invalid agent thumbprint") from exc
    now = int(time.time())
    claims = {
        "iss": issuer,
        "sub": agent_id,
        "op": operator_id,
        "aud": AUDIENCE,
        "scope": " ".join(sorted(set(scopes))),
        "cnf": {"jkt": key_thumbprint},
        "iat": now,
        "nbf": now,
        "exp": now + TTL,
        "jti": new_id("kya"),
    }
    token = jwt.encode(
        claims, signing_key, algorithm="EdDSA", headers={"typ": "kya+jwt", "kid": kid}
    )
    if len(token) > MAX_TOKEN_LENGTH:
        raise IdentityError("VALIDATION_ERROR", "Encoded KYA credential exceeds size limit")
    return token


def verify_kya_jwt(
    token: str,
    *,
    issuer_keys: Mapping[str, Ed25519PublicKey],
    expected_thumbprint: str,
    issuer: str = ISSUER,
) -> dict[str, Any]:
    """expected_thumbprint belongs to the independently resolved agent signing key."""
    try:
        if not isinstance(token, str) or len(token) > MAX_TOKEN_LENGTH:
            raise ValueError("Invalid compact token")
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "EdDSA" or header.get("typ") != "kya+jwt" or "crit" in header:
            raise ValueError("Unsupported JOSE header")
        key = issuer_keys[header["kid"]]
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Invalid issuer key type")
        claims = jwt.decode(
            token,
            key,
            algorithms=["EdDSA"],
            issuer=issuer,
            audience=AUDIENCE,
            leeway=LEEWAY,
            options={"require": list(REQUIRED), "strict_aud": True},
        )
        if not all(type(claims[field]) is int for field in ("iat", "nbf", "exp")):
            raise ValueError("Invalid NumericDate")
        if not claims["iat"] <= claims["nbf"] < claims["exp"] <= claims["iat"] + TTL:
            raise ValueError("Invalid token lifetime")
        if not all(
            isinstance(claims[field], str) and claims[field].strip()
            for field in ("sub", "op", "jti")
        ):
            raise ValueError("Invalid identity")
        scope = claims["scope"]
        if not isinstance(scope, str) or (
            scope and not all(SCOPE.fullmatch(s) for s in scope.split(" "))
        ):
            raise ValueError("Invalid scope claim")
        thumbprint = claims["cnf"]["jkt"]
        decode_fixed(thumbprint, 32)
    except (jwt.ExpiredSignatureError, jwt.ImmatureSignatureError) as exc:
        raise IdentityError("KYA_TOKEN_EXPIRED", "Credential outside validity window") from exc
    except (
        jwt.InvalidTokenError,
        KeyError,
        ValueError,
        TypeError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise IdentityError("KYA_TOKEN_INVALID", "Invalid KYA credential") from exc
    if thumbprint != expected_thumbprint:
        raise IdentityError("KEY_NOT_BOUND", "Credential not bound to this agent key")
    return claims
