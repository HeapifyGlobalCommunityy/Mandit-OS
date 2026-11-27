"""Service-to-service authentication verifier for Scoped Payment Token endpoints.

Per docs/REFERENCE.md §7.5 and §8.3:
- Protocol: Service-to-service calls use 'Authorization: Service <jwt>'.
- JWS: Signed with calling service's Ed25519 key (RFC 8037 / EdDSA).
- Claims: iss, aud, iat, exp, jti.
- Validity: at most 5 minutes (300 seconds).
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import Depends, Header, HTTPException, status

from mandit.common.crypto import b64url_decode


class ServiceAuthError(Exception):
    """Raised when service-to-service authentication fails."""

    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_401_UNAUTHORIZED,
        code: str = "UNAUTHORIZED",
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


@dataclass(frozen=True)
class ServiceAuthClaims:
    """Validated claims extracted from a verified Service <jwt>."""

    iss: str
    aud: str
    iat: int
    exp: int
    jti: str
    key_id: str


class ServiceAuthVerifier:
    """Verifies service-to-service Ed25519 JWT credentials."""

    def __init__(
        self,
        trusted_keys: dict[str, ed25519.Ed25519PublicKey] | None = None,
        default_issuer: str = "mock-psp",
        default_audience: str = "mandit-core",
        max_lifetime_seconds: int = 300,
        clock_skew_seconds: int = 5,
    ) -> None:
        self._trusted_keys: dict[str, ed25519.Ed25519PublicKey] = dict(trusted_keys or {})
        self.default_issuer = default_issuer
        self.default_audience = default_audience
        self.max_lifetime_seconds = max_lifetime_seconds
        self.clock_skew_seconds = clock_skew_seconds

    def register_trusted_key(self, key_id: str, public_key: ed25519.Ed25519PublicKey) -> None:
        """Register a trusted service public key."""
        self._trusted_keys[key_id] = public_key

    def unregister_trusted_key(self, key_id: str) -> None:
        """Remove a trusted service public key."""
        self._trusted_keys.pop(key_id, None)

    def clear_trusted_keys(self) -> None:
        """Clear all registered trusted keys (fails closed)."""
        self._trusted_keys.clear()

    @property
    def trusted_keys_count(self) -> int:
        return len(self._trusted_keys)

    def verify_service_jwt(
        self,
        auth_header: str | None,
        expected_iss: str | None = None,
        expected_aud: str | None = None,
    ) -> ServiceAuthClaims:
        """Verify an incoming 'Authorization: Service <jwt>' header.

        Strictly fail-closed: raises ServiceAuthError on any validation failure.
        """
        if not auth_header:
            raise ServiceAuthError("Missing Authorization header")

        parts = auth_header.strip().split(" ", 1)
        if len(parts) != 2:
            raise ServiceAuthError("Malformed Authorization header; expected 'Service <jwt>'")

        scheme, token_str = parts
        if scheme != "Service":
            raise ServiceAuthError(
                f"Invalid authorization scheme '{scheme}'; expected 'Service <jwt>'"
            )

        jws_parts = token_str.split(".")
        if len(jws_parts) != 3:
            raise ServiceAuthError(
                f"Malformed service JWT: expected 3 parts separated by '.', got {len(jws_parts)}"
            )

        header_b64, claims_b64, sig_b64 = jws_parts

        # 1. Parse header
        try:
            header_bytes = b64url_decode(header_b64)
            header = json.loads(header_bytes.decode("utf-8"))
        except Exception as exc:
            raise ServiceAuthError(f"Malformed service JWT header: {exc}") from exc

        if not isinstance(header, dict):
            raise ServiceAuthError("Service JWT header must be a JSON object")

        if header.get("alg") != "EdDSA":
            raise ServiceAuthError(
                f"Unsupported alg '{header.get('alg')}' in service JWT; expected 'EdDSA'"
            )

        typ = header.get("typ")
        if typ not in ("JWT", "service+jwt"):
            raise ServiceAuthError(f"Unsupported typ '{typ}' in service JWT; expected 'JWT'")

        kid = header.get("kid")
        if not kid or not isinstance(kid, str):
            raise ServiceAuthError("Missing or invalid 'kid' in service JWT header")

        if not self._trusted_keys:
            raise ServiceAuthError("No trusted service keys configured (fail-closed)")

        if kid not in self._trusted_keys:
            raise ServiceAuthError(f"Untrusted or unregistered service key ID '{kid}'")

        # 2. Verify signature
        public_key = self._trusted_keys[kid]
        signing_input = f"{header_b64}.{claims_b64}".encode("ascii")
        try:
            sig_bytes = b64url_decode(sig_b64)
            public_key.verify(sig_bytes, signing_input)
        except Exception as exc:
            raise ServiceAuthError("Invalid service JWT signature") from exc

        # 3. Parse and validate claims
        try:
            claims_bytes = b64url_decode(claims_b64)
            claims = json.loads(claims_bytes.decode("utf-8"))
        except Exception as exc:
            raise ServiceAuthError(f"Malformed service JWT payload: {exc}") from exc

        if not isinstance(claims, dict):
            raise ServiceAuthError("Service JWT payload must be a JSON object")

        target_iss = expected_iss or self.default_issuer
        target_aud = expected_aud or self.default_audience

        iss = claims.get("iss")
        if iss != target_iss:
            raise ServiceAuthError(
                f"Invalid issuer '{iss}' in service JWT; expected '{target_iss}'"
            )

        aud = claims.get("aud")
        if aud != target_aud:
            raise ServiceAuthError(
                f"Invalid audience '{aud}' in service JWT; expected '{target_aud}'"
            )

        iat = claims.get("iat")
        exp = claims.get("exp")
        if not isinstance(iat, (int, float)) or not isinstance(exp, (int, float)):
            raise ServiceAuthError("Invalid or missing 'iat' and 'exp' claims in service JWT")

        now = datetime.now(UTC).timestamp()

        # Check future issuance with clock skew allowance
        if iat > now + self.clock_skew_seconds:
            raise ServiceAuthError("Service JWT iat is in the future")

        # Check expiration
        if exp <= now:
            raise ServiceAuthError("Service JWT has expired")

        # Check maximum lifetime (REFERENCE §8.3: at most 5 minutes)
        lifetime = exp - iat
        if lifetime > self.max_lifetime_seconds:
            raise ServiceAuthError(
                f"Service JWT lifetime {lifetime:.0f}s exceeds maximum allowed duration "
                f"of {self.max_lifetime_seconds}s"
            )

        jti = claims.get("jti")
        if not jti or not isinstance(jti, str):
            raise ServiceAuthError("Missing or invalid 'jti' claim in service JWT")

        return ServiceAuthClaims(
            iss=str(iss),
            aud=str(aud),
            iat=int(iat),
            exp=int(exp),
            jti=str(jti),
            key_id=kid,
        )


# Global verifier instance (defaults to empty/fail-closed)
_SERVICE_AUTH_VERIFIER: ServiceAuthVerifier = ServiceAuthVerifier()


def get_service_auth_verifier() -> ServiceAuthVerifier:
    """Dependency provider for ServiceAuthVerifier."""
    return _SERVICE_AUTH_VERIFIER


def set_service_auth_verifier(verifier: ServiceAuthVerifier) -> None:
    """Configure the active ServiceAuthVerifier."""
    global _SERVICE_AUTH_VERIFIER
    _SERVICE_AUTH_VERIFIER = verifier


async def require_service_auth(
    authorization: str | None = Header(None, alias="Authorization"),  # noqa: B008
    verifier: ServiceAuthVerifier = Depends(get_service_auth_verifier),  # noqa: B008
) -> ServiceAuthClaims:
    """FastAPI dependency enforcing valid Service <jwt> authentication.

    Executes before request body processing and database mutation.
    """
    try:
        return verifier.verify_service_jwt(authorization)
    except ServiceAuthError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
