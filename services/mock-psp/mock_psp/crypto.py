"""Cryptographic signing, verification, and JWKS discovery for Mock PSP.

Implements Ed25519 webhook signatures per docs/modules/04-policy-and-payments.md §8.3.
"""

import re
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from mandit.common import jcs
from mandit.common.crypto import b64url_decode, b64url_encode
from mock_psp.schemas import PspJwksResponse, PspPublicKeyJwk

SIGNATURE_HEADER_RE = re.compile(r'keyid="([^"]+)",sig="([^"]+)"')


class PspKeyManager:
    """Manages dedicated Ed25519 keypair for Mock PSP and webhook signing."""

    def __init__(
        self,
        private_key: ed25519.Ed25519PrivateKey | None = None,
        key_id: str = "psp-2026-11",
    ) -> None:
        self.private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.key_id = key_id

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self.private_key.public_key()

    def get_public_jwks(self) -> PspJwksResponse:
        """Export public key in RFC 7517 / RFC 8037 JWKS format."""
        raw_pub = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        jwk = PspPublicKeyJwk(
            kty="OKP",
            crv="Ed25519",
            kid=self.key_id,
            x=b64url_encode(raw_pub),
        )
        return PspJwksResponse(keys=[jwk])

    def sign_webhook_payload(self, body: dict[str, Any]) -> str:
        """Produce canonical Mock-PSP-Signature header over JCS body.

        Format: keyid="<key_id>",sig="<base64url ed25519 over JCS(body)>"
        """
        canonical_bytes = jcs.canonicalize(body)
        sig_bytes = self.private_key.sign(canonical_bytes)
        sig_b64 = b64url_encode(sig_bytes)
        return f'keyid="{self.key_id}",sig="{sig_b64}"'

    def verify_webhook_signature(
        self,
        body: dict[str, Any],
        signature_header: str,
    ) -> bool:
        """Verify a Mock-PSP-Signature header against the body."""
        match = SIGNATURE_HEADER_RE.search(signature_header)
        if not match:
            return False
        keyid, sig_b64 = match.groups()
        if keyid != self.key_id:
            return False

        try:
            sig_bytes = b64url_decode(sig_b64)
            canonical_bytes = jcs.canonicalize(body)
            self.public_key.verify(sig_bytes, canonical_bytes)
            return True
        except Exception:
            return False
