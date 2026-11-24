"""Cryptographic signing and verification for Mandit OS.

Per docs/REFERENCE.md §8 and §11:
- Service signatures: Ed25519. Detached signatures are base64url without padding.
- Signature envelope:
  {"alg": "Ed25519", "key_id": "...", "signed_digest": "sha256:...", "value": "<base64url>"}
"""
import base64
from typing import Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from mandit.common import hashing, jcs

MANDIT_POLICY_KEY_ID = "mandit-policy-2026-11"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    pad = len(data) % 4
    if pad:
        data += "=" * (4 - pad)
    return base64.urlsafe_b64decode(data.encode("ascii"))


class Ed25519Signer:
    """Ed25519 signer for policy decisions."""

    def __init__(
        self,
        private_key: ed25519.Ed25519PrivateKey | None = None,
        key_id: str = MANDIT_POLICY_KEY_ID,
    ):
        self.private_key = private_key or ed25519.Ed25519PrivateKey.generate()
        self.key_id = key_id

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self.private_key.public_key()

    def sign_payload(self, payload: dict[str, Any]) -> dict[str, str]:
        """Sign a dictionary payload using Ed25519 over its JCS bytes.

        Returns canonical envelope:
        {"alg": "Ed25519", "key_id": self.key_id, "signed_digest": digest, "value": b64url}
        """
        payload_digest = hashing.digest(payload)
        canonical_bytes = jcs.canonicalize(payload)
        sig_bytes = self.private_key.sign(canonical_bytes)
        return {
            "alg": "Ed25519",
            "key_id": self.key_id,
            "signed_digest": payload_digest,
            "value": b64url_encode(sig_bytes),
        }


def verify_envelope(
    envelope: dict[str, Any],
    payload: dict[str, Any],
    public_key: ed25519.Ed25519PublicKey,
) -> bool:
    """Verify an Ed25519 signature envelope against a payload."""
    if envelope.get("alg") != "Ed25519":
        return False

    expected_digest = hashing.digest(payload)
    if envelope.get("signed_digest") != expected_digest:
        return False

    try:
        sig_bytes = b64url_decode(envelope.get("value", ""))
        canonical_bytes = jcs.canonicalize(payload)
        public_key.verify(sig_bytes, canonical_bytes)
        return True
    except Exception:
        return False
