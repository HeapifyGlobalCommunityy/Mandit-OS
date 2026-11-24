"""Cryptographic signing and verification for Mandit OS.

Per docs/REFERENCE.md §8 and §11:
- Service signatures: Ed25519. Detached signatures are base64url without padding.
- Signature envelope:
  {"alg": "Ed25519", "key_id": "...", "signed_digest": "sha256:...", "value": "<base64url>"}
"""
import base64
from typing import Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from mandit.common import hashing, jcs

MANDIT_POLICY_KEY_ID = "mandit-policy-2026-11"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    pad = len(data) % 4
    if pad:
        data += "=" * (4 - pad)
    return base64.urlsafe_b64decode(data.encode("ascii"))


def load_es256_public_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """Load an ECDSA P-256 public key from a JWK dict."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError(f"Invalid JWK: expected kty='EC', crv='P-256', got {jwk}")
    x_bytes = b64url_decode(jwk["x"])
    y_bytes = b64url_decode(jwk["y"])
    x_int = int.from_bytes(x_bytes, "big")
    y_int = int.from_bytes(y_bytes, "big")
    point = ec.EllipticCurvePublicNumbers(x_int, y_int, ec.SECP256R1())
    return point.public_key()


def parse_es256_signature(sig_bytes: bytes) -> bytes:
    """Convert raw 64-byte (r || s) signature to ASN.1/DER if needed."""
    if len(sig_bytes) == 64:
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:], "big")
        return encode_dss_signature(r, s)
    return sig_bytes


def verify_es256_signature(
    public_key: ec.EllipticCurvePublicKey,
    signature_envelope: dict[str, Any],
    challenge: str,
) -> bool:
    """Verify an ES256 user signature envelope over the exact challenge string.

    Per REFERENCE §7.4:
    - alg must be 'ES256'
    - signed_digest must equal challenge
    - Verified using ECDSA P-256 with single SHA-256 over challenge.encode('utf-8')
    """
    if signature_envelope.get("alg") != "ES256":
        return False
    if signature_envelope.get("signed_digest") != challenge:
        return False
    val = signature_envelope.get("value")
    if not val or not isinstance(val, str):
        return False
    try:
        sig_bytes = b64url_decode(val)
        der_sig = parse_es256_signature(sig_bytes)
        public_key.verify(der_sig, challenge.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


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
