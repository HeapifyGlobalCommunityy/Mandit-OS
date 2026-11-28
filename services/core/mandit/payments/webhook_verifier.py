"""Ed25519 webhook signature verifier for Mock PSP callbacks.

Per docs/modules/04-policy-and-payments.md §8.3 and docs/REFERENCE.md §8:
- Header: Mock-PSP-Signature: keyid="<key_id>",sig="<base64url ed25519 over JCS(body)>"
- Canonicalization: RFC 8785 JSON Canonicalization Scheme (JCS).
- Separation: Uses independent webhook signing keys distinct from service-auth keys.
- Security: Strictly fails closed for missing headers, malformed signatures,
  unknown key IDs, signature mismatch, or non-JSON payloads.
"""

import json
import re
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from mandit.common import jcs
from mandit.common.crypto import b64url_decode

SIGNATURE_HEADER_RE = re.compile(r'keyid="([^"]+)",sig="([^"]+)"')


class WebhookSignatureError(Exception):
    """Raised when incoming PSP webhook signature verification fails."""

    def __init__(
        self,
        message: str,
        code: str = "WEBHOOK_SIGNATURE_INVALID",
        status_code: int = 401,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


class PspWebhookVerifier:
    """Verifies incoming PSP webhook signatures using registered Ed25519 public keys."""

    def __init__(
        self,
        trusted_keys: dict[str, ed25519.Ed25519PublicKey] | None = None,
    ) -> None:
        self._trusted_keys: dict[str, ed25519.Ed25519PublicKey] = dict(trusted_keys or {})

    def register_trusted_key(
        self,
        key_id: str,
        public_key: ed25519.Ed25519PublicKey,
    ) -> None:
        """Register a trusted Ed25519 public key for Mock PSP webhook verification."""
        if not key_id or not isinstance(key_id, str):
            raise ValueError("key_id must be a non-empty string")
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise ValueError("public_key must be an instance of ed25519.Ed25519PublicKey")
        self._trusted_keys[key_id] = public_key

    def get_trusted_key(self, key_id: str) -> ed25519.Ed25519PublicKey | None:
        """Retrieve registered public key by key_id."""
        return self._trusted_keys.get(key_id)

    def verify(
        self,
        payload: dict[str, Any] | bytes | str,
        signature_header: str | None,
    ) -> dict[str, Any]:
        """Verify the Ed25519 signature over JCS canonical bytes of the payload.

        Fails closed on any error. Returns the validated payload dictionary.
        """
        # 1. Header presence check
        if not signature_header or not signature_header.strip():
            raise WebhookSignatureError(
                "Missing Mock-PSP-Signature header",
                code="MISSING_SIGNATURE",
                status_code=401,
            )

        # 2. Header format regex match
        match = SIGNATURE_HEADER_RE.search(signature_header)
        if not match:
            raise WebhookSignatureError(
                'Malformed Mock-PSP-Signature header format; expected keyid="...",sig="..."',
                code="MALFORMED_SIGNATURE",
                status_code=401,
            )

        key_id, sig_b64 = match.groups()

        # 3. Key ID lookup (fail closed if unknown/unregistered)
        public_key = self._trusted_keys.get(key_id)
        if public_key is None:
            raise WebhookSignatureError(
                f"Untrusted or unknown webhook key ID: '{key_id}'",
                code="UNKNOWN_KEY_ID",
                status_code=401,
            )

        # 4. Payload normalization
        if isinstance(payload, bytes):
            try:
                parsed_payload = json.loads(payload.decode("utf-8"))
            except Exception as exc:
                raise WebhookSignatureError(
                    f"Malformed JSON payload bytes: {exc}",
                    code="MALFORMED_PAYLOAD",
                    status_code=400,
                ) from exc
        elif isinstance(payload, str):
            try:
                parsed_payload = json.loads(payload)
            except Exception as exc:
                raise WebhookSignatureError(
                    f"Malformed JSON payload string: {exc}",
                    code="MALFORMED_PAYLOAD",
                    status_code=400,
                ) from exc
        elif isinstance(payload, dict):
            parsed_payload = payload
        else:
            raise WebhookSignatureError(
                f"Unsupported payload type {type(payload)}; expected dict, bytes, or JSON str",
                code="INVALID_PAYLOAD_TYPE",
                status_code=400,
            )

        if not isinstance(parsed_payload, dict):
            raise WebhookSignatureError(
                "Webhook payload must be a JSON object (dict)",
                code="INVALID_PAYLOAD_TYPE",
                status_code=400,
            )

        # 5. Base64URL decode signature
        try:
            sig_bytes = b64url_decode(sig_b64)
        except Exception as exc:
            raise WebhookSignatureError(
                f"Invalid base64url signature encoding: {exc}",
                code="MALFORMED_SIGNATURE",
                status_code=401,
            ) from exc

        if len(sig_bytes) != 64:
            raise WebhookSignatureError(
                f"Invalid Ed25519 signature length: {len(sig_bytes)} bytes, expected 64",
                code="MALFORMED_SIGNATURE",
                status_code=401,
            )

        # 6. RFC 8785 JCS canonicalization
        try:
            canonical_bytes = jcs.canonicalize(parsed_payload)
        except Exception as exc:
            raise WebhookSignatureError(
                f"Payload JCS canonicalization failed: {exc}",
                code="CANONICALIZATION_FAILED",
                status_code=400,
            ) from exc

        # 7. Ed25519 signature verification
        try:
            public_key.verify(sig_bytes, canonical_bytes)
        except Exception as exc:
            raise WebhookSignatureError(
                "Webhook Ed25519 signature verification failed",
                code="SIGNATURE_MISMATCH",
                status_code=401,
            ) from exc

        return parsed_payload


# Default singleton instance (fail closed with empty key registry by default)
_DEFAULT_WEBHOOK_VERIFIER = PspWebhookVerifier()


def get_webhook_verifier() -> PspWebhookVerifier:
    """Dependency provider returning the active PspWebhookVerifier."""
    return _DEFAULT_WEBHOOK_VERIFIER


def set_webhook_verifier(verifier: PspWebhookVerifier) -> None:
    """Register the active PspWebhookVerifier for the application."""
    global _DEFAULT_WEBHOOK_VERIFIER
    _DEFAULT_WEBHOOK_VERIFIER = verifier
