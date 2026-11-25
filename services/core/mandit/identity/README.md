# identity

The crypto core implements the credential format in `docs/modules/01-identity-and-mandate.md`.

- Registration should validate the public JWK and store its RFC 7638 thumbprint. PyNaCl validates the Ed25519 point, not just its byte length. The thumbprint ignores labels such as `kid`.
- `verify_challenge` verifies the signature against the **registered agent key**. The caller must look up the stored nonce, check its expiry, and atomically consume it before issuing a credential.
- `issue_kya_jwt` uses the **Mandit issuer key**. Pass granted scopes from trusted registry state. The signed `cnf.jkt` identifies the agent key, not the issuer key.
- `verify_kya_jwt` checks the credential using only a local issuer key map. Supply the expected thumbprint from the independently resolved agent request key, never from the token itself. A successful return is **not** an authenticated HTTP request: status, request signature, freshness, digest, replay and scope checks still belong to the gateway pipeline.

The compact JWT may contain at most 16,384 ASCII characters, including the signature and separators. Issuance rejects larger credentials with `VALIDATION_ERROR`; verification rejects oversized input with `KYA_TOKEN_INVALID` before decoding it.

Run `python -m pytest tests/identity` from `services/core` in a Python 3.12 environment with `requirements-dev.txt` installed.
