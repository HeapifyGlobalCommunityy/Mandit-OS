# identity

The crypto core implements the credential format in `docs/modules/01-identity-and-mandate.md`.

- Registration should validate the public JWK and store its RFC 7638 thumbprint. PyNaCl validates the Ed25519 point, not just its byte length. The thumbprint ignores labels such as `kid`.
- `verify_challenge` verifies the signature against the **registered agent key**. The caller must look up the stored nonce, check its expiry, and atomically consume it before issuing a credential.
- `issue_kya_jwt` uses the **Mandit issuer key**. Pass granted scopes from trusted registry state. The signed `cnf.jkt` identifies the agent key, not the issuer key.
- `verify_kya_jwt` checks the credential using only a local issuer key map. Supply the expected thumbprint from the independently resolved agent request key, never from the token itself. A successful return is **not** an authenticated HTTP request: status, request signature, freshness, digest, replay and scope checks still belong to the gateway pipeline.

The compact JWT may contain at most 16,384 ASCII characters, including the signature and separators. Issuance rejects larger credentials with `VALIDATION_ERROR`; verification rejects oversized input with `KYA_TOKEN_INVALID` before decoding it.

## Status

| Piece | Status |
|---|---|
| Ed25519 JWK validation and RFC 7638 thumbprint (`keys.py`) | Implemented |
| Challenge message and signature check (`challenge.py`) | Implemented; storage, expiry and single use are **Planned** |
| KYA JWT issue and verify (`kya_jwt.py`) | Implemented |
| `AgentContext`, `IdentityError`, `IdentityService` (`schemas.py`, `interface.py`) | Published; no service implementation yet |
| Registration, challenge and token endpoints; RFC 9421 `verify_request`; nonce store; revocation | **Planned** (later branches) |

## Tests

From the repository root, in a Python 3.12 environment with `requirements-dev.txt` installed:

```bash
python -m pytest services/core/tests/identity
```

`test_redteam_impersonation.py` replays the T2 corpus cases in `redteam/corpus/impersonation/`
(`ATK-IMP-001` to `ATK-IMP-006`) against this code. Their gateway-level steps run once the
gateway and the red-team harness exist.
