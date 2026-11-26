# Scoped Payment Token Service

`services/core/mandit/tokens/` implements the Scoped Payment Token Service for Mandit OS per `docs/modules/04-policy-and-payments.md` §7 and `docs/REFERENCE.md` §6 & §9.

## Capabilities

1. **EdDSA / JWS Signed Tokens**:
   - Single-use, Ed25519-signed compact JWS with header `alg: EdDSA` and `typ: mandit-pay+jwt`.
   - Claims: `jti`, `iss`, `aud`, `proposal_id`, `mandate_id`, `decision_id`, `merchant_id`, `payee_id`, `amount_minor`, `currency`, `checkout_hash`, `rail`, `max_uses: 1`, `iat`, `exp` (10 minutes), `nonce`.
   - Never exposed or logged to the agent (INV-09).
2. **Atomic Compare-And-Set Redemption**:
   - Single-use guaranteed via `UPDATE payment_tokens SET status='REDEEMING', idem_key=:idem WHERE token_id=:jti AND status='ISSUED' ... RETURNING ...`.
   - Idempotent retries with the same `idempotency_key` return the original success response.
   - Distinct keys on already redeeming/redeemed tokens fail with `TOKEN_ALREADY_REDEEMED`.
3. **Defense in Depth**:
   - Checks decision outcome is `ALLOW` and unexpired.
   - Re-verifies agent status (`is_active`).
   - Verifies spend reservation against mandate and proposal.
   - Re-fetches checkout to catch TOCTOU cart/price tampering (`CHECKOUT_CHANGED`).
   - Database uniqueness constraint prevents multiple tokens per proposal.
4. **Endpoints**:
   - `POST /v1/payment-tokens/redeem`: Mock PSP atomic redemption.
   - `POST /v1/payment-tokens/validate`: Verification without consumption.
   - `GET /v1/payment-tokens/{token_id}`: Metadata and status only (no JWS).
   - `POST /v1/payment-tokens/{token_id}/revoke`: Administrative/orchestrator revocation.
