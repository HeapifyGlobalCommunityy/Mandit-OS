# Mock PSP Service

`services/mock-psp/` implements the standalone simulated Payment Service Provider for Mandit OS per `docs/modules/04-policy-and-payments.md` §9 and `docs/REFERENCE.md` §9.4.

## Port & Base URL
- **Port:** `8200`
- **Base URL:** `http://mock-psp:8200`

## Capabilities
1. **Card Synthetic Flow**:
   - `POST /psp/v1/card/scoped-credentials`: Redeems single-use token with Mandit Core (`POST /v1/payment-tokens/redeem`) before minting scoped credential (`spc_...`).
   - `POST /psp/v1/card/authorize`: Authorizes amount $\le \text{max}$, enforces merchant, currency, and consumes single-use credential.
   - `POST /psp/v1/card/capture`: Captures amount $\le \text{authorized}$, updates state to `CAPTURED`, dispatches signed webhook.
2. **UPI Synthetic Flow**:
   - `POST /psp/v1/upi/intents`: Binds collect intent to payee VPA, amount, and expiry.
   - `POST /psp/v1/upi/intents/{id}/approve` (and `/psp/v1/upi/approve`): Transitions to `SUCCESS`, dispatches signed webhook callback.
   - `POST /psp/v1/upi/intents/{id}/decline` (and `/psp/v1/upi/decline`): Transitions to `FAILED`, dispatches signed decline webhook callback.
3. **Reconciliation & Status**:
   - `GET /psp/v1/payments/{psp_payment_id}`: Source of truth for Core reconciliation worker.
4. **Webhook Security & Discovery**:
   - Signs payloads using Ed25519 (`Mock-PSP-Signature: keyid="psp-2026-11",sig="..."`) over RFC 8785 JCS canonicalized bytes.
   - `GET /.well-known/psp-keys.json`: RFC 7517 JWK Set containing Mock PSP public key.
5. **Fault Injection**:
   - `POST /psp/v1/admin/faults`: Configures test faults (`TIMEOUT_AFTER_SUCCESS`, `DECLINE`, `DUPLICATE_WEBHOOK`, `FORGED_CALLBACK`). Protected by admin key and restricted to `test` and `demo` profiles.

## Database Schema & Migrations

The Mock PSP simulator maintains its own independent schema (`PspBase.metadata.create_all()`).

### Scoped Credential Token Uniqueness
To prevent duplicate credential provisioning against the same Mandit Core token under concurrent requests, `psp_scoped_credentials.token_id` carries a unique constraint (`unique=True`).

When running against a persistent database (e.g. PostgreSQL or a persistent container volume) migrated from an earlier simulator schema, run the following idempotent migration DDL if the constraint is not present:
```sql
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_psp_scoped_credentials_token_id
ON psp_scoped_credentials (token_id);
```
Alternatively, in development or ephemeral test environments, recreating the simulator database container automatically provisions the unique index.

### Concurrency and Single-Use Guarantees
Card authorization (`POST /psp/v1/card/authorize`) enforces single-use consumption atomically via an SQL Compare-And-Set (CAS) update:
```sql
UPDATE psp_scoped_credentials
SET status = 'CONSUMED'
WHERE credential_id = :credential_id
  AND status = 'ACTIVE'
  AND expires_at > :now
  AND merchant_id = :merchant_id
  AND currency = :currency
  AND max_amount_minor >= :amount_minor;
```
If two concurrent requests attempt to authorize using the same scoped credential, exactly one succeeds; the losing request receives `CREDENTIAL_INACTIVE` without creating a duplicate payment.
