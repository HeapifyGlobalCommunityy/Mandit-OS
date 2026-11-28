# Mandit OS — Payment Orchestrator (`mandit.payments`)

**Module Owner:** Team 4 (Policy & Payments)
**Specification:** [`docs/modules/04-policy-and-payments.md`](../../../docs/modules/04-policy-and-payments.md) §8, §9, §12
**Architecture Reference:** [`docs/REFERENCE.md`](../../../docs/REFERENCE.md) §9.4, §12.5, §13, §14

---

## 1. Overview & Responsibility

The `mandit.payments` package provides the payment execution engine, rail adapters, idempotency guards, and reconciliation state machines for Mandit OS.

The orchestrator:
1. Validates that incoming execution requests carry a valid, unexpired `ALLOW` decision from the Policy Engine.
2. Interacts with Team 1 (`mandit.mandates`) to reserve spend against the mandate.
3. Issues single-use scoped payment tokens via Team 4's `TokenService` (`mandit.tokens`), which enforces TOCTOU checkout hash validation against the merchant.
4. Executes payments across synthetic rails (Card and UPI) with the standalone Mock PSP.
5. Finalizes mandate spend (commits on success, releases on decline/failure) and emits auditable ledger events to the evidence outbox.
6. Handles asynchronous signed webhooks and reconciles pending/unknown transactions.

---

## 2. Trust Boundary & Security Invariants

- **Mandit Core vs. Mock PSP:** Mandit Core never handles raw card numbers or bank account PINs. The Mock PSP operates as an independent service in its own isolated database (`services/mock-psp/`).
- **Zero Token Leakage (INV-09):** Scoped payment tokens (`ptok_...`) and signed JWS strings are minted strictly within the database transaction and transmitted exclusively to the Mock PSP. They are never returned in agent API responses, logs, or evidence payloads.
- **Single-Use Enforcement:** Scoped payment credentials and tokens are single-use via atomic database Compare-And-Set (CAS). Replayed requests fail closed.
- **Fail-Closed Webhook Verification:** PSP webhooks must carry a valid `Mock-PSP-Signature` header (Ed25519 over RFC 8785 canonical JSON bytes) verified against Mock PSP public keys. Furthermore, Core never trusts a webhook alone; it confirms the payment status via the PSP status API (`GET /psp/v1/payments/{id}`) before changing state.
- **Strictly Simulated Rails:** No real payment rails or credentials exist in Phase 1. All synthetic execution is performed via the Mock PSP simulator.

---

## 3. Rail Execution Models

### Card Rail (Synchronous)
1. **Scoped Credential Creation:** Orchestrator calls `POST /psp/v1/card/scoped-credentials` with the single-use JWS token. Mock PSP redeems the token against Core (`POST /v1/payment-tokens/redeem`) under authenticated service credentials before minting a scoped credential (`spc_...`).
2. **Authorization:** Orchestrator calls `POST /psp/v1/card/authorize`, which atomically consumes the scoped credential via SQL CAS (`status = 'ACTIVE' -> 'CONSUMED'`).
3. **Capture:** Orchestrator calls `POST /psp/v1/card/capture` up to the authorized amount, transitioning the payment to `CAPTURED`.
4. **Finalization:** Core commits mandate spend, marks token `REDEEMED`, marks payment `CAPTURED`, notifies merchant, and emits `PAYMENT_RESULT`.

### UPI Rail (Asynchronous Collect Intent)
1. **Intent Creation:** Orchestrator calls `POST /psp/v1/upi/intents` with payee VPA and amount. Mock PSP redeems the token, creates intent `upi_intent_...`, and returns `status = 'PENDING'`.
2. **Payment Creation:** Core persists payment with `status = 'PENDING'`.
3. **Customer Approval:** Simulated payer approves or declines in their banking app (`POST /psp/v1/upi/intents/{id}/approve` or `decline`).
4. **Callback & Verification:** Mock PSP sends a signed webhook callback (`payment.captured` or `payment.failed`). Core verifies the signature, confirms status with Mock PSP, transitions payment to `SUCCESS`, `FAILED`, or `EXPIRED`, and commits or releases mandate spend.

---

## 4. Dependencies & Cross-Team Interfaces

| Service | Module / Team | Protocol | Role in Payment Execution |
| :--- | :--- | :--- | :--- |
| **Policy Engine** | `mandit.policy` (T4) | `DecisionProvider` | Source of truth for `ALLOW` decisions. Rejects `BLOCK`, `RETRIEVE_MORE`, and unconfirmed `STEP_UP`. |
| **Confirmation** | `mandit.confirmation` (T4) | In-process | Manages user confirmation responses that satisfy `STEP_UP`. |
| **Token Service** | `mandit.tokens` (T4) | `TokenService` | Mints single-use JWS payment tokens and handles Mock PSP CAS redemption. |
| **Mandates** | `mandit.mandates` (T1) | `MandateClient` | External interface for `reserve_spend()`, `commit_spend()`, and `release_spend()`. |
| **Grounding** | `mandit.grounding` (T3) | `GroundingClient` | External interface for `get_proposal()`, `refetch_checkout()` (TOCTOU), and `complete_checkout()`. |
| **Evidence** | `mandit.common.events` (T5) | `emit()` | Transactional outbox emitter for `PAYMENT_CREATED`, `PAYMENT_RESULT`, `WEBHOOK_REJECTED`, `WEBHOOK_REPLAYED`. |
| **Mock PSP** | `services/mock-psp` | `PspClient` | Independent service simulator for synthetic card and UPI rails. |

*Note:* Team 1 (`mandit.mandates`) and Team 3 (`mandit.grounding`) are currently under active development by other workstreams. Team 4 uses typed protocols and test doubles for isolated unit testing.

---

## 5. Storage & Database Migration

Mapping directly to migration `services/core/migrations/versions/0004_policy_and_payments.py`:
- `payments`: Authoritative persistent payment records.
- `psp_webhook_events`: Replay prevention store for processed PSP webhook event IDs (`psp_event_id`).
- `idempotency_keys`: Idempotent execution cache mapping `(key, route, request_hash)` to stored responses.

---

## 6. PSP Adapters & Webhook Verification (Milestone 2)

### PSP Client Adapters
- `HttpPspClient`: Communicates with standalone Mock PSP (`http://mock-psp:8200`) via HTTP POST/GET.
  - Configures explicit request (`timeout=10.0s`) and connection (`connect_timeout=5.0s`) timeouts.
  - Fail-closed error handling: raises `PspTimeoutError` on timeout, `PspConnectionError` on network errors, and `PspResponseError` on non-success HTTP status codes.
  - **No Automatic Retries:** In accordance with the contract, timeouts or network errors on state-changing payment requests are strictly never retried automatically, preventing duplicate charges.
- `InProcessPspClient`: Deterministic adapter directly calling `MockPspService` in-memory for unit and integration testing without network overhead.

### Webhook Signature Verifier (`PspWebhookVerifier`)
- **Header:** `Mock-PSP-Signature: keyid="<key_id>",sig="<b64url ed25519 over JCS(body)>"`
- **Canonicalization:** RFC 8785 JSON Canonicalization Scheme (JCS). Ordinary `json.dumps()` is strictly prohibited.
- **Key Separation:** Dedicated Ed25519 public keys registered specifically for webhook verification (`register_trusted_key(key_id, public_key)`), kept strictly separate from service-to-service authentication keys.
- **Fail-Closed Behavior:** Fails closed (401) on missing headers, malformed signatures, unknown key IDs, signature mismatches, or malformed JSON.
- **Non-Authority:** Webhook delivery is never treated as authoritative proof of payment success; Core status confirmation via `GET /psp/v1/payments/{psp_payment_id}` is mandatory before any state mutation.

---

## 7. Payment Orchestrator Engine & State Machine (Milestone 3)

Implemented in `mandit.payments.service.PaymentOrchestratorImpl` per `docs/modules/04-policy-and-payments.md §8`:

### Execution Phases & Transaction Boundaries
1. **Phase 1 (Preconditions & Preparation):**
   - Idempotency lookup on `idempotency_keys` table. Replays completed responses directly (`200 OK`) and rejects concurrent duplicate executions.
   - Rejects mismatched requests using the same idempotency key with `409 IDEMPOTENCY_KEY_MISMATCH`.
   - Validates latest decision from Policy Engine: requires `outcome == 'ALLOW'` and unexpired validity.
   - Refetches checkout from Grounding service and verifies SHA-256 hash integrity (TOCTOU protection). The decision's `proposal_hash` must equal the proposal's, and both checkout hashes must be present and equal; amount, currency, merchant and rail come from the verified checkout and proposal with no defaults, and must match the issued token.
   - Reserves spend via Team 1 `MandateClient.reserve_spend(...)`.
   - Issues single-use scoped token via Team 4 `TokenService.issue(...)` (releases spend if issuance fails).
   - Persists initial `PaymentModel` record with `status='CREATED'`.
   - Emits transactional `PAYMENT_CREATED` event into outbox.
   - **Transaction 1 Commits & Closes** before any network operations.
2. **Phase 2 (PSP Rail Operations):**
   - External PSP HTTP / In-Process calls run with **zero open database transactions**.
   - **Card Rail:** Creates scoped credential (`POST /psp/v1/card/scoped-credentials`), authorizes (`POST /psp/v1/card/authorize`), and captures (`POST /psp/v1/card/capture`).
   - **UPI Rail:** Creates UPI intent (`POST /psp/v1/upi/intents`) and transitions to `PENDING`.
   - PSP idempotency keys are `<payment_id>:cred`, `:auth` and `:upi`, so reconciliation can find a payment whose answer was lost.
3. **Phase 3 (Outcome Persistence & Settlement):**
   - **Transaction 2 Opens:**
   - **Success (CAPTURED / SUCCESS):** Commits spend via `MandateClient.commit_spend(...)`, transitions token to `REDEEMED`, marks checkout complete, and emits `PAYMENT_RESULT`.
   - **Decline / Failure (FAILED):** Only when the PSP definitely did not act: it refused the request (4xx) or the connection was never made. Releases spend reservation via `MandateClient.release_spend(...)`, marks token `FAILED`, and emits `PAYMENT_RESULT`. `failure_code` is a fixed code, never exception text.
   - **Timeout / Ambiguous Outcome (UNKNOWN):** Timeouts, connections broken off after sending, 5xx answers, unreadable 2xx answers and unexpected errors. Preserves spend reservation in `RESERVED` state (never released while rail outcome is unresolved), transitions payment and token to `UNKNOWN`, emits `PAYMENT_RESULT`. Charges are never retried while in `UNKNOWN`.
   - **Pending (PENDING - UPI):** Preserves spend reservation pending callback / webhook resolution.
   - Finalizes `idempotency_keys` record with response status and serialized body.
   - **Transaction 2 Commits & Closes**.

---

## 8. Payment API, Webhooks & Reconciliation (Milestone 4)

Implemented in `mandit.payments.api` and `mandit.payments.service`:

### API Endpoints
- `POST /v1/payments/execute`:
  - Header: `Idempotency-Key: <key>`
  - Body: `PaymentExecuteRequest(proposal_id=...)`
  - Response: `PaymentExecuteResponse` (200 OK)
  - Maps domain errors to appropriate HTTP status codes (400, 404, 409, 410).
- `GET /v1/payments/{payment_id}`:
  - Response: `PaymentStatusResponse` (200 OK, 404 if not found)
- `POST /v1/payments/webhooks/mock-psp`:
  - Header: `Mock-PSP-Signature: keyid="...",sig="..."`
  - Validates RFC 8785 JCS Ed25519 signature (fails closed with 401 on missing/invalid/unknown keys).
  - Deduplicates via `psp_webhook_events`: returns 200 OK with `WEBHOOK_REPLAYED` without duplicate state mutation.
  - Queries `GET /psp/v1/payments/{psp_payment_id}` out-of-band before changing state.
  - Settle spend: commits on confirmed `CAPTURED`/`SUCCESS`; releases on `FAILED`/`EXPIRED`.

### Reconciliation Worker (`reconcile()`)
- Scans `payments` for `CREATED`, `UNKNOWN` and `PENDING` states older than `timeout_threshold_seconds` (default: 15s). `CREATED` rows are executions whose outcome was never written.
- Queries `GET /psp/v1/payments/{psp_payment_id}` for authoritative status. Without a `psp_payment_id` (the PSP answer was lost), it looks the payment up by its PSP idempotency key (`<payment_id>:auth` or `<payment_id>:upi`). If the PSP has none and the token has expired, the payment is `FAILED` and the spend is released.
- Settles terminal outcomes (`CAPTURED`, `SUCCESS`, `FAILED`, `EXPIRED`) with corresponding spend commit/release.
- Never repeats payment charges.
- Idempotent across multiple runs.

### Production Key Provisioning Boundary
By default, `PspWebhookVerifier` starts with an empty trusted-key registry (fail-closed). Production key registration is an explicit Core Application Bootstrap / Platform configuration step during startup:
```python
from mandit.payments.webhook_verifier import get_webhook_verifier

# In Core application lifespan / startup:
verifier = get_webhook_verifier()
verifier.register_trusted_key("psp-2026-11", psp_public_key)
```
