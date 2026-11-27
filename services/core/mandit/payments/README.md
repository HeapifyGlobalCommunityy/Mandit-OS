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
