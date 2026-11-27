# Team 4: Policy and Payments

| Field | Value |
|---|---|
| Modules | Policy Engine; Human Confirmation; Scoped Payment Token Service; Payment Orchestrator (card and UPI adapters); Mock PSP |
| Code locations | `services/core/mandit/policy/`, `services/core/mandit/confirmation/`, `services/core/mandit/tokens/`, `services/core/mandit/payments/`, `services/mock-psp/`, `apps/console/app/confirmations/` |
| Owned tables | `decisions`, `confirmations`, `payment_tokens`, `payments`, `psp_webhook_events`, `idempotency_keys`; mock PSP has its own `scoped_credentials`, `psp_payments`, `upi_intents` |
| Commit scopes | `policy`, `confirmation`, `tokens`, `payments`, `mock-psp`, `console` |
| Document status | Baseline v0.1 |

---

## 1. Mission

Team 4 is the **transaction execution team**. It turns the outputs of identity, mandate, safety and grounding into one explainable decision, obtains human approval when required, and executes the payment so that the agent never holds a credential and no binding can be bypassed. This team owns the code where money actually moves, so it carries the strictest review requirements (see [CONTRIBUTING.md §8.5](../../CONTRIBUTING.md#85-review-requirements)).

## 2. Responsibilities

| # | Responsibility | Phase |
|---|---|---|
| R1 | Pure, versioned policy function: hard gates, step-up rules, Trust Score bands | 1 |
| R2 | Decision records with fired rules, an inputs hash and a Mandit signature | 1 |
| R3 | Input freezing through the Team 5 snapshot store before deciding | 1 |
| R4 | Bounded RETRIEVE_MORE loop (one re-verification) | 1 |
| R5 | Human confirmation: a display payload rendered by Mandit, a challenge, signed approval, expiry, invalidation on change | 1 |
| R6 | Confirmation screen in the console | 1 |
| R7 | Token issue, validate, redeem (atomic), revoke and expire | 1 |
| R8 | Payment orchestration: revalidation (TOCTOU), spend reservation, token, PSP call, reconciliation | 1 |
| R9 | Mock PSP: card-like and UPI-like flows, signed webhooks, fault injection | 1 |
| R10 | Idempotency for every mutating payment endpoint | 1 |
| R11 | Reaction to `AGENT_REVOKED` and `MANDATE_REVOKED`: revoke unredeemed tokens | 1 |

## 3. Interfaces Provided to Other Teams

```python
# services/core/mandit/policy/interface.py
class PolicyEngine(Protocol):
    version: str                                     # e.g. "policy-1.0.0"

    def decide(self, inputs: FrozenDecisionInputs) -> DecisionResult:
        """PURE FUNCTION. No I/O, no clock reads (time is in inputs), no randomness.
        Used both live and by Team 5 replay."""

class DecisionService(Protocol):
    async def evaluate(self, proposal_id: str) -> Decision: ...
    async def get(self, decision_id: str) -> Decision: ...

# services/core/mandit/tokens/interface.py
class TokenService(Protocol):
    async def issue(self, decision_id: str, reservation_id: str) -> IssuedToken: ...
    async def redeem(self, req: RedeemRequest) -> RedeemResult: ...       # atomic CAS
    async def validate(self, req: RedeemRequest) -> ValidationResult: ...
    async def revoke(self, token_id: str, reason: str) -> None: ...

# services/core/mandit/payments/interface.py
class PaymentOrchestrator(Protocol):
    async def execute(self, proposal_id: str, idempotency_key: str) -> Payment: ...
    async def get(self, payment_id: str) -> Payment: ...
```

`FrozenDecisionInputs` is a single immutable object containing:

- `evaluated_at`
- the identity result (`AgentContext` and status)
- the mandate (full signed object, version, spent and count)
- the verification report (Team 3)
- the risk summary (Team 2)
- `user_merchant_history` (count of previous purchases from this merchant)
- `confirmation` (if any)
- `attempt`

Before calling `decide`, the decision service snapshots this object through `EvidenceService.snapshot(kind="decision_inputs")`. Its digest becomes `inputs_hash`.

| Consumer | Uses |
|---|---|
| Team 2 | `evaluate` (through the `purchase.propose` orchestration), `execute` |
| Team 5 | `PolicyEngine.decide` for replay; decision, confirmation, token and payment events |
| Team 6 | Mock PSP fault injection; token redemption endpoints for replay and concurrency attacks |

## 4. Data Model

```sql
CREATE TABLE decisions (
  decision_id         TEXT PRIMARY KEY,
  proposal_id         TEXT NOT NULL,
  proposal_hash       TEXT NOT NULL,
  transaction_id      TEXT NOT NULL,
  attempt             INT  NOT NULL,
  outcome             TEXT NOT NULL CHECK (outcome IN ('ALLOW','STEP_UP','RETRIEVE_MORE','BLOCK')),
  stage               TEXT NOT NULL CHECK (stage IN ('HARD_GATE','RULE','TRUST_SCORE','CONFIRMATION')),
  rules_fired         JSONB NOT NULL,
  trust_score         NUMERIC(4,3),
  policy_version      TEXT NOT NULL,
  trust_model_version TEXT,
  inputs_snapshot_id  TEXT NOT NULL,
  inputs_hash         TEXT NOT NULL,
  confirmation_id     TEXT,
  expires_at          TIMESTAMPTZ NOT NULL,         -- ALLOW valid for 10 minutes
  signature           JSONB NOT NULL,               -- Mandit policy key over JCS(decision)
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE confirmations (
  confirmation_id     TEXT PRIMARY KEY,
  decision_id         TEXT NOT NULL,
  proposal_id         TEXT NOT NULL,
  proposal_hash       TEXT NOT NULL,
  user_id             TEXT NOT NULL,
  display             JSONB NOT NULL,
  challenge           TEXT NOT NULL,                -- sha256:JCS({display, proposal_hash, expires_at, confirmation_id})
  status              TEXT NOT NULL CHECK (status IN ('PENDING','APPROVED','REJECTED','EXPIRED','INVALIDATED')),
  response_signature  JSONB,
  responded_at        TIMESTAMPTZ,
  expires_at          TIMESTAMPTZ NOT NULL          -- 10 minutes
);

CREATE TABLE payment_tokens (
  token_id        TEXT PRIMARY KEY,
  proposal_id     TEXT NOT NULL UNIQUE,             -- one token per proposal
  decision_id     TEXT NOT NULL,
  mandate_id      TEXT NOT NULL,
  reservation_id  TEXT NOT NULL,
  merchant_id     TEXT NOT NULL,
  payee_id        TEXT NOT NULL,
  amount_minor    BIGINT NOT NULL CHECK (amount_minor > 0),
  currency        CHAR(3) NOT NULL,
  checkout_hash   TEXT NOT NULL,
  rail            TEXT NOT NULL CHECK (rail IN ('CARD','UPI')),
  status          TEXT NOT NULL CHECK (status IN
                    ('ISSUED','REDEEMING','REDEEMED','FAILED','UNKNOWN','EXPIRED','REVOKED')),
  idem_key        TEXT,
  expires_at      TIMESTAMPTZ NOT NULL,             -- 10 minutes after issue
  issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  redeemed_at     TIMESTAMPTZ
);

CREATE TABLE payments (
  payment_id      TEXT PRIMARY KEY,
  proposal_id     TEXT NOT NULL UNIQUE,
  token_id        TEXT,
  rail            TEXT NOT NULL,
  psp_payment_id  TEXT,
  status          TEXT NOT NULL,                    -- see REFERENCE §12.5
  amount_minor    BIGINT NOT NULL,
  currency        CHAR(3) NOT NULL,
  failure_code    TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE psp_webhook_events (
  psp_event_id    TEXT PRIMARY KEY,                 -- replay prevention
  payment_id      TEXT NOT NULL,
  body_hash       TEXT NOT NULL,
  received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE idempotency_keys (
  key             TEXT PRIMARY KEY,
  route           TEXT NOT NULL,
  request_hash    TEXT NOT NULL,
  response_status INT,
  response_body   JSONB,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## 5. Policy Engine

### 5.1 Algorithm

```python
SEVERITY = {"ALLOW": 0, "STEP_UP": 1, "RETRIEVE_MORE": 2, "BLOCK": 3}

def decide(x: FrozenDecisionInputs) -> DecisionResult:
    fired: list[RuleHit] = []

    # Stage 1: hard gates (REFERENCE §11.1). All evaluated, all recorded.
    for rule in HARD_GATES:                       # HG-01 .. HG-16
        hit = rule.evaluate(x)
        if hit: fired.append(hit)                 # effect = BLOCK
    if any(h.effect == "BLOCK" for h in fired):
        return DecisionResult("BLOCK", "HARD_GATE", fired, trust_score=None)

    # Stage 2: step-up rules (REFERENCE §11.2)
    for rule in STEP_UP_RULES:                    # SU-01 .. SU-07
        hit = rule.evaluate(x)
        if hit: fired.append(hit)                 # effect = STEP_UP

    # Stage 3: trust bands (advisory, after hard gates only)
    ts = x.verification.trust.score
    band = band_for(ts)                           # ALLOW | STEP_UP | RETRIEVE_MORE | BLOCK
    if band == "RETRIEVE_MORE" and x.attempt >= 2:
        band = "STEP_UP"; fired.append(RuleHit("TS-02", "RETRIEVE_MORE_EXHAUSTED", "STEP_UP"))
    elif band != "ALLOW":
        fired.append(RuleHit("TS-01", f"TRUST_SCORE_{band}", band))

    outcome = max([h.effect for h in fired] + ["ALLOW"], key=SEVERITY.get)

    # Confirmation can satisfy STEP_UP, but never BLOCK or RETRIEVE_MORE (INV-07)
    if outcome == "STEP_UP" and x.confirmation and x.confirmation.valid_for(x.proposal_hash, x.evaluated_at):
        return DecisionResult("ALLOW", "CONFIRMATION", fired, ts)

    stage = "RULE" if any(h.rule_id.startswith("SU") for h in fired) else "TRUST_SCORE"
    return DecisionResult(outcome, stage, fired, ts)
```

Rules:

- Rules live in `policy/rules/` as small classes, each with `rule_id`, `code`, `effect` and `evaluate()`.
- Adding or changing a rule bumps `policy_version` (SemVer).
- Every rule has at least one positive and one negative unit test.

### 5.2 `POST /v1/proposals/{proposal_id}/evaluate`

Request: `{}`. Inputs are gathered server-side and never accepted from the caller.

Response `200`:

```json
{
  "decision_id": "dec_01JD48...",
  "proposal_id": "prop_01JD43...",
  "proposal_hash": "sha256:7ab2...",
  "transaction_id": "txn_01JD3Y9X...",
  "attempt": 1,
  "outcome": "BLOCK",
  "stage": "HARD_GATE",
  "rules_fired": [
    { "rule_id": "HG-03", "code": "MERCHANT_NOT_ALLOWED", "effect": "BLOCK",
      "detail": { "merchant_id": "mer_fastlaptopdeals" } },
    { "rule_id": "HG-04", "code": "MERCHANT_NOT_IN_REGISTRY", "effect": "BLOCK", "detail": {} },
    { "rule_id": "HG-07", "code": "OVER_TXN_CAP", "effect": "BLOCK",
      "detail": { "amount_minor": 14500000, "cap_minor": 8000000 } },
    { "rule_id": "HG-14", "code": "INJECTION_DETECTED_HIGH", "effect": "BLOCK",
      "detail": { "content_id": "cnt_01JD41..." } }
  ],
  "trust_score": null,
  "policy_version": "policy-1.0.0",
  "trust_model_version": "trust-1.0.0",
  "inputs_hash": "sha256:41c0...",
  "confirmation_id": null,
  "expires_at": "2026-11-23T10:23:02.000Z",
  "created_at": "2026-11-23T10:13:02.000Z"
}
```

For STEP_UP, `confirmation_id` is populated. For RETRIEVE_MORE, the service immediately calls Team 3 `verify(refresh=True)` and re-evaluates with `attempt = 2`. The response returned is the **final** decision, and both decisions are recorded.

Events: `DECISION_MADE` (every attempt), `INCIDENT_LOGGED` (when the trust band is BLOCK).

## 6. Human Confirmation

### 6.1 Display payload

The display payload is built **only** from the signed checkout, the registry and the decision record. Agent-supplied text is never used. This prevents the agent from misrepresenting what the user approves.

```json
{
  "confirmation_id": "cnf_01JD49...",
  "decision_id": "dec_01JD48...",
  "proposal_hash": "sha256:7ab2...",
  "display": {
    "merchant": { "merchant_id": "mer_croma_demo", "legal_name": "Croma Demo Retail (synthetic)" },
    "items": [ { "title": "ASUS TUF A15, RTX 4060, 16 GB, 512 GB", "quantity": 1, "amount_minor": 6482966 } ],
    "tax_minor": 1166934,
    "fees_minor": 0,
    "total_minor": 7649900,
    "currency": "INR",
    "payment_method": "CARD_TOKEN",
    "delivery_eta_days": 3,
    "reasons": [
      { "code": "ABOVE_APPROVAL_THRESHOLD", "template_id": "stepup.above_threshold",
        "params": { "threshold_minor": 5000000 } },
      { "code": "PRICIER_ALTERNATIVE_CHOSEN", "template_id": "stepup.pricier_alternative",
        "params": { "difference_minor": 450000,
                    "alternative": { "title": "ASUS TUF A15, RTX 4060, 8 GB, 512 GB", "total_minor": 7199900 } } }
    ]
  },
  "challenge": "sha256:b7e3...",
  "status": "PENDING",
  "expires_at": "2026-11-23T10:23:02.000Z"
}
```

### 6.2 `POST /v1/confirmations/{confirmation_id}/respond`

Request:

```json
{
  "response": "APPROVE",
  "signature": {
    "alg": "ES256",
    "key_id": "ukey_01JD3Z0000DEMOUSERKEY0001",
    "signed_digest": "sha256:b7e3...",
    "value": "MEQCIF..."
  }
}
```

`response` is either `APPROVE` or `REJECT`.

Server checks:

1. The confirmation is `PENDING` and not expired.
2. The caller owns it.
3. `signed_digest == challenge`.
4. The signature is valid under the user's active key.
5. The proposal hash is unchanged (re-read from Team 3) and the checkout is not expired. If either has changed, the confirmation becomes `INVALIDATED` with `CONFIRMATION_PROPOSAL_CHANGED`.

On APPROVE, the policy is re-evaluated with the confirmation in the inputs, which produces a new `ALLOW` decision with stage `CONFIRMATION`.

Response `200`:

```json
{ "confirmation_id": "cnf_01JD49...", "status": "APPROVED", "decision_id": "dec_01JD4A...", "outcome": "ALLOW" }
```

Events: `CONFIRMATION_APPROVED`, `CONFIRMATION_REJECTED`, `CONFIRMATION_EXPIRED`, `CONFIRMATION_INVALIDATED`, and then `DECISION_MADE`.

### 6.3 Console screen (`/confirmations/[id]`)

- Shows the display payload exactly, with amounts formatted from minor units.
- Lists the reasons as plain-language sentences from Team 5 templates.
- Shows a side-by-side comparison when `PRICIER_ALTERNATIVE_CHOSEN` is present.
- Offers an Approve action, which signs the challenge, and a Reject action.
- Shows a countdown to expiry.
- For out-of-mandate situations, the screen does **not** offer approval. Those situations produce BLOCK, never STEP_UP. Instead it offers a link that opens a pre-filled mandate amendment (INV-07).

## 7. Scoped Payment Token

### 7.1 Token format (JWS, EdDSA, `typ: mandit-pay+jwt`)

```json
{
  "jti": "ptok_01JD4B...",
  "iss": "mandit-token-svc",
  "aud": "mock-psp",
  "proposal_id": "prop_01JD43...",
  "mandate_id": "man_01JD3Z0000LAPTOP60K000000",
  "decision_id": "dec_01JD4A...",
  "merchant_id": "mer_croma_demo",
  "payee_id": "acq_croma_001",
  "amount_minor": 7649900,
  "currency": "INR",
  "checkout_hash": "sha256:9c1e...",
  "rail": "CARD",
  "max_uses": 1,
  "iat": 1763892800,
  "exp": 1763893400,
  "nonce": "e7a1..."
}
```

The token is passed only from the token service to the mock PSP. It is never returned to the agent and never logged (INV-09).

### 7.2 Issuance (inside the orchestrator's DB transaction)

```python
async def issue(decision_id, reservation_id):
    d = await decisions.get(decision_id)
    assert d.outcome == "ALLOW" and d.expires_at > now(),   "DECISION_NOT_ALLOW / DECISION_EXPIRED"
    assert await identity.is_active(d.agent_id),            "AGENT_REVOKED"
    m = await mandates.assert_usable(d.mandate_id, ...)    # re-check at issue time
    co = await grounding.refetch_checkout(d.checkout_id)    # TOCTOU
    assert co.hash == d.checkout_hash,                      "CHECKOUT_CHANGED"
    # insert payment_tokens row (UNIQUE proposal_id prevents a second token)
```

Event: `TOKEN_ISSUED` or `TOKEN_ISSUE_REFUSED` (with code).

### 7.3 `POST /v1/payment-tokens/redeem` (called by the mock PSP; service auth)

#### Service Authentication Contract (REFERENCE §7.5, §8.3, §9.4)

The token redemption endpoint is protected by mandatory service-to-service authentication:
- **Header:** `Authorization: Service <jwt>`
- **JWT Header:** `{"alg": "EdDSA", "typ": "JWT", "kid": "<key_id>"}`
- **JWT Claims:**
  - `iss`: Calling service identifier (`"mock-psp"`)
  - `aud`: Target service identifier (`"mandit-core"`)
  - `iat`: Timestamp (UTC epoch seconds)
  - `exp`: Timestamp (UTC epoch seconds; strictly enforced maximum lifetime `exp - iat <= 300` seconds / 5 minutes)
  - `jti`: Unique token UUID
- **Key Isolation & Ownership:**
  - The Mock PSP securely generates and maintains its Ed25519 private key in `PspKeyManager` (`key_id = "psp-2026-11"`). Mandit Core never stores or has access to this private key.
  - Mandit Core verifies the incoming Ed25519 signature exclusively against a pre-registered public key corresponding to `kid`.
- **Core Bootstrap Responsibility & Dependency Injection:**
  - `services/core` is a modular monolith where domain routers are assembled by the root application / integration owner.
  - Team 4 exposes the dependency-injection interface via `mandit.tokens.service_auth`:
    - `get_service_auth_verifier() -> ServiceAuthVerifier`
    - `set_service_auth_verifier(verifier: ServiceAuthVerifier) -> None`
    - `ServiceAuthVerifier.register_trusted_key(key_id: str, public_key: ed25519.Ed25519PublicKey) -> None`
  - **Registration Timing:** The Core application bootstrap owner must register the trusted Mock PSP public key during application startup (e.g. within FastAPI `lifespan` or the application factory) prior to serving traffic:
    ```python
    from mandit.tokens.service_auth import get_service_auth_verifier

    # During application lifespan / startup:
    verifier = get_service_auth_verifier()
    verifier.register_trusted_key("psp-2026-11", psp_ed25519_public_key)
    ```
  - **Testing vs. Production:** FastAPI `app.dependency_overrides` is strictly reserved for test suites. Production bootstrap must use the verifier interface directly.
  - **Fail-Closed Guarantee:** By default, `_SERVICE_AUTH_VERIFIER` contains an empty key registry. If Core is started without registering a trusted key, all `/redeem` requests fail closed with `401 UNAUTHORIZED` (`detail={"code": "UNAUTHORIZED", "message": "No trusted service keys configured (fail-closed)"}`).
- **Replay Scope & Payment-Token CAS Guarantee:**
  - The `Service <jwt>` authenticates the *calling service identity* and has a maximum lifetime of 300 seconds.
  - **No request-level JWT replay protection:** The same service JWT can authenticate multiple redemption calls within its 300-second window.
  - **Single-use guarantee is enforced at the database level:** Individual payment tokens are strictly single-use via atomic compare-and-set (`PaymentTokenModel.status == 'ISSUED' -> 'REDEEMING'`). Replayed attempts to redeem an already consumed token return `409 Conflict (TOKEN_ALREADY_REDEEMED)`.

Request:

```json
{
  "token": "eyJhbGciOiJFZERTQSIs...",
  "merchant_id": "mer_croma_demo",
  "payee_id": "acq_croma_001",
  "amount_minor": 7649900,
  "currency": "INR",
  "checkout_hash": "sha256:9c1e...",
  "idempotency_key": "idem_9f2c..."
}
```

Atomic redemption:

```sql
UPDATE payment_tokens
   SET status = 'REDEEMING', idem_key = :idem
 WHERE token_id = :jti AND status = 'ISSUED' AND expires_at > now()
   AND merchant_id = :merchant_id AND payee_id = :payee_id
   AND amount_minor = :amount AND currency = :currency AND checkout_hash = :checkout_hash
RETURNING token_id, proposal_id;
```

If no row is returned: when the existing row has `idem_key == :idem` and status `REDEEMING` or `REDEEMED`, return the original result (an idempotent retry). Otherwise, diagnose and reject.

Response `200`:

```json
{ "token_id": "ptok_01JD4B...", "result": "ACCEPTED", "status": "REDEEMING" }
```

Rejection `409` or `410`: `TOKEN_ALREADY_REDEEMED`, `TOKEN_EXPIRED`, `TOKEN_REVOKED`, `TOKEN_MERCHANT_MISMATCH`, `TOKEN_PAYEE_MISMATCH`, `TOKEN_AMOUNT_MISMATCH`, `TOKEN_CURRENCY_MISMATCH`, `TOKEN_CHECKOUT_MISMATCH`, `TOKEN_SIGNATURE_INVALID`.

Events: `TOKEN_REDEEMED` (on the PSP result) or `TOKEN_REDEMPTION_REJECTED`.

`POST /v1/payment-tokens/validate` takes the same body and performs the same checks without consuming the token. `GET /v1/payment-tokens/{token_id}` returns metadata and status, never the JWS.

## 8. Payment Orchestrator

### 8.1 `POST /v1/payments/execute`

Headers: `Idempotency-Key: <sha256(proposal_id)>`.

Request: `{ "proposal_id": "prop_01JD43..." }`

Sequence:

```
1. idempotency check (same key + same body → return stored response)
2. load latest decision for proposal; require ALLOW, unexpired          → DECISION_NOT_ALLOW
3. BEGIN
     reservation = mandates.reserve_spend(mandate, proposal, amount)     → OVER_TOTAL_CAP
     token = tokens.issue(decision, reservation)                          → TOKEN_ISSUE_REFUSED(code)
     insert payments(status=CREATED)
     emit TOKEN_ISSUED, PAYMENT_CREATED  (same transaction / outbox)
   COMMIT
4. rail adapter:
     CARD: psp.create_scoped_credential(token) → psp.authorize → psp.capture
     UPI : psp.create_intent(token) → await callback (PENDING → SUCCESS/FAILED/EXPIRED)
5. on success: mandates.commit_spend; tokens→REDEEMED; payments→CAPTURED/SUCCESS;
               merchant.complete_checkout; emit PAYMENT_RESULT
   on decline: mandates.release_spend; tokens→FAILED; payments→FAILED; emit PAYMENT_RESULT
   on timeout: tokens→UNKNOWN; payments→UNKNOWN; schedule reconciliation; DO NOT retry charge
```

Response `200`:

```json
{
  "payment_id": "pay_01JD4C...",
  "proposal_id": "prop_01JD43...",
  "rail": "CARD",
  "status": "CAPTURED",
  "amount_minor": 7649900,
  "currency": "INR",
  "merchant_id": "mer_croma_demo",
  "receipt": { "transaction_id": "txn_01JD3Y9X...", "evidence_url": "/v1/evidence/txn_01JD3Y9X..." }
}
```

### 8.2 Reconciliation (worker)

Every 30 seconds, the worker selects payments in `UNKNOWN` or `PENDING` older than 15 seconds and queries `GET /psp/v1/payments/{psp_payment_id}`. It then moves them to a terminal state and commits or releases the spend. After 10 minutes without resolution, it raises `INCIDENT_LOGGED` with `RECONCILIATION_TIMEOUT`. **A charge is never retried while a payment is `UNKNOWN`.**

### 8.3 Webhooks: `POST /v1/payments/webhooks/mock-psp`

Headers: `Mock-PSP-Signature: keyid="psp-2026-11",sig="<base64url ed25519 over JCS(body)>"`

Body:

```json
{
  "psp_event_id": "pspevt_01JD4D...",
  "type": "payment.captured",
  "psp_payment_id": "psp_01JD4E...",
  "payment_ref": "pay_01JD4C...",
  "amount_minor": 7649900,
  "currency": "INR",
  "status": "CAPTURED",
  "occurred_at": "2026-11-23T10:14:05.000Z"
}
```

Handling:

1. Verify the signature. If it fails, reject with `WEBHOOK_SIGNATURE_INVALID` and emit `WEBHOOK_REJECTED`.
2. Insert `psp_event_id`. A duplicate returns `200` with no effect and emits `WEBHOOK_REPLAYED`.
3. **Confirm the status through the PSP status API before** changing state. A webhook alone is never trusted.

## 9. Mock PSP

A separate service with its own database and keys. Card and UPI semantics follow the PRD (Section 17).

### 9.1 Card-like flow

| Endpoint | Request | Response | Notes |
|---|---|---|---|
| `POST /psp/v1/card/scoped-credentials` | `{ "mandit_token", "merchant_id", "max_amount_minor", "currency", "expires_at" }` | `201 { "credential_id": "spc_...", "status": "ACTIVE" }` | Calls Mandit `/v1/payment-tokens/redeem` first; refuses if it is rejected |
| `POST /psp/v1/card/authorize` | `{ "credential_id", "merchant_id", "amount_minor", "currency", "idempotency_key" }` | `200 { "psp_payment_id", "status": "AUTHORIZED" \| "FAILED", "decline_code" }` | Enforces seller, `amount ≤ max`, expiry and single use **independently** (defence in depth) |
| `POST /psp/v1/card/capture` | `{ "psp_payment_id", "amount_minor" }` | `200 { "status": "CAPTURED" }` | `amount ≤ authorized`, otherwise `CAPTURE_EXCEEDS_AUTH` |
| `GET /psp/v1/payments/{id}` | n/a | `200 { "psp_payment_id", "status", "amount_minor", "currency", "merchant_id" }` | Reconciliation source |

States: `CREATED → AUTHORIZED → CAPTURED`; `FAILED`.

### 9.2 UPI-like flow

| Endpoint | Request | Response |
|---|---|---|
| `POST /psp/v1/upi/intents` | `{ "mandit_token", "payee_vpa", "amount_minor", "currency", "expires_at", "idempotency_key" }` | `201 { "intent_id", "psp_payment_id", "status": "CREATED" }`, then `PENDING` |
| `POST /psp/v1/upi/intents/{id}/approve` | `{ "payer_vpa": "demo.user@mockbank" }` | `200 { "status": "SUCCESS" }` and a signed callback |
| `POST /psp/v1/upi/intents/{id}/decline` | `{}` | `200 { "status": "FAILED" }` and a signed callback |

States: `CREATED → PENDING → SUCCESS`; `FAILED`; `EXPIRED`. The payee VPA must equal the token's `payee_id` (`CHANGED_PAYEE` otherwise).

### 9.3 Fault injection (`POST /psp/v1/admin/faults`, test and demo profiles only)

```json
{
  "scope": { "merchant_id": "mer_croma_demo" },
  "faults": [
    { "type": "TIMEOUT_AFTER_SUCCESS", "probability": 1.0, "count": 1 },
    { "type": "DUPLICATE_WEBHOOK", "count": 2 },
    { "type": "OUT_OF_ORDER_WEBHOOK" },
    { "type": "DECLINE", "decline_code": "INSUFFICIENT_FUNDS" },
    { "type": "FORGED_CALLBACK" }
  ]
}
```

## 10. Ledger Events Emitted

`DECISION_MADE`, `INCIDENT_LOGGED`, `STEP_UP_REQUESTED`, `CONFIRMATION_APPROVED`, `CONFIRMATION_REJECTED`, `CONFIRMATION_EXPIRED`, `CONFIRMATION_INVALIDATED`, `TOKEN_ISSUED`, `TOKEN_ISSUE_REFUSED`, `TOKEN_REDEEMED`, `TOKEN_REDEMPTION_REJECTED`, `TOKEN_EXPIRED`, `TOKEN_REVOKED`, `PAYMENT_CREATED`, `PAYMENT_RESULT`, `WEBHOOK_REJECTED`, `WEBHOOK_REPLAYED`.

## 11. Testing Requirements

| Test | Type | Required by |
|---|---|---|
| Each rule (HG-01 to HG-16, SU-01 to SU-07, TS-01, TS-02) has positive and negative cases | Unit | G3 |
| Property: for any generated input, `ALLOW ⇒ amount ≤ cap ∧ payee = registry payee ∧ currency = mandate ∧ all critical claims VERIFIED` | Property (Hypothesis) | G3 |
| `decide` is pure: identical inputs give identical outputs across 1,000 runs and processes | Unit | G4 |
| A confirmation cannot convert BLOCK to ALLOW | Unit | G4 |
| A confirmation is invalidated when the checkout changes | Integration | G4 |
| **200 concurrent redemptions of one token produce exactly one success** | Concurrency | G3 |
| Redemption with a single field altered (merchant, payee, amount, currency, checkout hash) is rejected with the correct code | Unit | G2 |
| Expired token rejected; a revoked mandate revokes outstanding tokens | Integration | G3 |
| `TIMEOUT_AFTER_SUCCESS` leads to `UNKNOWN`, then reconciliation to `CAPTURED`, with exactly one charge at the PSP | Fault injection | G4 |
| Duplicate and forged webhooks have no effect | Fault injection | G4 |
| TOCTOU: a flaky merchant changes the price after the decision, and the token is refused with `CHECKOUT_CHANGED` | Integration | G4 |

## 12. Milestones

| Week | Deliverable |
|---|---|
| 1–2 | Design note; `decision.v1`, `confirmation.v1`, `payment-token.v1` and `payment.v1` schemas; `PolicyEngine` stub returning ALLOW |
| 3–4 | Mock PSP card flow; token issue and atomic redeem; orchestrator happy path (G2) |
| 5 | Hard gates; decision records; frozen inputs |
| 6 | Step-up rules; token binding checks; TOCTOU (G3) |
| 7 | Confirmation service and screen; Trust Score bands; RETRIEVE_MORE |
| 8 | UPI flow; reconciliation; webhooks; fault injection (G4) |
| 9 | Concurrency and fault-injection hardening |

## 13. Areas for Improvement (Phase 2)

| # | Improvement | Rationale |
|---|---|---|
| I-4.1 | Move rules to **Cedar** (or OPA/Rego) with static analysis, for example proving that no policy allows `payee ≠ registry payee` | Analysable, auditable policies |
| I-4.2 | A learned risk model contributing a signal that can only **escalate** (toward STEP_UP or BLOCK), with its own version | Uses ML signals without letting them approve payments |
| I-4.3 | Agent behaviour fingerprinting (tool-call order, merchant categories, spend range, time of day) | Detects compromised but authenticated agents |
| I-4.4 | Rolling-window cumulative caps and split-transaction (salami) detection | Prevents threshold evasion |
| I-4.5 | Merchant-initiated charge flow: the orchestrator hands a scoped credential to the merchant, and the merchant charges the PSP | Closer to real ACP and SPT semantics |
| I-4.6 | Stripe test-mode Shared Payment Token adapter and Razorpay test-mode adapter behind the same rail interface | Demonstrates a path to real rails |
| I-4.7 | Refunds and disputes as separate capabilities, with refunds only to the original instrument | Completes the payment lifecycle; protects against refund fraud |
| I-4.8 | Trusted Surface with WebAuthn over the cart hash, and batching of low-risk confirmations to reduce approval fatigue | Phishing-resistant, meaningful approvals |
| I-4.9 | Restricted PSP keys per capability (charge, refund, payout) | Smaller blast radius |
| I-4.10 | Formal model of the token state machine (TLA+) | Proves single-use and no double charge under retries |
