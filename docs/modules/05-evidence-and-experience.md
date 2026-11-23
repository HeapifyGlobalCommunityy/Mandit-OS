# Team 5: Evidence and Experience

| Field | Value |
|---|---|
| Modules | Evidence Ledger; transactions; snapshots; deterministic replay; evidence-aware explanations; audit dashboard; evidence bundle export |
| Code locations | `services/core/mandit/evidence/`, `services/core/mandit/common/events.py` (shared, maintained by Team 5), `apps/console/app/audit/` |
| Owned tables | `transactions`, `ledger_events`, `ledger_payloads`, `snapshots`, `replays`, `explanations`, `event_outbox` |
| Commit scopes | `evidence`, `console` |
| Document status | Baseline v0.1 |

---

## 1. Mission

Team 5 makes every decision **provable and understandable**. The Evidence Ledger links the user's instruction, the agent identity, the content seen, the verified facts, the policy decision, the token and the payment result into one tamper-evident chain. Replay reproduces any decision from frozen inputs. Explanations tell the user, in plain language, what happened and why.

> **Start early.** Every other team emits events from their first pull request. The ledger interface, the event envelope and a working in-memory (or simple Postgres) implementation must be on `develop` by the Week 2 gate. Integration then grows incrementally. Waiting until other modules are finished is explicitly ruled out.

## 2. Responsibilities

| # | Responsibility | Phase |
|---|---|---|
| R1 | Event envelope, event-emission client (`common.events`), schema validation per event type | 1 (Week 1–2) |
| R2 | Append-only, hash-chained ledger with per-event signatures | 1 |
| R3 | Database-level append-only enforcement (grants and triggers) | 1 |
| R4 | Transactional outbox, so that events commit atomically with the decisions they describe | 1 |
| R5 | Transactions resource (correlation root) | 1 |
| R6 | Snapshot store for frozen inputs (mandate, verification, risk, identity, policy version) | 1 |
| R7 | Chain verification (per transaction and global) | 1 |
| R8 | Deterministic replay using Team 4's pure `decide()` | 1 |
| R9 | Template-based explanations generated only from decision records | 1 |
| R10 | Audit dashboard: transaction list, timeline, chain status, replay, explanation, bundle download | 1 |
| R11 | Evidence bundle export (JSON) | 1 |
| R12 | Maintenance of [module 05 §12](#12-ledger-event-catalogue) and the explanation template registry | 1 |

## 3. Interfaces Provided to Other Teams

```python
# services/core/mandit/common/events.py  (used by every module)
async def emit(
    session: AsyncSession,              # caller's DB session: event committed atomically with caller's write
    *,
    transaction_id: str | None,         # None only for non-transactional events (e.g. AGENT_REGISTERED)
    event_type: str,                    # must exist in the event catalogue (§12)
    producer: str,                      # module name, e.g. "policy"
    actor: Actor,                       # {"type": "AGENT"|"USER"|"SERVICE", "id": "..."}
    refs: dict[str, str],               # mandate_id, agent_id, proposal_id, decision_id, ...
    payload: dict,                      # validated against schemas/events/<event_type>.v<N>.json
) -> str: ...                           # returns event_id

# services/core/mandit/evidence/interface.py
class EvidenceService(Protocol):
    async def open_transaction(self, mandate_id: str, agent: AgentContext) -> Transaction: ...
    async def snapshot(self, session, *, transaction_id: str, kind: str, obj: dict) -> Snapshot: ...
    async def load_snapshot(self, snapshot_id: str) -> Snapshot: ...
    async def chain(self, transaction_id: str) -> list[LedgerEvent]: ...
    async def verify(self, transaction_id: str | None = None,
                     seq_range: tuple[int, int] | None = None) -> ChainVerification: ...
    async def replay(self, transaction_id: str) -> ReplayResult: ...
    async def explain(self, transaction_id: str) -> Explanation: ...
```

| Consumer | Uses |
|---|---|
| All teams | `emit`; event payload schemas |
| Team 2 | `open_transaction` (from `transaction.open`) |
| Team 4 | `snapshot(kind="decision_inputs")` before every decision |
| Team 6 | `verify` and tamper tests; `replay` fidelity metrics |

## 4. Data Model

```sql
CREATE TABLE transactions (
  transaction_id  TEXT PRIMARY KEY,
  mandate_id      TEXT NOT NULL,
  agent_id        TEXT NOT NULL,
  user_id         TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('OPEN','PAID','BLOCKED','ABANDONED','FAILED')),
  final_outcome   TEXT,
  opened_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  closed_at       TIMESTAMPTZ
);

CREATE TABLE ledger_events (
  seq             BIGINT PRIMARY KEY,               -- global, gapless, assigned under lock
  event_id        TEXT UNIQUE NOT NULL,
  transaction_id  TEXT,
  event_type      TEXT NOT NULL,
  schema_version  INT  NOT NULL,
  producer        TEXT NOT NULL,
  actor           JSONB NOT NULL,
  refs            JSONB NOT NULL,
  payload_hash    TEXT NOT NULL,
  prev_hash       TEXT NOT NULL,
  event_hash      TEXT NOT NULL UNIQUE,
  signer_key_id   TEXT NOT NULL,
  signature       TEXT NOT NULL,
  occurred_at     TIMESTAMPTZ NOT NULL
);

CREATE TABLE ledger_payloads (                      -- separable for privacy (Phase 2 crypto-shredding)
  payload_hash    TEXT PRIMARY KEY,
  payload         JSONB NOT NULL
);

CREATE TABLE snapshots (
  snapshot_id     TEXT PRIMARY KEY,
  transaction_id  TEXT NOT NULL,
  kind            TEXT NOT NULL,                    -- decision_inputs | mandate | checkout | content | verification
  digest          TEXT NOT NULL,
  body            JSONB NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE replays (
  replay_id       TEXT PRIMARY KEY,
  transaction_id  TEXT NOT NULL,
  decision_id     TEXT NOT NULL,
  policy_version  TEXT NOT NULL,
  original_outcome TEXT NOT NULL,
  replayed_outcome TEXT NOT NULL,
  match           BOOLEAN NOT NULL,
  diff            JSONB,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE event_outbox (
  outbox_id       BIGSERIAL PRIMARY KEY,
  event_draft     JSONB NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  appended_at     TIMESTAMPTZ
);
```

Append-only enforcement:

```sql
REVOKE UPDATE, DELETE, TRUNCATE ON ledger_events, ledger_payloads, snapshots FROM mandit_app;
GRANT INSERT, SELECT ON ledger_events, ledger_payloads, snapshots TO mandit_app;
CREATE TRIGGER ledger_no_mutation BEFORE UPDATE OR DELETE ON ledger_events
  FOR EACH ROW EXECUTE FUNCTION raise_immutable();
```

The tamper demonstration and tests use a separate `mandit_tamper_test` role that exists only in the test and demo profiles.

## 5. Event Envelope and Hash Chain

### 5.1 Envelope (`schemas/ledger-event.v1.json`)

```json
{
  "event_id": "evt_01JD4F...",
  "seq": 10452,
  "transaction_id": "txn_01JD3Y9X...",
  "event_type": "DECISION_MADE",
  "schema_version": 1,
  "producer": "policy",
  "actor": { "type": "SERVICE", "id": "policy" },
  "refs": {
    "mandate_id": "man_01JD3Z0000LAPTOP60K000000",
    "agent_id": "agt_01JD3Y0000SHOPPERV3000000",
    "proposal_id": "prop_01JD43...",
    "decision_id": "dec_01JD48..."
  },
  "payload": { "outcome": "BLOCK", "rules_fired": ["HG-03", "HG-04", "HG-07", "HG-14"], "policy_version": "policy-1.0.0" },
  "payload_hash": "sha256:aa01...",
  "prev_hash": "sha256:7d3f...",
  "event_hash": "sha256:c4b9...",
  "signer_key_id": "mandit-ledger-2026-11",
  "signature": "base64url...",
  "occurred_at": "2026-11-23T10:13:02.114Z"
}
```

### 5.2 Hash computation

```python
GENESIS = "sha256:" + "0" * 64

payload_hash = digest(payload)                                       # sha256 over JCS(payload)
event_hash   = digest({
    "seq": seq, "prev_hash": prev_hash, "event_id": event_id,
    "transaction_id": transaction_id, "event_type": event_type, "schema_version": schema_version,
    "producer": producer, "actor": actor, "refs": refs,
    "payload_hash": payload_hash, "occurred_at": occurred_at,
})
signature = ed25519_sign(ledger_key, event_hash)
```

Append procedure: take a Postgres advisory lock (or `SELECT ... FOR UPDATE` on a single-row `ledger_head` table), read the head, compute and insert, update the head, then commit. The chain is **global** (one sequence). Per-transaction views are filtered reads.

### 5.3 Transactional outbox

`emit()` inserts into `event_outbox` inside the caller's transaction. A worker (or an after-commit hook) appends outbox entries to the ledger in order and marks them `appended_at`. A decision row can therefore never be committed without its event, and ledger serialization never holds locks inside business transactions.

## 6. Endpoints

### 6.1 `POST /v1/transactions` (through the gateway tool `transaction.open`)

Request: `{ "mandate_id": "man_01JD3Z0000LAPTOP60K000000" }`

Response `201`:

```json
{ "transaction_id": "txn_01JD3Y9X...", "mandate_id": "man_...", "status": "OPEN", "opened_at": "..." }
```

Event: `TRANSACTION_OPENED`.

### 6.2 `GET /v1/transactions?status=&outcome=&merchant_id=&from=&to=&cursor=`

Response `200`:

```json
{
  "items": [
    { "transaction_id": "txn_...", "mandate_id": "man_...", "agent_id": "agt_...", "merchant_id": "mer_croma_demo",
      "status": "PAID", "final_outcome": "ALLOW", "amount_minor": 7649900, "currency": "INR",
      "opened_at": "...", "closed_at": "...", "event_count": 23, "chain_status": "VERIFIED" }
  ],
  "next_cursor": "..."
}
```

### 6.3 `GET /v1/evidence/{transaction_id}`

Returns `{ "transaction": {...}, "events": [envelope with payload, ...], "snapshots": [ {snapshot_id, kind, digest} ] }`, ordered by `seq`.

### 6.4 `GET /v1/evidence/{transaction_id}/verify`

Response `200`:

```json
{
  "transaction_id": "txn_...",
  "status": "VERIFIED",
  "checked_events": 23,
  "first_seq": 10430,
  "last_seq": 10475,
  "failures": []
}
```

On tampering, `status` is `TAMPERED` and `failures` lists entries such as `{ "seq": 10452, "code": "LEDGER_HASH_MISMATCH", "expected": "sha256:...", "actual": "sha256:..." }`. Codes: `LEDGER_HASH_MISMATCH`, `LEDGER_CHAIN_BROKEN` (`prev_hash` ≠ the previous `event_hash`), `LEDGER_SIGNATURE_INVALID`, `LEDGER_PAYLOAD_MISMATCH`, `LEDGER_SEQ_GAP`.

Verification of a transaction checks its events **and** the links into and out of each event in the global chain, so that an inserted or deleted event in between is detected. Event: `LEDGER_VERIFIED` or `LEDGER_TAMPER_DETECTED`.

### 6.5 `POST /v1/evidence/{transaction_id}/replay`

Request: `{ "decision_id": "dec_01JD48..." }`. Optional: defaults to every decision in the transaction.

```python
async def replay(txn_id, decision_id):
    d = await decisions.get(decision_id)
    snap = await load_snapshot(d.inputs_snapshot_id)
    assert digest(snap.body) == d.inputs_hash                 # snapshot integrity
    engine = POLICY_REGISTRY[d.policy_version]                # versioned, pure; never "latest"
    result = engine.decide(FrozenDecisionInputs.parse(snap.body))
    return compare(d, result)                                 # outcome + rules_fired must match
```

Response `200`:

```json
{
  "replay_id": "rpl_01JD4G...",
  "transaction_id": "txn_...",
  "results": [
    { "decision_id": "dec_01JD48...", "policy_version": "policy-1.0.0",
      "original_outcome": "BLOCK", "replayed_outcome": "BLOCK",
      "original_rules": ["HG-03", "HG-04", "HG-07", "HG-14"], "replayed_rules": ["HG-03", "HG-04", "HG-07", "HG-14"],
      "match": true }
  ],
  "note": "Replay re-evaluates the decision from frozen inputs. No payment is re-executed."
}
```

Event: `REPLAY_PERFORMED`, or `REPLAY_DIVERGED` with a diff when outcomes differ. A divergence is a severity-1 defect.

**Policy version retention.** Team 4 must keep every released `policy_version` importable (`policy/versions/v1_0_0.py`, and so on) so that historical decisions remain replayable.

### 6.6 `GET /v1/evidence/{transaction_id}/explanation`

Response `200`:

```json
{
  "transaction_id": "txn_...",
  "outcome": "BLOCK",
  "headline": "Payment blocked.",
  "body": [
    "The agent attempted to pay ₹1,45,000 to Fast Laptop Deals, which is not one of your approved merchants.",
    "Your approved limit for this purchase was ₹80,000.",
    "The product page contained hidden instructions directed at the AI agent. These were treated as untrusted data.",
    "The merchant is not in the verified merchant registry."
  ],
  "footer": "No payment token was issued.",
  "template_version": "explain-1.0.0",
  "sources": [ { "event_id": "evt_...", "event_type": "DECISION_MADE" } ]
}
```

### 6.7 `GET /v1/evidence/{transaction_id}/bundle`

Returns `application/json` containing:

- `bundle_version`
- the transaction
- every event with its payload
- every snapshot body
- the explanation
- the chain verification result
- the Mandit public keys needed for offline verification (`ledger`, `policy`, `token` and `kya` JWKS)

A standalone verification script, `tools/verify_bundle.py`, must be able to verify a bundle offline.

### 6.8 `POST /internal/v1/evidence/events`

For out-of-process producers (service auth). The body is the `emit()` argument set as JSON. Response `201 { "event_id", "seq" }`.

## 7. Explanations

### 7.1 Rules

1. Explanations are generated **only** from decision records, rule hits, verification reports and payment results. Agent text (`rationale_untrusted`, `summary`) is never included verbatim.
2. Each reason code in [REFERENCE Appendix B](../REFERENCE.md#appendix-b-error-and-reason-codes) maps to one template in `evidence/templates/explain-1.0.0.yaml`. A code without a template fails CI.
3. Amounts are formatted with `common.money.format_minor` in the `en-IN` locale for INR.
4. BLOCK explanations always end with "No payment token was issued." when no token exists.

### 7.2 Template example

```yaml
OVER_TXN_CAP:
  sentence: "The amount of {amount} exceeds your approved limit of {cap} for a single purchase."
  params: { amount: rules_fired.detail.amount_minor|money, cap: rules_fired.detail.cap_minor|money }
MERCHANT_NOT_ALLOWED:
  sentence: "{merchant_name} is not one of the merchants you approved."
INJECTION_DETECTED_HIGH:
  sentence: "The page the agent relied on contained hidden instructions directed at the AI agent. These were treated as untrusted data and ignored."
PRICIER_ALTERNATIVE_CHOSEN:
  sentence: "The agent chose an item that costs {difference} more than a matching option it also found."
```

Event: `EXPLANATION_GENERATED` (payload: `template_version` and the reason codes used).

## 8. Audit Dashboard (Console)

| Route | Content |
|---|---|
| `/audit` | Transaction list with filters, outcome badges and chain-status badges |
| `/audit/[transaction_id]` | Lifecycle timeline (mandate → identity → content → checkout → proposal → claims → decision → confirmation → token → payment), with each node expandable to its event payload; explanation panel; chain verification badge; **Replay** button; **Download evidence bundle** button |
| `/audit/ledger` | Global chain verification; head hash; sequence range check |

The timeline must make it obvious **where** an attack was stopped, for example by highlighting the node with the first BLOCK rule. Injection findings link to the content record and show the hidden excerpt, which is never shown to the agent.

## 9. Testing Requirements

| Test | Type | Required by |
|---|---|---|
| `emit` rejects unknown event types and payloads that violate the schema | Unit | G1 |
| Chain verifies after 10,000 appends from concurrent producers; no sequence gaps | Concurrency | G2 |
| Mutating any field of any event (payload, hash, `prev_hash`, timestamp, order) is detected (100% of the tamper corpus) | Property and corpus | G4 |
| Deleting or inserting an event is detected | Unit | G4 |
| `UPDATE` and `DELETE` from the application role fail at the database level | Integration | G2 |
| Replay matches the original for every decision in the demo scenarios and the full corpus | Integration | G4 |
| Every registered reason code has a template; explanation output contains no agent free text | Unit | G4 |
| The bundle verifies offline with `tools/verify_bundle.py` | Integration | G4 |
| Audit timeline renders both demo scenarios | Playwright | G4 |

## 10. Milestones

| Week | Deliverable |
|---|---|
| 1–2 | **Envelope, `emit()`, event catalogue v1, Postgres ledger with hash chain** (G1); design note |
| 3–4 | Outbox; transactions resource; chain verification; events from Teams 1, 3 and 4 integrated (G2) |
| 5–6 | Snapshots; events from Team 2; tamper tests; minimal audit list view |
| 7 | Replay; explanations; audit timeline |
| 8 | Bundle export; offline verifier; demo polish (G4) |
| 9 | Explanation clarity study (≥ 4 of 5 readers rate it understandable); defect fixes |

## 11. Areas for Improvement (Phase 2)

| # | Improvement | Rationale |
|---|---|---|
| I-5.1 | **Signed Merkle checkpoints** every N events or every minute, signed with a separate key held in a KMS | Efficient proofs; separates the checkpoint key from the append path |
| I-5.2 | **External anchoring** of checkpoint roots (RFC 3161 timestamp authority or a public transparency log) | Detects consistent rewrites of the whole chain by an insider |
| I-5.3 | **Party receipts**: user, merchant and PSP each receive the checkpoint root covering their transaction | Independent witnesses; dispute-grade evidence |
| I-5.4 | **Crypto-shredding**: per-subject encryption of payload blobs, with erasure by key destruction while the chain still verifies | DPDP Act and GDPR erasure compatibility |
| I-5.5 | WORM object storage (Object Lock) for payload blobs | Storage-level immutability |
| I-5.6 | Dispute evidence export in a format suited to chargeback representment | The commercial use of the ledger |
| I-5.7 | Public verification endpoint for evidence bundles | Third-party verifiability |
| I-5.8 | Localised explanations (Hindi and other languages) and accessibility review | Wider user comprehension |
| I-5.9 | Inclusion proofs (Merkle audit paths) in bundles | Compact proof that an event is in the log |

---

## 12. Ledger Event Catalogue

### Rules

1. An event type must be registered here, and its payload schema committed, **in the same pull request** that first emits it. `common.events.emit()` rejects unregistered types (`EVENT_TYPE_UNKNOWN`).
2. Payloads contain **identifiers, hashes and decision data**, never secrets, private keys, full JWTs, payment tokens, raw addresses or other personal data. Large content is referenced by `content_id` or `snapshot_id`.
3. Adding an optional field is a minor change and keeps the schema version. Removing or renaming a field, or changing its type, requires a new schema version (`v2`), and the old version stays readable for replay.
4. Pull requests that add or change an event must request a review from Team 5.

### Summary by producer

| Producer (team) | Event types |
|---|---|
| `identity` (T1) | `OPERATOR_REGISTERED`, `OPERATOR_VERIFIED`, `AGENT_REGISTERED`, `AGENT_KEY_ADDED`, `AGENT_KEY_RETIRED`, `AGENT_REVOKED`, `AGENT_CREDENTIAL_ISSUED`, `AGENT_AUTH_FAILED`, `USER_KEY_REGISTERED` |
| `mandates` (T1) | `MANDATE_CREATED`, `MANDATE_REJECTED`, `MANDATE_SUPERSEDED`, `MANDATE_REVOKED`, `MANDATE_EXPIRED`, `MANDATE_EXHAUSTED`, `MANDATE_MATCH_EVALUATED`, `SPEND_RESERVED`, `SPEND_COMMITTED`, `SPEND_RELEASED` |
| `gateway`, `safety` (T2) | `TOOL_CALL_RECEIVED`, `TOOL_CALL_DENIED`, `CONTENT_SEEN`, `SITE_SCANNED`, `INJECTION_DETECTED`, `PII_IN_EGRESS` |
| `grounding` (T3) | `CHECKOUT_SNAPSHOT`, `CHECKOUT_SIGNATURE_INVALID`, `PROPOSAL_SUBMITTED`, `CLAIM_VERIFIED`, `FACT_RECORDED`, `VERIFICATION_COMPLETED`, `TRUST_SCORE_COMPUTED`, `ABSTENTION_RAISED` |
| `policy`, `confirmation`, `tokens`, `payments` (T4) | `DECISION_MADE`, `INCIDENT_LOGGED`, `STEP_UP_REQUESTED`, `CONFIRMATION_APPROVED`, `CONFIRMATION_REJECTED`, `CONFIRMATION_EXPIRED`, `CONFIRMATION_INVALIDATED`, `TOKEN_ISSUED`, `TOKEN_ISSUE_REFUSED`, `TOKEN_REDEEMED`, `TOKEN_REDEMPTION_REJECTED`, `TOKEN_EXPIRED`, `TOKEN_REVOKED`, `PAYMENT_CREATED`, `PAYMENT_RESULT`, `WEBHOOK_REJECTED`, `WEBHOOK_REPLAYED` |
| `evidence` (T5) | `TRANSACTION_OPENED`, `TRANSACTION_CLOSED`, `EXPLANATION_GENERATED`, `REPLAY_PERFORMED`, `REPLAY_DIVERGED`, `LEDGER_VERIFIED`, `LEDGER_TAMPER_DETECTED` |

### Event definitions

`refs` lists the identifiers that must be present in the envelope's `refs` object. "Txn" indicates whether `transaction_id` is required.

#### Identity and Mandate (Team 1)

| Event type | Txn | Required refs | Payload fields (v1) |
|---|---|---|---|
| `OPERATOR_REGISTERED` | No | `operator_id` | `legal_name`, `domain` |
| `OPERATOR_VERIFIED` | No | `operator_id` | `verified_by`, `method` |
| `AGENT_REGISTERED` | No | `agent_id`, `operator_id` | `key_id`, `key_thumbprint`, `scopes[]`, `version`, `model_declared` |
| `AGENT_KEY_ADDED` | No | `agent_id` | `key_id`, `key_thumbprint` |
| `AGENT_KEY_RETIRED` | No | `agent_id` | `key_id` |
| `AGENT_REVOKED` | No | `agent_id` | `reason`, `revoked_by`, `keys_revoked[]` |
| `AGENT_CREDENTIAL_ISSUED` | No | `agent_id` | `jti`, `key_id`, `scopes[]`, `expires_at` |
| `AGENT_AUTH_FAILED` | Optional | `agent_id` (if known) | `code`, `key_id`, `route`, `source_ip_hash` |
| `USER_KEY_REGISTERED` | No | `user_id` | `key_id`, `alg`, `key_thumbprint` |
| `MANDATE_CREATED` | No | `mandate_id`, `user_id`, `agent_id` | `version`, `digest`, `constraints_digest`, `expires_at`, `supersedes` |
| `MANDATE_REJECTED` | No | `user_id` | `code`, `digest` |
| `MANDATE_SUPERSEDED` | No | `mandate_id` | `old_version`, `new_version` |
| `MANDATE_REVOKED` | No | `mandate_id`, `user_id` | `version`, `reason` |
| `MANDATE_EXPIRED` | No | `mandate_id` | `version`, `expired_at` |
| `MANDATE_EXHAUSTED` | Yes | `mandate_id` | `spent_minor`, `txn_count` |
| `MANDATE_MATCH_EVALUATED` | Yes | `mandate_id`, `proposal_id` | `satisfied`, `violations[]` (codes), `signals[]`, `matcher_version` |
| `SPEND_RESERVED` | Yes | `mandate_id`, `proposal_id` | `reservation_id`, `amount_minor`, `currency`, `spent_after_minor` |
| `SPEND_COMMITTED` | Yes | `mandate_id` | `reservation_id` |
| `SPEND_RELEASED` | Yes | `mandate_id` | `reservation_id`, `reason` |

#### Safety Scanning (Team 2)

| Event type | Txn | Required refs | Payload fields (v1) |
|---|---|---|---|
| `TOOL_CALL_RECEIVED` | Yes | `agent_id`, `tool_call_id` | `tool_name`, `args_hash`, `latency_ms` |
| `TOOL_CALL_DENIED` | Yes | `agent_id`, `tool_call_id` | `tool_name`, `code`, `args_hash` |
| `CONTENT_SEEN` | Yes | `content_id`, `tool_call_id` | `source_type`, `source_url`, `domain`, `content_hash`, `classification`, `fetched_at` |
| `SITE_SCANNED` | Yes | `content_id`, `scan_id` | `domain`, `site_risk_score`, `site_risk_level`, `signals[]` (codes), `scanner_version` |
| `INJECTION_DETECTED` | Yes | `content_id`, `scan_id` | `severity`, `findings[]` (`technique`, `severity`, `targets[]`, `finding_id`), `detectors_enabled[]` |
| `PII_IN_EGRESS` | Yes | `agent_id`, `tool_call_id` | `tool_name`, `pattern_types[]` (no values) |

#### Grounding and Verification (Team 3)

| Event type | Txn | Required refs | Payload fields (v1) |
|---|---|---|---|
| `CHECKOUT_SNAPSHOT` | Yes | `checkout_id`, `merchant_id` | `checkout_hash`, `total_minor`, `currency`, `payee_id`, `expires_at`, `signature_valid`, `snapshot_id` |
| `CHECKOUT_SIGNATURE_INVALID` | Yes | `checkout_id`, `merchant_id` | `kid`, `reason` |
| `PROPOSAL_SUBMITTED` | Yes | `proposal_id`, `mandate_id`, `agent_id`, `checkout_id` | `proposal_hash`, `checkout_hash`, `stated_amount_minor`, `stated_currency`, `source_ids[]` |
| `CLAIM_VERIFIED` | Yes | `proposal_id`, `claim_id` | `claim_type`, `criticality`, `status`, `method`, `source_type`, `source_hash`, `confidence` |
| `FACT_RECORDED` | Yes | `proposal_id`, `fact_id`, `claim_id` | `source_type`, `source_ref`, `source_hash`, `observed_at`, `status`, `confidence` |
| `VERIFICATION_COMPLETED` | Yes | `proposal_id`, `verification_id` | `attempt`, `critical_unverified[]`, `reconciled`, `computed_total_minor`, `verifier_version`, `snapshot_id` |
| `TRUST_SCORE_COMPUTED` | Yes | `proposal_id`, `verification_id` | `components{G,C,S,R,P}`, `weights`, `score`, `band`, `trust_model_version` |
| `ABSTENTION_RAISED` | Yes | `proposal_id` | `code`, `template_id`, `params` |

#### Policy and Payments (Team 4)

| Event type | Txn | Required refs | Payload fields (v1) |
|---|---|---|---|
| `DECISION_MADE` | Yes | `proposal_id`, `decision_id`, `mandate_id` | `attempt`, `outcome`, `stage`, `rules_fired[]` (`rule_id`, `code`, `effect`), `trust_score`, `policy_version`, `trust_model_version`, `inputs_hash`, `inputs_snapshot_id` |
| `INCIDENT_LOGGED` | Yes | `proposal_id` | `incident_type`, `code`, `severity` |
| `STEP_UP_REQUESTED` | Yes | `decision_id`, `confirmation_id` | `reasons[]` (codes), `challenge`, `expires_at` |
| `CONFIRMATION_APPROVED` | Yes | `confirmation_id`, `user_id` | `challenge`, `key_id`, `signature_digest` |
| `CONFIRMATION_REJECTED` | Yes | `confirmation_id`, `user_id` | `challenge`, `key_id` |
| `CONFIRMATION_EXPIRED` | Yes | `confirmation_id` | `expired_at` |
| `CONFIRMATION_INVALIDATED` | Yes | `confirmation_id` | `code`, `old_proposal_hash`, `new_proposal_hash` |
| `TOKEN_ISSUED` | Yes | `token_id`, `proposal_id`, `decision_id` | `merchant_id`, `payee_id`, `amount_minor`, `currency`, `checkout_hash`, `rail`, `expires_at` (never the token value) |
| `TOKEN_ISSUE_REFUSED` | Yes | `proposal_id`, `decision_id` | `code` |
| `TOKEN_REDEEMED` | Yes | `token_id`, `payment_id` | `psp_payment_id`, `redeemed_at` |
| `TOKEN_REDEMPTION_REJECTED` | Yes | `token_id` | `code`, `attempted{merchant_id, amount_minor, currency}` |
| `TOKEN_EXPIRED` | Yes | `token_id` | `expired_at` |
| `TOKEN_REVOKED` | Yes | `token_id` | `reason` |
| `PAYMENT_CREATED` | Yes | `payment_id`, `proposal_id`, `token_id` | `rail`, `amount_minor`, `currency` |
| `PAYMENT_RESULT` | Yes | `payment_id`, `token_id` | `status`, `psp_payment_id`, `failure_code`, `reconciled` |
| `WEBHOOK_REJECTED` | Optional | `payment_id` (if parsable) | `code`, `psp_event_id` |
| `WEBHOOK_REPLAYED` | Optional | `payment_id` | `psp_event_id` |

#### Evidence and Experience (Team 5)

| Event type | Txn | Required refs | Payload fields (v1) |
|---|---|---|---|
| `TRANSACTION_OPENED` | Yes | `mandate_id`, `agent_id`, `user_id` | `opened_at` |
| `TRANSACTION_CLOSED` | Yes | `mandate_id` | `status`, `final_outcome` |
| `EXPLANATION_GENERATED` | Yes | `decision_id` | `template_version`, `codes[]`, `outcome` |
| `REPLAY_PERFORMED` | Yes | `decision_id`, `replay_id` | `policy_version`, `match: true` |
| `REPLAY_DIVERGED` | Yes | `decision_id`, `replay_id` | `policy_version`, `original_outcome`, `replayed_outcome`, `diff` |
| `LEDGER_VERIFIED` | Optional | n/a | `scope` (`transaction` or `global`), `first_seq`, `last_seq`, `checked_events` |
| `LEDGER_TAMPER_DETECTED` | Optional | n/a | `scope`, `failures[]` (`seq`, `code`) |
