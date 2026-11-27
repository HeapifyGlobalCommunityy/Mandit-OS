# Team 1: Identity and Mandate

| Field | Value |
|---|---|
| Modules | Know Your Agent (KYA) identity service; agent SDK request signing; Intent Mandate service; mandate matching; mandate dashboard |
| Code locations | `services/core/mandit/identity/`, `services/core/mandit/mandates/`, `sdk/python/mandit_sdk/`, `apps/console/app/mandates/` |
| Owned tables | `operators`, `agents`, `agent_keys`, `agent_challenges`, `agent_credentials`, `user_keys`, `mandates`, `mandate_spend` |
| Commit scopes | `identity`, `mandates`, `sdk`, `console` |
| Document status | Baseline v0.1 |

---

## 1. Mission

Team 1 builds the **authorization foundation** of Mandit OS. Identity answers *who is acting*. The mandate answers *what they are allowed to do*. Every other module trusts the outputs of this team, so correctness and fail-closed behaviour take priority over features.

## 2. Responsibilities

| # | Responsibility | Phase |
|---|---|---|
| R1 | Operator registration and manual verification (KYB stand-in) | 1 |
| R2 | Agent registration with Ed25519 public keys | 1 |
| R3 | Challenge-response credential issuance (KYA JWT, ≤15 minutes, key-bound) | 1 |
| R4 | Request-signature verification middleware used by the Gateway | 1 |
| R5 | Key rotation, key retirement and agent revocation, plus a public directory and revocation list | 1 |
| R6 | Python SDK that signs every outgoing agent request | 1 |
| R7 | User signing-key registration (WebCrypto ES256) | 1 |
| R8 | Mandate creation, validation, storage, listing and revocation | 1 |
| R9 | Mandate matching function returning exact, coded reasons | 1 |
| R10 | Mandate spend reservation (cumulative caps and transaction counts) | 1 |
| R11 | Mandate dashboard form in the console | 1 |
| R12 | Mandate amendment (new version that supersedes the old one) | 1 (API), 2 (UI) |

## 3. Interfaces Provided to Other Teams

```python
# services/core/mandit/identity/interface.py
class IdentityService[RequestT, AgentT](Protocol):
    async def verify_request(self, request: RequestT) -> AgentContext:
        """Verify KYA JWT + RFC 9421 signature + nonce + timestamp + digest.
        Raises IdentityError(code=...) on any failure. Never returns a partial context."""

    async def get_agent(self, agent_id: str) -> AgentT: ...
    async def is_active(self, agent_id: str, key_id: str | None = None) -> bool: ...

@dataclass(frozen=True)
class AgentContext:
    agent_id: str
    operator_id: str
    key_id: str
    key_thumbprint: str          # RFC 7638 JWK thumbprint, base64url
    scopes: frozenset[str]
    credential_id: str           # jti of the KYA JWT
    verified_at: datetime
```

`RequestT` and `AgentT` are type parameters because the HTTP framework request type and the agent registry record do not exist yet. The integration layer binds them (for example `IdentityService[starlette.requests.Request, Agent]`). Method names, arguments, return types and error behaviour are as specified above. `AgentContext` and `IdentityError` are published in `identity/schemas.py`; consumers should import them from there rather than keep local copies.

```python
# services/core/mandit/mandates/interface.py
class MandateService(Protocol):
    async def get(self, mandate_id: str) -> Mandate: ...
    async def assert_usable(self, mandate_id: str, agent: AgentContext) -> Mandate:
        """Raises MandateError if not ACTIVE, not in validity window, or not bound to agent."""

    async def match(self, mandate_id: str, action: ProposedAction) -> MatchResult: ...

    async def reserve_spend(self, mandate_id: str, proposal_id: str,
                            amount_minor: int, currency: str) -> SpendReservation:
        """Atomic. Fails with OVER_TOTAL_CAP / TXN_COUNT_EXCEEDED. Must be called inside the
        caller's DB transaction (Team 4 token issuance)."""

    async def commit_spend(self, reservation_id: str) -> None: ...
    async def release_spend(self, reservation_id: str) -> None: ...
```

| Consumer | Uses |
|---|---|
| Team 2 (Gateway) | `verify_request`, `assert_usable`, mandate allowlists for egress control |
| Team 3 (Grounding) | `match` (for the `USER_INSTRUCTION` claim), `get` |
| Team 4 (Policy and Payments) | `match`, `reserve_spend`, `commit_spend`, `release_spend`, `is_active` (re-checked at token issue) |
| Team 5 (Evidence) | Mandate snapshots for replay; identity events |
| Team 6 (Red Team) | Fixture agents and mandates; revoked and forged keys for impersonation tests |

## 4. Data Model

```sql
CREATE TABLE operators (
  operator_id     TEXT PRIMARY KEY,
  legal_name      TEXT NOT NULL,
  domain          TEXT NOT NULL,
  contact_email   TEXT NOT NULL,              -- synthetic only
  status          TEXT NOT NULL CHECK (status IN ('PENDING','VERIFIED','SUSPENDED')),
  verified_at     TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE agents (
  agent_id        TEXT PRIMARY KEY,
  operator_id     TEXT NOT NULL REFERENCES operators(operator_id),
  name            TEXT NOT NULL,
  version         TEXT NOT NULL,
  model_declared  TEXT,                       -- e.g. "claude-opus-5-5"; informational
  scopes          TEXT[] NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at      TIMESTAMPTZ,
  revoked_reason  TEXT
);

CREATE TABLE agent_keys (
  key_id          TEXT PRIMARY KEY,           -- akey_...
  agent_id        TEXT NOT NULL REFERENCES agents(agent_id),
  jwk             JSONB NOT NULL,             -- {"kty":"OKP","crv":"Ed25519","x":"..."}
  thumbprint      TEXT NOT NULL UNIQUE,       -- RFC 7638
  status          TEXT NOT NULL CHECK (status IN ('ACTIVE','RETIRED','REVOKED')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at      TIMESTAMPTZ
);

CREATE TABLE agent_challenges (
  challenge_id    TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL,
  key_id          TEXT NOT NULL,
  nonce           TEXT NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL,
  consumed_at     TIMESTAMPTZ
);

CREATE TABLE agent_credentials (
  jti             TEXT PRIMARY KEY,
  agent_id        TEXT NOT NULL,
  key_id          TEXT NOT NULL,
  issued_at       TIMESTAMPTZ NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE user_keys (
  key_id          TEXT PRIMARY KEY,           -- ukey_...
  user_id         TEXT NOT NULL,
  alg             TEXT NOT NULL CHECK (alg IN ('ES256')),
  jwk             JSONB NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE mandates (
  mandate_id            TEXT NOT NULL,
  version               INT  NOT NULL,
  user_id               TEXT NOT NULL,
  agent_id              TEXT NOT NULL,
  agent_key_thumbprint  TEXT NOT NULL,
  task_description      TEXT NOT NULL,        -- NOT enforced; display only
  constraints           JSONB NOT NULL,
  not_before            TIMESTAMPTZ NOT NULL,
  expires_at            TIMESTAMPTZ NOT NULL,
  nonce                 TEXT NOT NULL,
  supersedes            TEXT,                 -- mandate_id:version
  signature             JSONB NOT NULL,
  digest                TEXT NOT NULL,        -- sha256 of JCS(unsigned mandate)
  status                TEXT NOT NULL CHECK (status IN
                          ('ACTIVE','EXPIRED','REVOKED','SUPERSEDED','EXHAUSTED','REJECTED')),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (mandate_id, version)
);

CREATE TABLE mandate_spend (
  reservation_id  TEXT PRIMARY KEY,
  mandate_id      TEXT NOT NULL,
  proposal_id     TEXT NOT NULL UNIQUE,
  amount_minor    BIGINT NOT NULL CHECK (amount_minor > 0),
  currency        CHAR(3) NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('RESERVED','COMMITTED','RELEASED')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Spent amount is computed as `SUM(amount_minor) WHERE status IN ('RESERVED','COMMITTED')`. Reservation uses `SELECT ... FOR UPDATE` on the mandate row, so that concurrent reservations serialize.

## 5. Agent Authentication Protocol

### 5.1 KYA JWT

Header: `{"alg": "EdDSA", "typ": "kya+jwt", "kid": "mandit-kya-2026-11"}`

```json
{
  "iss": "https://mandit.local/kya",
  "sub": "agt_01JD3Y0000SHOPPERV3000000",
  "op": "op_01JD3Y0000ACMEOPERATOR0000",
  "aud": "mandit-gateway",
  "scope": "transaction:open merchant:read web:fetch checkout:create purchase:propose purchase:read purchase:execute",
  "cnf": { "jkt": "q8xR3...thumbprint" },
  "iat": 1763892000,
  "nbf": 1763892000,
  "exp": 1763892900,
  "jti": "kya_01JD3Y4K1M2N3P4Q5R6S7T8V9W"
}
```

The verifier **pins `alg` to `EdDSA`** and ignores any `jku` or `x5u` header. `kid` must resolve to Mandit's own issuer key set.

### 5.2 Signed request

```http
POST /v1/gateway/tools/merchant.search HTTP/1.1
Host: mandit.local
Authorization: KYA eyJhbGciOiJFZERTQSIs...
Mandit-Transaction-ID: txn_01JD3Y9X8W7V6T5S4R3Q2P1N0M
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig1=("@method" "@target-uri" "content-digest" "authorization" "mandit-transaction-id");created=1763892010;nonce="b3f1c2...";keyid="akey_01JD3Y...";alg="ed25519"
Signature: sig1=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:
X-Request-ID: req_01JD3Y...

{"query":"gaming laptop","category":"electronics.laptops","limit":10}
```

### 5.3 Verification algorithm (`verify_request`)

| Step | Check | Failure code |
|---|---|---|
| 1 | `Authorization` header present with the `KYA` scheme | `UNAUTHENTICATED` |
| 2 | JWT signature valid under the Mandit issuer key; `alg == EdDSA` | `KYA_TOKEN_INVALID` |
| 3 | `nbf ≤ now < exp` (±60 s leeway) | `KYA_TOKEN_EXPIRED` |
| 4 | `aud == "mandit-gateway"` | `KYA_TOKEN_INVALID` |
| 5 | Agent `ACTIVE`; operator `VERIFIED` (revocation cache TTL ≤ 60 s) | `AGENT_REVOKED`, `OPERATOR_NOT_VERIFIED` |
| 6 | `Signature-Input` and `Signature` present; covered components include the required set | `SIGNATURE_MISSING` |
| 7 | The `keyid` key is `ACTIVE` and its thumbprint equals `cnf.jkt` | `KEY_NOT_BOUND` |
| 8 | Ed25519 signature valid over the RFC 9421 signature base | `SIGNATURE_INVALID` |
| 9 | `|now − created| ≤ 60 s` | `TIMESTAMP_OUT_OF_WINDOW` |
| 10 | Redis `SET mandit:nonce:{keyid}:{nonce} 1 NX EX 300` succeeds | `NONCE_REPLAYED` |
| 11 | `Content-Digest` equals the SHA-256 of the raw body | `CONTENT_DIGEST_MISMATCH` |

Every failure emits `AGENT_AUTH_FAILED` with the code, `agent_id` (if known) and `key_id`. Every failure returns `401` or `403` and **never** a partially populated context.

### 5.4 SDK

```python
from mandit_sdk import ManditClient, Ed25519Signer

client = ManditClient(
    base_url="http://localhost:8000",
    agent_id="agt_01JD3Y0000SHOPPERV3000000",
    signer=Ed25519Signer.from_pem_file("/run/secrets/agent_key.pem"),
)
await client.authenticate()                       # challenge -> KYA JWT; auto-refresh at 80% of lifetime
txn = await client.open_transaction(mandate_id="man_...")
results = await client.tool("merchant.search", {"query": "gaming laptop"})
```

SDK requirements:

1. Sign every request as described in §5.2.
2. Generate a 128-bit random nonce per request.
3. Refresh credentials automatically before they expire.
4. Attach `Idempotency-Key` to mutating calls and reuse it on retry.
5. Raise typed exceptions mapped from the error codes.
6. Never log keys, JWTs or signatures.

## 6. Endpoints: Identity

### 6.1 `POST /v1/operators`

Request:

```json
{
  "legal_name": "Acme Agents Pvt Ltd (synthetic)",
  "domain": "acme-agents.example",
  "contact_email": "ops@acme-agents.example"
}
```

Response `201`:

```json
{
  "operator_id": "op_01JD3Y0000ACMEOPERATOR0000",
  "status": "PENDING",
  "created_at": "2026-11-23T10:00:00.000Z"
}
```

`POST /v1/operators/{operator_id}/verify` (Mandit admin) returns `200 {"operator_id": "...", "status": "VERIFIED", "verified_at": "..."}` and emits `OPERATOR_VERIFIED`. Verifying an operator that is already `VERIFIED` returns the same body and emits no second event. A `SUSPENDED` operator is not revived: `409 CONFLICT`.

`GET /v1/operators/{operator_id}` returns `operator_id`, `legal_name`, `domain`, `contact_email`, `status`, `created_at` and, once verified, `verified_at`.

Errors: `VALIDATION_ERROR` (400), `UNAUTHENTICATED` (401), `FORBIDDEN` (403, registration and verification by anyone but a Mandit admin), `NOT_FOUND` (404), `CONFLICT` (409).

Event: `OPERATOR_REGISTERED`. The ledger payload carries `legal_name` and `domain` only; the contact email is personal data and stays out of the ledger.

Phase 1 validation: `domain` and the domain of `contact_email` must be reserved synthetic names (RFC 2606 and RFC 6761: `*.example`, `*.test`, `*.invalid`, `*.localhost`, `example.com`, `example.net`, `example.org`), because the programme uses synthetic data only and verification is manual. Domains are stored in lowercase.

### 6.2 `POST /v1/agents/register`

Request:

```json
{
  "operator_id": "op_01JD3Y0000ACMEOPERATOR0000",
  "name": "acme-shopper",
  "version": "3.0.0",
  "model_declared": "demo-llm",
  "public_key": { "kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" },
  "requested_scopes": ["transaction:open", "merchant:read", "web:fetch", "checkout:create",
                       "purchase:propose", "purchase:read", "purchase:execute"]
}
```

Response `201`:

```json
{
  "agent_id": "agt_01JD3Y0000SHOPPERV3000000",
  "key_id": "akey_01JD3Y0000SHOPPERKEY0001",
  "key_thumbprint": "q8xR3...",
  "scopes": ["transaction:open", "merchant:read", "web:fetch", "checkout:create",
             "purchase:propose", "purchase:read", "purchase:execute"],
  "status": "ACTIVE",
  "directory_url": "/.well-known/mandit/agents/agt_01JD3Y0000SHOPPERV3000000.jwks"
}
```

Errors: `OPERATOR_NOT_VERIFIED` (403), `VALIDATION_ERROR` (400, for example a non-Ed25519 key), `SCOPE_DENIED` (403, a requested scope not grantable to the operator), `CONFLICT` (409, the public key is already registered to an agent), `NOT_FOUND` (404, the operator does not exist or the caller does not act for it).

Event: `AGENT_REGISTERED`.

Rules:

1. The caller must be a Mandit admin or an admin of `operator_id`. Any other caller gets `NOT_FOUND`, the same as for a missing operator, so operator identifiers cannot be enumerated.
2. Grantable scopes in Phase 1 are the tool scopes of [REFERENCE §10](../REFERENCE.md#10-mcp-tool-surface) except `user:ask` (a Phase 2 tool). Any other requested scope fails the whole request with `SCOPE_DENIED`; scopes are never silently dropped. Granted scopes are deduplicated and sorted.
3. A public key (by RFC 7638 thumbprint) identifies exactly one agent. Registering it again, even with a different `kid` label, returns `CONFLICT`. The `UNIQUE` constraint on `agent_keys.thumbprint` enforces this.
4. Only the public members `{kty, crv, x}` are stored. A JWK containing `d` is rejected.
5. Request bodies are JSON objects of at most 16 KiB with `Content-Type: application/json`. Unknown fields, repeated members and non-finite numbers are rejected with `VALIDATION_ERROR`; error details name the field but do not echo the value.

`GET /v1/agents/{agent_id}` (USER who acts for the operator, Mandit admin, or SERVICE) returns `agent_id`, `operator_id`, `name`, `version`, `model_declared`, `scopes`, `status`, `created_at`, `revoked_at`, `directory_url` and `keys` (`key_id`, `key_thumbprint`, `status`, `created_at` each). Public key material is served by the directory (§6.6), not here.

### 6.3 `POST /v1/agents/{agent_id}/challenge`

Request: `{"key_id": "akey_01JD3Y0000SHOPPERKEY0001"}`

Response `200`:

```json
{
  "challenge_id": "chl_01JD3Y...",
  "nonce": "4f7a1c9e2b...",
  "expires_at": "2026-11-23T10:01:00.000Z"
}
```

A challenge expires after 60 seconds and can be used once.

### 6.4 `POST /v1/agents/{agent_id}/token`

Request:

```json
{
  "challenge_id": "chl_01JD3Y...",
  "key_id": "akey_01JD3Y0000SHOPPERKEY0001",
  "signature": "base64url(ed25519_sign(sk, 'mandit-kya-challenge:' + nonce + ':' + agent_id))"
}
```

Response `200`:

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs...",
  "token_type": "KYA",
  "expires_in": 900,
  "scope": "transaction:open merchant:read ..."
}
```

Errors: `CHALLENGE_INVALID` (401), `AGENT_REVOKED` (403), `KEY_NOT_ACTIVE` (403).

Event: `AGENT_CREDENTIAL_ISSUED`.

### 6.5 Key rotation and revocation

| Endpoint | Request | Response | Event |
|---|---|---|---|
| `POST /v1/agents/{id}/keys` | `{"public_key": {JWK}}` | `201 {"key_id", "key_thumbprint", "status": "ACTIVE"}` | `AGENT_KEY_ADDED` |
| `POST /v1/agents/{id}/keys/{key_id}/retire` | `{}` | `200 {"key_id", "status": "RETIRED"}` | `AGENT_KEY_RETIRED` |
| `POST /v1/agents/{id}/revoke` | `{"reason": "compromised"}` | `200 {"agent_id", "status": "REVOKED", "revoked_at"}` | `AGENT_REVOKED` |

On revocation:

1. All keys move to `REVOKED`.
2. The revocation cache entry is invalidated immediately.
3. All `ACTIVE` mandates bound to the agent remain stored, but fail `assert_usable`.
4. Team 4 is notified through the `AGENT_REVOKED` event, so it can revoke unredeemed tokens.

### 6.6 Directory

`GET /.well-known/mandit/agents/{agent_id}.jwks`:

```json
{
  "agent_id": "agt_01JD3Y0000SHOPPERV3000000",
  "operator_id": "op_01JD3Y0000ACMEOPERATOR0000",
  "status": "ACTIVE",
  "keys": [
    { "kid": "akey_01JD3Y0000SHOPPERKEY0001", "kty": "OKP", "crv": "Ed25519", "x": "11qY...", "status": "ACTIVE" }
  ]
}
```

`GET /v1/revocations?since=2026-11-23T00:00:00Z` returns `{"agents": [...], "keys": [...], "as_of": "..."}`.

## 7. Endpoints: Mandates

### 7.1 Mandate object (`schemas/mandate.v1.json`)

```json
{
  "mandate_id": "man_01JD3Z0000LAPTOP60K000000",
  "version": 1,
  "supersedes": null,
  "user_id": "usr_01JD3Z0000DEMOUSER0000000",
  "agent_id": "agt_01JD3Y0000SHOPPERV3000000",
  "agent_key_thumbprint": "q8xR3...",
  "task_description": "Buy a laptop under ₹60,000 from a trusted merchant",
  "constraints": {
    "allowed_merchants": ["mer_croma_demo", "mer_reliance_demo"],
    "allowed_domains": ["croma.mock.mandit.local", "reliance.mock.mandit.local"],
    "allowed_categories": ["electronics.laptops"],
    "currency": "INR",
    "max_amount_per_txn_minor": 6000000,
    "max_amount_total_minor": 6000000,
    "max_txn_count": 1,
    "approval_threshold_minor": 5000000,
    "payment_methods": ["CARD_TOKEN", "UPI_INTENT"],
    "require_refund_policy": true,
    "min_returns_window_days": 7,
    "max_delivery_days": 5,
    "forbidden_line_types": ["SUBSCRIPTION", "INSURANCE", "DONATION", "GIFT_CARD"],
    "selection_rule": "CONFIRM_IF_PRICIER_THAN_CHEAPEST_MATCHING"
  },
  "not_before": "2026-11-23T10:00:00.000Z",
  "expires_at": "2026-11-25T10:00:00.000Z",
  "nonce": "8c1d0f...",
  "signature": {
    "alg": "ES256",
    "key_id": "ukey_01JD3Z0000DEMOUSERKEY0001",
    "signed_digest": "sha256:5e0f...",
    "value": "MEUCIQ..."
  }
}
```

Field rules:

| Field | Rule |
|---|---|
| `task_description` | Free text, displayed only and **never enforced**. The UI must tell the user that only the constraints are enforced. |
| `allowed_merchants` | Non-empty; each ID must exist in the Team 3 merchant registry with status `VERIFIED`. |
| `allowed_domains` | Derived from the registry entries for the merchants; the user cannot add arbitrary domains in Phase 1. |
| `currency` | ISO 4217; Phase 1 supports `INR` (and `USD` for tests). |
| `max_amount_per_txn_minor` | Integer > 0. |
| `max_amount_total_minor` | ≥ `max_amount_per_txn_minor`. |
| `approval_threshold_minor` | 0 ≤ value ≤ `max_amount_per_txn_minor`. A value of 0 means every purchase requires confirmation. |
| `expires_at` | After `not_before`; at most 30 days after creation in Phase 1. |
| `selection_rule` | `NONE` or `CONFIRM_IF_PRICIER_THAN_CHEAPEST_MATCHING`. |
| `signature.signed_digest` | Must equal `sha256(JCS(mandate without signature))`, recomputed by the server. |

### 7.2 `POST /v1/mandates`

Request: the full mandate object **without** `mandate_id` and `version`. The console obtains these first from `POST /v1/mandates/drafts`, which returns `{mandate_id, version, nonce, not_before}`, so the signed bytes include the final identifier.

> Implementation note: the draft step keeps the signed object identical to the stored object. Team 1 may instead choose client-generated ULIDs. The decision must be recorded in this document before the Week 2 gate.

Response `201`:

```json
{
  "mandate_id": "man_01JD3Z0000LAPTOP60K000000",
  "version": 1,
  "status": "ACTIVE",
  "digest": "sha256:5e0f...",
  "created_at": "2026-11-23T10:00:05.000Z"
}
```

Validation order (fail closed):

1. Schema.
2. Field rules (§7.1).
3. The user key is `ACTIVE` and belongs to the caller.
4. Digest recompute.
5. Signature verification.
6. The agent is `ACTIVE`, and the thumbprint matches an active agent key.
7. Merchants are `VERIFIED` in the registry.
8. `supersedes` (if set) references an `ACTIVE` mandate of the same user, which then becomes `SUPERSEDED`.

Errors: `MANDATE_MALFORMED` (400), `MANDATE_SIGNATURE_INVALID` (422), `AGENT_REVOKED` (422), `MERCHANT_NOT_IN_REGISTRY` (422).

Events: `MANDATE_CREATED` or `MANDATE_REJECTED`, and `MANDATE_SUPERSEDED` when applicable.

### 7.3 `GET /v1/mandates/{mandate_id}`

Returns the mandate object plus `status`, `spent_minor`, `txn_count` and `remaining_minor`. An agent may read only mandates bound to itself, and receives the constraints but **not** the signature value.

### 7.4 `POST /v1/mandates/{mandate_id}/revoke`

Request: `{"reason": "user_requested"}`. Response `200 {"mandate_id", "status": "REVOKED", "revoked_at"}`.

Event: `MANDATE_REVOKED`. Team 4 listens for it and revokes unredeemed tokens.

### 7.5 `POST /v1/mandates/{mandate_id}/match`

Service-to-service call. The same logic is exposed in-process as `MandateService.match`.

Request (`ProposedAction`):

```json
{
  "agent_id": "agt_01JD3Y0000SHOPPERV3000000",
  "agent_key_thumbprint": "q8xR3...",
  "merchant_id": "mer_fastlaptopdeals",
  "domain": "fastlaptopdeals.example.com",
  "categories": ["electronics.laptops"],
  "line_types": ["PRODUCT", "SHIPPING", "TAX"],
  "amount_minor": 14999900,
  "currency": "INR",
  "payment_method": "CARD_TOKEN",
  "delivery_days": 3,
  "returns_window_days": null,
  "evaluated_at": "2026-11-23T10:20:00.000Z"
}
```

Response `200`:

```json
{
  "mandate_id": "man_01JD3Z0000LAPTOP60K000000",
  "mandate_version": 1,
  "satisfied": false,
  "violations": [
    { "code": "MERCHANT_NOT_ALLOWED", "field": "merchant_id",
      "expected": ["mer_croma_demo", "mer_reliance_demo"], "actual": "mer_fastlaptopdeals" },
    { "code": "DOMAIN_NOT_ALLOWED", "field": "domain",
      "expected": ["croma.mock.mandit.local", "reliance.mock.mandit.local"], "actual": "fastlaptopdeals.example.com" },
    { "code": "OVER_TXN_CAP", "field": "amount_minor", "expected": 6000000, "actual": 14999900 },
    { "code": "RETURNS_UNVERIFIED", "field": "returns_window_days", "expected": ">= 7", "actual": null }
  ],
  "signals": [
    { "code": "ABOVE_APPROVAL_THRESHOLD", "threshold_minor": 5000000 }
  ],
  "remaining_minor": 6000000,
  "matcher_version": "mandate-match-1.0.0"
}
```

`violations` are hard failures. `signals` are inputs to step-up rules and are not failures. Event: `MANDATE_MATCH_EVALUATED`.

### 7.6 Matching algorithm

```python
def match(m: Mandate, a: ProposedAction, spent_minor: int, txn_count: int) -> MatchResult:
    v, s = [], []
    if m.status != "ACTIVE":                          v.append(V(f"MANDATE_{m.status}"))
    if not (m.not_before <= a.evaluated_at < m.expires_at):
        v.append(V("MANDATE_EXPIRED" if a.evaluated_at >= m.expires_at else "MANDATE_NOT_YET_VALID"))
    if a.agent_id != m.agent_id or a.agent_key_thumbprint != m.agent_key_thumbprint:
        v.append(V("AGENT_NOT_BOUND_TO_MANDATE"))
    c = m.constraints
    if a.merchant_id not in c.allowed_merchants:      v.append(V("MERCHANT_NOT_ALLOWED", ...))
    if a.domain not in c.allowed_domains:             v.append(V("DOMAIN_NOT_ALLOWED", ...))
    if a.currency != c.currency:                      v.append(V("CURRENCY_MISMATCH", ...))
    if a.amount_minor > c.max_amount_per_txn_minor:   v.append(V("OVER_TXN_CAP", ...))
    if spent_minor + a.amount_minor > c.max_amount_total_minor: v.append(V("OVER_TOTAL_CAP", ...))
    if txn_count + 1 > c.max_txn_count:               v.append(V("TXN_COUNT_EXCEEDED", ...))
    if set(a.line_types) & set(c.forbidden_line_types): v.append(V("FORBIDDEN_LINE_TYPE", ...))
    if not set(a.categories) <= set(c.allowed_categories): v.append(V("CATEGORY_NOT_ALLOWED", ...))
    if a.payment_method not in c.payment_methods:     v.append(V("PAYMENT_METHOD_NOT_ALLOWED", ...))
    if c.max_delivery_days is not None:
        if a.delivery_days is None:                   s.append(S("DELIVERY_UNVERIFIED"))
        elif a.delivery_days > c.max_delivery_days:   v.append(V("DELIVERY_REQUIREMENT_UNMET", ...))
    if c.require_refund_policy:
        if a.returns_window_days is None:             s.append(S("RETURNS_UNVERIFIED"))
        elif a.returns_window_days < c.min_returns_window_days:
            v.append(V("RETURNS_REQUIREMENT_UNMET", ...))
    if a.amount_minor >= c.approval_threshold_minor:  s.append(S("ABOVE_APPROVAL_THRESHOLD"))
    return MatchResult(satisfied=not v, violations=v, signals=s)
```

Requirements:

- The function is **pure**: no I/O. Spend values are passed in.
- It **collects all** violations rather than stopping at the first one, so that explanations are complete.
- Its version is recorded in every result.

## 8. Mandate Dashboard (Console)

| Route | Purpose |
|---|---|
| `/mandates` | List mandates with status, remaining amount and expiry; revoke action |
| `/mandates/new` | Creation form |
| `/mandates/[id]` | Detail view: constraints, signature digest, spend history, linked transactions |
| `/settings/keys` | Generate and register the user signing key |

Form fields: task description; agent (select from active agents); merchants (multi-select from the registry); categories; currency; per-transaction limit; total limit; maximum transaction count; approval threshold; expiry; payment methods; maximum delivery days; refund-policy requirement and minimum returns window; selection rule.

UX requirements:

1. Amounts are entered in major units and converted to minor units with exact decimal arithmetic before signing.
2. Before signing, the form shows a **review screen** that renders the exact canonical object to be signed, a plain-language summary, and the statement "Only the constraints listed are enforced. The task description is not."
3. Signing uses `crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"}, privateKey, digestBytes)` with a non-extractable key.
4. Validation errors are shown inline, mapped from the error codes.

## 9. Ledger Events Emitted

`OPERATOR_REGISTERED`, `OPERATOR_VERIFIED`, `AGENT_REGISTERED`, `AGENT_KEY_ADDED`, `AGENT_KEY_RETIRED`, `AGENT_REVOKED`, `AGENT_CREDENTIAL_ISSUED`, `AGENT_AUTH_FAILED`, `USER_KEY_REGISTERED`, `MANDATE_CREATED`, `MANDATE_REJECTED`, `MANDATE_SUPERSEDED`, `MANDATE_REVOKED`, `MANDATE_EXPIRED`, `MANDATE_EXHAUSTED`, `MANDATE_MATCH_EVALUATED`, `SPEND_RESERVED`, `SPEND_COMMITTED`, `SPEND_RELEASED`. Payloads are defined in [module 05 §12](05-evidence-and-experience.md#12-ledger-event-catalogue).

## 10. Testing Requirements

| Test | Type | Required by |
|---|---|---|
| Valid signed request accepted; each of the 11 verification steps individually violated and rejected with the correct code | Unit and integration | G2 |
| Replayed nonce rejected; request at `created ± 61 s` rejected | Integration | G2 |
| JWT with `alg: none`, HS256 or a foreign `kid` rejected | Unit | G2 |
| Revoked agent rejected within 60 s on every route | Integration | G2 |
| Mandate signature over altered bytes (any single field) rejected | Property (Hypothesis) | G2 |
| `match()` returns every violation, for generated actions | Property | G3 |
| 100 concurrent `reserve_spend` calls never exceed `max_amount_total_minor` | Concurrency | G3 |
| JCS canonicalization equals the reference vectors from RFC 8785 | Unit | G1 |
| Dashboard creates a mandate end to end | Playwright | G2 |

Coverage target for `identity/` and `mandates/`: ≥ 90% line coverage, 100% of error-code paths.

## 11. Milestones

| Week | Deliverable |
|---|---|
| 1–2 | Design note; `agent.v1`, `mandate.v1` and `operator.v1` schemas; `IdentityService` and `MandateService` stubs; JCS and signature helpers in `common/` |
| 3 | Operator and agent registration; challenge and token issuance; SDK signing |
| 4 | `verify_request` middleware in the gateway; mandate creation API; dashboard form (G2) |
| 5 | Matching function with full codes; revocation; directory |
| 6 | Spend reservation; key rotation; amendment (`supersedes`) |
| 7–8 | Hardening; integration with policy and tokens; console polish |
| 9 | Fix defects found by the red team |

## 12. Areas for Improvement (Phase 2)

| # | Improvement | Rationale |
|---|---|---|
| I-1.1 | Replace WebCrypto keys with **WebAuthn passkeys**; set `challenge = sha256(JCS(mandate))` | Device-bound, phishing-resistant consent with user-verification evidence |
| I-1.2 | Align the mandate shape with **AP2 open and closed mandates** (Intent and Cart mandates) | Interoperability; a closed mandate replaces the separate confirmation signature |
| I-1.3 | **Delegation chains** for sub-agents (planner → checkout agent) with enforced scope attenuation at every hop | Supports multi-agent systems without identity sharing |
| I-1.4 | Operator KYB with domain-control proof (DNS TXT or `/.well-known` challenge) | Replaces manual verification |
| I-1.5 | Push-based revocation (server-sent events or webhooks) to verifiers | Reduces the revocation window below the cache TTL |
| I-1.6 | Natural language to structured mandate assistant, which highlights phrases that cannot be enforced ("trusted", "good reviews") | Turns fuzzy intent into checkable fields and shows the user the gap |
| I-1.7 | Agent keys held in a KMS or HSM, never exportable; signed directory documents | Smaller blast radius if an agent host is compromised |
| I-1.8 | Consume the NPCI Unified Agent Protocol registry when a public specification exists | Avoids competing with a national registry |
| I-1.9 | Mandate amendment UI with a visual diff between versions | Clear consent for scope changes (INV-07) |
