# Team 3: Grounding and Verification

| Field | Value |
|---|---|
| Modules | Mock merchant service (honest); merchant registry; checkout snapshots; proposals; Claim Verification Engine; Grounded Fact Ledger; deterministic calculator; Trust Score; abstention |
| Code locations | `services/core/mandit/grounding/`, `services/mock-merchant/` |
| Owned tables | `merchants`, `merchant_keys`, `checkouts`, `proposals`, `claims`, `facts`, `verifications`; mock merchant has its own `catalog`, `inventory`, `policies`, `checkouts` |
| Commit scopes | `grounding`, `mock-merchant`, `registry` |
| Document status | Baseline v0.1 |

---

## 1. Mission

Team 3 answers one question: **can we trust the facts the agent is using to make this purchase?** It does so by moving every money-relevant fact out of the agent's text and into structured, signed and independently recomputed data. The agent may *choose* a product. It may not *assert* the price, the total, the payee or the policy terms. Those values come only from authoritative sources.

## 2. Responsibilities

| # | Responsibility | Phase |
|---|---|---|
| R1 | Mock merchant service: catalog, inventory, policies, signed checkout, storefront HTML, merchant keys; fixture loader so that Team 6 can add malicious merchants | 1 |
| R2 | Merchant registry: verified merchants, domains, payees, categories, public keys | 1 |
| R3 | Checkout snapshot storage with signature verification and hashing | 1 |
| R4 | Proposal intake, canonical `proposal_hash` | 1 |
| R5 | Claim construction from structured proposal fields (no LLM in Phase 1) | 1 |
| R6 | Per-claim verification against the catalog, checkout, registry and mandate | 1 |
| R7 | Deterministic calculator: line totals, tax, fees, discounts, final total, currency | 1 |
| R8 | Grounded Fact Ledger: every verified fact with the six mandatory attributes | 1 |
| R9 | Trust Score components and score (`trust-1.0.0`) | 1 |
| R10 | Abstention records with template IDs for explanations | 1 |
| R11 | Selection sanity (factual-steering signal SU-07) | 1 |
| R12 | Bounded re-verification with fresh sources (RETRIEVE_MORE) | 1 |

## 3. Interfaces Provided to Other Teams

```python
# services/core/mandit/grounding/interface.py
class GroundingService(Protocol):
    async def get_merchant(self, merchant_id: str) -> Merchant: ...
    async def resolve_domain(self, domain: str) -> Merchant | None: ...
    async def store_checkout(self, signed_checkout: str, merchant_id: str,
                             transaction_id: str) -> CheckoutSnapshot: ...
    async def refetch_checkout(self, checkout_id: str) -> CheckoutSnapshot:
        """Fetch from merchant again (TOCTOU). Used by Team 4 at execution."""
    async def create_proposal(self, req: ProposalCreate, agent: AgentContext) -> Proposal: ...
    async def verify(self, proposal_id: str, refresh: bool = False) -> VerificationReport: ...
    async def latest_verification(self, proposal_id: str) -> VerificationReport: ...
```

| Consumer | Uses |
|---|---|
| Team 1 | `get_merchant` and the registry list for the mandate form and validation |
| Team 2 | `resolve_domain` (look-alike detection), `store_checkout` |
| Team 4 | `verify`, `latest_verification`, `refetch_checkout`, `get_merchant` (payee) |
| Team 5 | Claims, facts and verification reports in snapshots |
| Team 6 | Fixture loader for malicious merchants; fabricated-claim scenarios |

## 4. Mock Merchant Service

A separate FastAPI service with its own database and Ed25519 signing keys, representing a different trust domain. Multiple merchants are hosted under `/merchants/{merchant_id}`. Each merchant's behaviour is defined by a fixture file:

```yaml
# services/mock-merchant/fixtures/honest/croma_demo.yaml
merchant_id: mer_croma_demo
legal_name: Croma Demo Retail (synthetic)
domain: croma.mock.mandit.local
payee: { card_acquirer_id: acq_croma_001, upi_vpa: croma.demo@mockbank }
behaviour: honest            # honest | flaky | malicious
tax_rate_bps: 1800           # 18% GST
catalog:
  - sku: ASUS-TUF-A15-16-512
    gtin: "0195553000001"
    title: "ASUS TUF A15, RTX 4060, 16 GB, 512 GB"
    category: electronics.laptops
    price_minor: 6482966     # pre-tax; total with 18% GST = 7649900
    stock: 12
    delivery_eta_days: 3
policies: { returns_window_days: 7, refundable: true, warranty_months: 12 }
```

Behaviours:

| Behaviour | Description | Owner |
|---|---|---|
| `honest` | Consistent catalog, checkout and policies | Team 3 |
| `flaky` | Price changes between checkout creation and re-fetch (TOCTOU test); occasional 5xx responses | Team 3 |
| `malicious` | Hidden injections, fake discounts, payee swap, drip fees, false "discontinued" claims, subscription line items. Malicious merchants sign checkouts **with their own valid keys** | Team 6 (fixtures), Team 3 (engine support) |

### 4.1 `GET /merchants/{merchant_id}/v1/catalog/products?q=&category=&limit=`

Response `200`:

```json
{
  "merchant_id": "mer_croma_demo",
  "results": [
    { "sku": "ASUS-TUF-A15-16-512", "gtin": "0195553000001", "title": "ASUS TUF A15, RTX 4060, 16 GB, 512 GB",
      "category": "electronics.laptops", "price_minor": 6482966, "currency": "INR",
      "price_includes_tax": false, "in_stock": true, "delivery_eta_days": 3 }
  ],
  "as_of": "2026-11-23T10:10:00.000Z",
  "signature": "base64url(ed25519(JCS(body without signature)))"
}
```

### 4.2 `POST /merchants/{merchant_id}/v1/checkouts`

Request:

```json
{
  "items": [{ "sku": "ASUS-TUF-A15-16-512", "quantity": 1 }],
  "ship_to": { "pincode": "400001" },
  "payment_method": "CARD_TOKEN"
}
```

Response `201`: a compact JWS (`alg: EdDSA`, `kid` from `/.well-known/merchant-keys.json`) whose payload is:

```json
{
  "checkout_id": "co_01JD42...",
  "merchant_id": "mer_croma_demo",
  "payee": { "card_acquirer_id": "acq_croma_001", "upi_vpa": "croma.demo@mockbank" },
  "lines": [
    { "line_id": "l1", "type": "PRODUCT", "sku": "ASUS-TUF-A15-16-512", "category": "electronics.laptops",
      "description": "ASUS TUF A15 16GB", "quantity": 1, "unit_price_minor": 6482966, "amount_minor": 6482966 },
    { "line_id": "l2", "type": "SHIPPING", "description": "Standard", "quantity": 1,
      "unit_price_minor": 0, "amount_minor": 0 },
    { "line_id": "l3", "type": "TAX", "description": "GST 18%", "quantity": 1,
      "unit_price_minor": 1166934, "amount_minor": 1166934 }
  ],
  "subtotal_minor": 6482966,
  "discount_minor": 0,
  "fees_minor": 0,
  "tax_minor": 1166934,
  "total_minor": 7649900,
  "currency": "INR",
  "delivery": { "eta_days": 3, "method": "STANDARD" },
  "returns": { "window_days": 7, "refundable": true },
  "created_at": "2026-11-23T10:12:00.000Z",
  "expires_at": "2026-11-23T10:27:00.000Z"
}
```

Line types: `PRODUCT`, `SHIPPING`, `TAX`, `FEE`, `DISCOUNT`, `SUBSCRIPTION`, `INSURANCE`, `DONATION`, `GIFT_CARD`. The tax rounding rule is half-up per line, in minor units. It is documented in the fixture and reproduced exactly by the calculator.

### 4.3 Other endpoints

| Endpoint | Response |
|---|---|
| `GET .../v1/catalog/products/{sku}` | Single product as in §4.1, plus `variants[]` and `policies` |
| `GET .../v1/checkouts/{checkout_id}` | The current signed checkout. A `flaky` merchant may return a changed total. |
| `POST .../v1/checkouts/{checkout_id}/complete` | Request `{ "psp_payment_id", "payment_id" }`; response `{ "order_id", "status": "CONFIRMED" }` |
| `GET .../v1/policies` | `{ "returns_window_days", "refundable", "warranty_months", "delivery_sla_days" }`, signed |
| `GET .../.well-known/merchant-keys.json` | `{ "keys": [ { "kid", "kty": "OKP", "crv": "Ed25519", "x" } ] }` |
| `GET .../storefront/p/{sku}` | HTML product page (the injection surface for malicious fixtures) |

## 5. Merchant Registry

```sql
CREATE TABLE merchants (
  merchant_id     TEXT PRIMARY KEY,
  legal_name      TEXT NOT NULL,
  domains         TEXT[] NOT NULL,
  payees          JSONB NOT NULL,          -- {"card_acquirer_id": "...", "upi_vpa": "..."}
  categories      TEXT[] NOT NULL,
  base_url        TEXT NOT NULL,
  status          TEXT NOT NULL CHECK (status IN ('VERIFIED','SUSPENDED')),
  onboarded_at    TIMESTAMPTZ NOT NULL
);
CREATE TABLE merchant_keys (
  kid TEXT PRIMARY KEY, merchant_id TEXT NOT NULL, jwk JSONB NOT NULL, status TEXT NOT NULL
);
```

`GET /v1/merchants/{merchant_id}` returns the row. Malicious fixture merchants are **not** in the registry unless the scenario explicitly tests a compromised registered merchant.

## 6. Proposals

### 6.1 `POST /v1/proposals` (called by the gateway)

Request:

```json
{
  "transaction_id": "txn_01JD3Y9X...",
  "mandate_id": "man_01JD3Z0000LAPTOP60K000000",
  "checkout_id": "co_01JD42...",
  "payment_method": "CARD_TOKEN",
  "stated": {
    "amount_minor": 7649900,
    "currency": "INR",
    "merchant_id": "mer_croma_demo",
    "product_title": "ASUS TUF A15 16GB",
    "sku": "ASUS-TUF-A15-16-512",
    "delivery_eta_days": 3,
    "returns_window_days": 7
  },
  "source_ids": ["cnt_01JD40...", "cnt_01JD41..."],
  "alternatives_seen": [
    { "merchant_id": "mer_croma_demo", "sku": "ASUS-TUF-A15-8-512", "price_minor": 6101610,
      "content_id": "cnt_01JD40..." }
  ],
  "rationale_untrusted": "16 GB RAM is better for gaming."
}
```

Response `201`:

```json
{
  "proposal_id": "prop_01JD43...",
  "proposal_hash": "sha256:7ab2...",
  "checkout_hash": "sha256:9c1e...",
  "status": "SUBMITTED",
  "created_at": "2026-11-23T10:13:00.000Z"
}
```

`proposal_hash = sha256(JCS({proposal_id, transaction_id, mandate_id, agent_id, checkout_id, checkout_hash, payment_method}))`. The `stated` values are **not** part of the hash, because they are claims, not terms. Any change to the checkout produces a different hash, which invalidates confirmations and tokens.

Errors: `CHECKOUT_NOT_FOUND` (404), `CHECKOUT_EXPIRED` (410), `MANDATE_NOT_FOUND` (404).

Event: `PROPOSAL_SUBMITTED`.

## 7. Claim Verification Engine

### 7.1 Claim construction

Phase 1 builds claims deterministically from `stated`, the checkout, the registry and the mandate. No LLM is used.

| Claim type | Criticality | Asserted value | Authoritative source | Method | Unverified action (brief, Table 1) |
|---|---|---|---|---|---|
| `PRODUCT_IDENTITY` | CRITICAL | `stated.sku`, `stated.product_title` | Signed catalog plus checkout product line | `EXACT_MATCH` on SKU and GTIN; title similarity is informational only | Block (HG-12) |
| `PRICE` | STANDARD | Price seen on the page (from `source_ids`) | Catalog `price_minor` | `EXACT_MATCH` | Human confirmation (SU-05) |
| `TAX_AND_FEES` | STANDARD | Checkout tax and fees | Calculator recompute | `RECOMPUTE` | Human confirmation (SU-05) |
| `PAYMENT_AMOUNT` | CRITICAL | `stated.amount_minor`, `stated.currency` | Checkout `total_minor` plus calculator | `RECOMPUTE` and `EXACT_MATCH` | Block (HG-09, HG-10) |
| `MERCHANT_LEGITIMACY` | CRITICAL | `checkout.merchant_id`, `payee`, domain | Registry | `REGISTRY_LOOKUP` | Block (HG-04) |
| `DELIVERY_TERMS` | STANDARD | `stated.delivery_eta_days` | Checkout `delivery`, policy endpoint | `EXACT_MATCH` and `RULE` | Flag or block (HG-16, SU-06) |
| `RETURNS_POLICY` | STANDARD | `stated.returns_window_days` | Checkout `returns`, policy endpoint | `EXACT_MATCH` and `RULE` | Flag or block (HG-16, SU-06) |
| `USER_INSTRUCTION` | CRITICAL | Proposed action | Signed mandate (`MandateService.match`) | `MANDATE_MATCH` | Block if out of scope (HG-02 to HG-13) |
| `AGENT_REASONING` | INFORMATIONAL | `rationale_untrusted` | n/a | Stored only in Phase 1 | Not used for decisions |

### 7.2 Claim record (`schemas/claim.v1.json`)

```json
{
  "claim_id": "clm_01JD45...",
  "proposal_id": "prop_01JD43...",
  "claim_type": "PAYMENT_AMOUNT",
  "criticality": "CRITICAL",
  "asserted_value": { "amount_minor": 7649900, "currency": "INR" },
  "authoritative_value": { "amount_minor": 7649900, "currency": "INR" },
  "source_type": "MERCHANT_API",
  "source_ref": "checkout:co_01JD42...",
  "source_hash": "sha256:9c1e...",
  "source_signed": true,
  "observed_at": "2026-11-23T10:12:00.000Z",
  "method": "RECOMPUTE",
  "status": "VERIFIED",
  "confidence": 1.0,
  "fact_id": "fact_01JD46..."
}
```

Statuses: `VERIFIED`, `MISMATCH`, `UNVERIFIABLE` (no authoritative source available), `STALE` (source older than the freshness window).

Source types follow the brief: `MERCHANT_API`, `PSP_API`, `BANK_API`, `REGULATOR_REGISTRY`, `USER_INSTRUCTION`. The Phase 1 mock merchant registry is classed as `REGULATOR_REGISTRY`.

### 7.3 Confidence (Phase 1 heuristic, clearly labelled)

Confidence in Phase 1 is a **deterministic function of the verification method and the source**. It is not a learned or calibrated probability, and must not be described as calibrated in any report.

| Condition | Confidence |
|---|---|
| `EXACT_MATCH` or `RECOMPUTE` against a signed source, fresh | 1.00 |
| `EXACT_MATCH` against an unsigned structured source, fresh | 0.85 |
| `RULE`-based match (for example delivery ≤ the limit) against a signed source | 0.90 |
| `REGISTRY_LOOKUP` hit with matching payee | 1.00 |
| Any `STALE` source | Value above × 0.5 |
| `MISMATCH` or `UNVERIFIABLE` | 0.00 |

### 7.4 Deterministic calculator

```python
def reconcile(co: SignedCheckout, tax_rule: TaxRule) -> Calculation:
    product_lines = [l for l in co.lines if l.type == "PRODUCT"]
    for l in co.lines:
        assert l.amount_minor == l.unit_price_minor * l.quantity, "LINE_ARITHMETIC"
    subtotal = sum(l.amount_minor for l in product_lines)
    fees     = sum(l.amount_minor for l in co.lines if l.type in ("FEE", "SHIPPING"))
    discount = sum(l.amount_minor for l in co.lines if l.type == "DISCOUNT")   # stored negative
    tax      = tax_rule.compute(product_lines, fees)                          # half-up per line, integer
    total    = subtotal + fees + discount + tax
    return Calculation(subtotal, fees, discount, tax, total,
                       reconciled=(total == co.total_minor and tax == co.tax_minor))
```

Rules:

- Integer arithmetic only.
- `Decimal` may be used for rate application, with the result quantized to a whole minor unit (half-up).
- A currency mismatch between lines aborts with `CURRENCY_MISMATCH`.
- The calculator version is recorded (`calc-1.0.0`).

### 7.5 `POST /v1/proposals/{proposal_id}/verify`

Request: `{ "refresh": false }`. With `refresh: true`, the engine re-fetches the checkout, catalog and policies from the merchant, and recomputes everything.

Response `200` (`schemas/verification.v1.json`):

```json
{
  "verification_id": "ver_01JD47...",
  "proposal_id": "prop_01JD43...",
  "proposal_hash": "sha256:7ab2...",
  "attempt": 1,
  "checkout": {
    "checkout_id": "co_01JD42...", "checkout_hash": "sha256:9c1e...",
    "merchant_signature_valid": true, "expires_at": "2026-11-23T10:27:00.000Z"
  },
  "claims": [ { "...": "claim records, see §7.2" } ],
  "calculation": {
    "subtotal_minor": 6482966, "fees_minor": 0, "discount_minor": 0, "tax_minor": 1166934,
    "computed_total_minor": 7649900, "merchant_total_minor": 7649900,
    "agent_stated_total_minor": 7649900, "reconciled": true, "calculator_version": "calc-1.0.0"
  },
  "mandate_match": { "satisfied": true, "violations": [], "signals": ["ABOVE_APPROVAL_THRESHOLD"] },
  "selection": {
    "pricier_alternative_chosen": true,
    "cheapest_matching": { "sku": "ASUS-TUF-A15-8-512", "total_minor": 7199900 },
    "difference_minor": 450000
  },
  "trust": {
    "components": { "G": 1.00, "C": 0.97, "S": 1.00, "R": 1.00, "P": 0.95 },
    "weights": { "G": 0.30, "C": 0.15, "S": 0.20, "R": 0.10, "P": 0.25 },
    "score": 0.983,
    "band": "ALLOW",
    "trust_model_version": "trust-1.0.0"
  },
  "abstentions": [],
  "critical_unverified": [],
  "verifier_version": "verify-1.0.0",
  "created_at": "2026-11-23T10:13:01.000Z"
}
```

Abstention entry format:

```json
{ "code": "RETURNS_UNVERIFIED", "template_id": "abstain.returns_unverified",
  "params": { "merchant": "Croma Demo Retail" } }
```

Examples of the user-facing message that Team 5 renders: "I could not verify the seller's return policy." "The final price differs from the approved budget." "This merchant is not in your trusted list."

Events: `CLAIM_VERIFIED` (one per claim; payload includes the status), `VERIFICATION_COMPLETED`, `TRUST_SCORE_COMPUTED`, `ABSTENTION_RAISED`, `FACT_RECORDED`.

### 7.6 Selection sanity (factual-steering defence)

For mandates with `selection_rule = CONFIRM_IF_PRICIER_THAN_CHEAPEST_MATCHING`:

1. For each `alternatives_seen` entry, fetch the authoritative price from the catalog. Agent-supplied prices are ignored.
2. Keep only alternatives that satisfy every mandate constraint: merchant, category, delivery and returns.
3. If any alternative has a lower total than the chosen item, set `pricier_alternative_chosen = true`. Team 4 rule SU-07 then forces a STEP_UP, and the confirmation screen shows both options.

This is the only structural defence against a merchant stating a false fact ("Model A is discontinued"), because such content contains no instruction for the injection firewall to detect.

## 8. Trust Score

`TrustScore = w1·G + w2·C + w3·S + w4·R + w5·P`. All components lie in [0, 1], and higher means safer.

| Component | Definition in `trust-1.0.0` |
|---|---|
| **G**: grounding | Σ(weight × verified) / Σ weight over all non-informational claims, where CRITICAL claims weigh 3 and STANDARD claims weigh 1 |
| **C**: confidence | Mean claim confidence (§7.3), weighted as for G |
| **S**: source reliability | Mean over sources used: signed merchant API or registry 1.0; unsigned merchant API 0.7; web page 0.3 |
| **R**: freshness and consistency | 1.0 if every source is younger than 5 minutes and no claims contradict each other; decays linearly to 0 at 30 minutes; 0 if any contradiction exists (for example, page price ≠ catalog price for the chosen SKU) |
| **P**: policy and fraud safety | `(1 − site_risk_score) × injection_factor`, where `injection_factor` is 1.0 for NONE, 0.9 for LOW, 0.6 for MEDIUM and 0.2 for HIGH, taken over the referenced sources (from Team 2 `get_risk`) |

Initial weights: G 0.30, C 0.15, S 0.20, R 0.10, P 0.25. Bands are defined in [REFERENCE.md §11.3](../REFERENCE.md#113-stage-3-trust-score-bands). Team 3 computes the score. **Team 4 decides.** The score is advisory and never overrides a hard gate.

Configuration lives in `grounding/config/trust-1.0.0.yaml`. A change to weights, component definitions or thresholds creates a new version and requires team-lead approval plus a before-and-after evaluation from Team 6.

## 9. Grounded Fact Ledger

```sql
CREATE TABLE facts (
  fact_id         TEXT PRIMARY KEY,
  proposal_id     TEXT NOT NULL,
  claim_id        TEXT NOT NULL,
  statement       JSONB NOT NULL,         -- {"subject":"checkout:co_..","predicate":"total_minor","object":7649900}
  source_type     TEXT NOT NULL,          -- (2) source type
  source_ref      TEXT NOT NULL,          -- (1) machine-readable source
  source_hash     TEXT NOT NULL,          -- (3) hash of source response
  observed_at     TIMESTAMPTZ NOT NULL,   -- (4) freshness timestamp
  status          TEXT NOT NULL,          -- (5) verification status
  confidence      NUMERIC(4,3) NOT NULL,  -- (6) confidence
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Application role: INSERT, SELECT only.
```

A fact that lacks any of the six attributes cannot be inserted (`NOT NULL` constraints), so it can never enter the payment workflow (INV-04). `GET /v1/facts/{fact_id}` returns the row.

## 10. Ledger Events Emitted

`CHECKOUT_SNAPSHOT`, `CHECKOUT_SIGNATURE_INVALID`, `PROPOSAL_SUBMITTED`, `CLAIM_VERIFIED`, `FACT_RECORDED`, `VERIFICATION_COMPLETED`, `TRUST_SCORE_COMPUTED`, `ABSTENTION_RAISED`.

## 11. Testing Requirements

| Test | Type | Required by |
|---|---|---|
| Calculator matches hand-computed totals for 50 fixture checkouts, including discounts, fees and rounding edges | Unit | G2 |
| Property: any single-field mutation of a signed checkout fails signature verification | Property | G2 |
| Property: `computed_total == merchant_total` for all honest fixtures; any line change breaks reconciliation | Property | G3 |
| Agent-stated amount ≠ checkout total produces a `PAYMENT_AMOUNT` MISMATCH | Unit | G3 |
| Unregistered merchant or payee mismatch produces `MERCHANT_LEGITIMACY` MISMATCH | Unit | G3 |
| Pricier alternative detected for the factual-steering fixture | Integration | G4 |
| `refresh: true` detects a flaky merchant price change | Integration | G4 |
| Claim verification accuracy ≥ 95% on the labelled mock-catalog test set from Team 6 | Evaluation | G5 |

## 12. Milestones

| Week | Deliverable |
|---|---|
| 1–2 | Design note; `merchant.v1`, `checkout.v1`, `proposal.v1`, `claim.v1` and `verification.v1` schemas; `GroundingService` stub |
| 3–4 | Mock merchant (honest) with signed checkout; registry; snapshot storage (G2) |
| 5 | Proposals; claim construction; calculator |
| 6 | Full verification report; Fact Ledger; abstentions (G3) |
| 7 | Trust Score; selection sanity; refresh re-verification |
| 8 | Flaky merchant; integration with policy (G4) |
| 9 | Accuracy evaluation; weight tuning support |

## 13. Areas for Improvement (Phase 2)

| # | Improvement | Rationale |
|---|---|---|
| I-3.1 | **Template regeneration of agent summaries**: render the user-facing summary from verified fields, then run one LLM consistency check of the agent's free text against the record and show the template version | Removes hallucination-prone text from the decision path |
| I-3.2 | Atomic claim extraction from free-text agent output (LLM-assisted, verified deterministically) | Covers claims made outside structured fields |
| I-3.3 | **Contradiction detector** across page, catalog, checkout and policy | Strengthens R; catches drip pricing and bait-and-switch |
| I-3.4 | Calibration of confidence on a labelled dataset, reporting Expected Calibration Error with sample sizes; multicalibration by merchant and claim type once data allows | Replaces the heuristic C with an evidence-based value |
| I-3.5 | Cross-merchant price comparison for the selection rule | Stronger defence against factual steering |
| I-3.6 | Merchant Fact Contracts aligned with UCP and ACP catalog and checkout schemas | Interoperability with real merchant APIs |
| I-3.7 | Evaluate replacing the additive Trust Score with a pure decision table if the ablation shows the score adds no protective value | Avoids compensatory scoring and gameability |
| I-3.8 | Image-hash and GTIN verification against an external product database | Stronger product identity |
