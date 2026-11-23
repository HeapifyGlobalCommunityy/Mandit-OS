# Mandit OS

**A trust and security layer for agentic payments.**

Mandit OS is a mandatory authorization and evidence gateway for purchases initiated by AI agents. Before any money moves, it establishes:

- who the agent is;
- what the user actually authorized;
- whether the websites and tools involved are safe;
- whether the facts the agent relies on are true.

It then issues a narrowly scoped, single-use payment token and records a tamper-evident, replayable evidence trail for every decision.

> **Status:** Phase 1 (baseline) under active development. This is a research prototype that uses **synthetic data and simulated payment rails only**. It is not production-ready, it does not handle real funds, and it does not claim PCI compliance.

---

## The Problem

Autonomous agents now browse the web, compare prices and initiate payments for people. Existing payment security protects *credentials*. It does not protect *delegated authority*: the right of a non-human actor to spend a specific amount, at a specific place, for a specific purpose. An agent that reads a poisoned page, believes a hallucinated price, or is impersonated can move money while every credential remains technically valid.

The design rule of Mandit OS is that **security is enforced outside the model**, at the authorization and transaction boundary, because a prompt cannot protect money.

## Architecture

```mermaid
flowchart LR
    U((User)) --> C[Console<br/>mandates · approvals · audit]
    A[AI Agent] -->|signed tool calls only| G[Tool Gateway / MCP]
    subgraph M[Mandit OS Core]
      G --> I[Identity · KYA]
      G --> S[Safety Scanner ·<br/>Injection Firewall]
      G --> V[Grounding ·<br/>Claim Verification]
      V --> P[Policy Engine ·<br/>Human Confirmation]
      P --> T[Scoped Token ·<br/>Payment Orchestrator]
      I & S & V & P & T --> L[Evidence Ledger ·<br/>Replay · Explanations]
      C --> MD[Mandates]
      C --> P
      C --> L
    end
    G --> MM[Mock Merchants]
    T --> PSP[Mock PSP<br/>card · UPI]
    A -. no route .-x PSP
```

| Module | Purpose |
|---|---|
| Know Your Agent (KYA) | Verifiable agent identity, short-lived key-bound credentials, signed requests |
| Intent Mandate | User-signed constraints on what the agent may buy, where, for how much and until when |
| Web Safety Scanner | Domain, TLS and checkout-integrity risk |
| Prompt Injection Firewall | Detects hidden and AI-addressed instructions; labels all content as untrusted |
| Grounded Agent Intelligence | Verifies every money-relevant claim against authoritative sources; deterministic calculator; Trust Score; abstention |
| Policy Engine | Hard gates, step-up rules and Trust Score bands, resolved to ALLOW, STEP_UP, RETRIEVE_MORE or BLOCK |
| Human Confirmation | Signed approval bound to the exact proposal |
| Scoped Payment Token | Single-use token bound to merchant, payee, amount, currency, checkout and expiry |
| Evidence Ledger | Hash-chained, append-only evidence; deterministic replay; plain-language explanations |

The complete technical specification is in the [System Reference](docs/REFERENCE.md).

## Repository Layout

```
apps/console        Next.js console (mandates, confirmations, audit)
apps/demo-agent     Demonstration shopping agent
services/core       Mandit OS core (FastAPI modular monolith)
services/mock-*     Mock merchant and mock PSP (separate trust domains)
sdk/python          Agent SDK (request signing)
redteam/            Attack corpus, harness and reports
schemas/            Shared JSON Schemas
deploy/             Docker Compose and cloud manifests
docs/               Documentation
```

## Quick Start

```bash
git clone https://github.com/HeapifyGlobalCommunityy/Mandit-OS.git
cd Mandit-OS && git checkout develop
cp .env.example .env
make setup && make migrate && make seed
make dev          # console at http://localhost:3000, API at http://localhost:8000
make test
```

The `make` targets are introduced by the initial scaffolding pull request. See [CONTRIBUTING.md §4](CONTRIBUTING.md#4-getting-started).

## Documentation

Three documents, plus the per-team specifications they point to:

| Document | What it covers |
|---|---|
| This README | Overview, status, open questions, vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Workflow, branching, PRs, standards, and which docs to update for which change |
| [docs/REFERENCE.md](docs/REFERENCE.md) | Architecture, pipeline, conventions, endpoints, decision model, delivery gates (§15), glossary, error codes, threat model |

Per-team specifications (`docs/modules/`):

| Team | Specification |
|---|---|
| 1: Identity and Mandate | [01-identity-and-mandate.md](docs/modules/01-identity-and-mandate.md) |
| 2: Safety Scanning | [02-safety-scanning.md](docs/modules/02-safety-scanning.md) |
| 3: Grounding and Verification | [03-grounding-and-verification.md](docs/modules/03-grounding-and-verification.md) |
| 4: Policy and Payments | [04-policy-and-payments.md](docs/modules/04-policy-and-payments.md) |
| 5: Evidence and Experience | [05-evidence-and-experience.md](docs/modules/05-evidence-and-experience.md) (includes the ledger event catalogue) |
| 6: Red Team and Evaluation | [06-red-team-and-evaluation.md](docs/modules/06-red-team-and-evaluation.md) (includes the evaluation log) |

## Open Questions

| ID | Question | Needed by |
|---|---|---|
| OQ-01 | Which cloud provider and hosting budget will the demo use? | G4 |
| OQ-02 | What is the p95 latency target for automated decisions? | G1 |
| OQ-03 | What are the evidence retention period and deletion policy? | G4 |
| OQ-04 | Server-issued draft mandate IDs or client-generated ULIDs? | G1 |
| OQ-05 | Confirm metric targets (≥ 95% block rate, < 5% false blocks, ≥ 95% verification accuracy) | G1 |
| OQ-06 | Which LLM and agent framework will the demo agent use? | G2 |

## Contributing

All pull requests target the **`develop`** branch. Branch names follow `<type>/<module>/<short-description>` (for example `feature/mandates/matching-function`), and every pull request declares which other modules it affects, or states "No". See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Mandit OS uses synthetic data and simulated rails only; never deploy it with real payments, card data or personal data.

**Do not report vulnerabilities in public issues or PRs.** Use GitHub Private Vulnerability Reporting (Security tab), or message the technical lead or the Team 6 lead. Include the affected module/commit, the safety invariant violated ([REFERENCE §2.2](docs/REFERENCE.md#22-safety-invariants-frozen-at-the-week-2-gate)), reproduction steps using synthetic fixtures, and the impact. Targets: acknowledgement in 2 working days, triage in 5, fix for a violated invariant before the next gate. Fixes go on a `security/<module>/<description>` branch and add a red-team corpus case.

Never commit keys, tokens or `.env` files (the `gitleaks` hook and CI enforce this); if one leaks, rotate it immediately and report it. Attack techniques in `redteam/` are for testing this project only.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

Licensed under the [Apache License 2.0](LICENSE).
