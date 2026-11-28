# identity

The identity module implements the KYA design in `docs/modules/01-identity-and-mandate.md`.

## Crypto core

- Registration validates the public JWK and stores its RFC 7638 thumbprint. PyNaCl validates the Ed25519 point, not just its byte length. The thumbprint ignores labels such as `kid`.
- `verify_challenge` verifies the signature against the **registered agent key**. The caller must look up the stored nonce, check its expiry, and atomically consume it before issuing a credential.
- `issue_kya_jwt` uses the **Mandit issuer key**. Pass granted scopes from trusted registry state. The signed `cnf.jkt` identifies the agent key, not the issuer key.
- `verify_kya_jwt` checks the credential using only a local issuer key map. Supply the expected thumbprint from the independently resolved agent request key, never from the token itself. A successful return is **not** an authenticated HTTP request: status, request signature, freshness, digest, replay and scope checks still belong to the gateway pipeline.

The compact JWT may contain at most 16,384 ASCII characters, including the signature and separators. Issuance rejects larger credentials with `VALIDATION_ERROR`; verification rejects oversized input with `KYA_TOKEN_INVALID` before decoding it.

## Registration (R1, R2)

| Layer | File | Role |
|---|---|---|
| HTTP | `api.py` | FastAPI `router`: body parsing, error envelope, status codes |
| Rules | `service.py` | `RegistrationService`: authorization, operator lifecycle, scope and key checks, events |
| Storage | `repository.py`, `models.py` | `UnitOfWork` protocol; PostgreSQL implementation mapped onto the migration 0001 tables |
| Events | `events.py` | `EventSink` protocol, same arguments as `common.events.emit()` |

Design decisions:

- **Fail closed by default.** `api.get_principal` returns no caller (401) and `api.get_registration_service` returns no service (503) until the application overrides them. Console authentication and `common.events` do not exist yet, so nothing is wired by default.
- **Event and write commit together.** The service writes and emits through one `UnitOfWork`, and commits only after both succeed (REFERENCE 7.7). If the event fails, the registration is rolled back.
- **Authorization before validation, validation before the database.** A caller that may not act for an operator gets `NOT_FOUND`, the same as for a missing one, so identifiers cannot be enumerated.
- **The database is the authority for key uniqueness.** `agent_keys.thumbprint` is `UNIQUE`; a duplicate maps to `CONFLICT` and cannot race. A key identifies exactly one agent (ATK-IMP-008).
- **Locks.** Verification takes `FOR UPDATE` on the operator row, so concurrent verifies emit one event. Agent registration takes `FOR SHARE`, so a concurrent status change waits until the registration commits.
- **Strict input.** Bodies are limited to 16 KiB, must be `application/json` (which an HTML form cannot send cross-site), and may not repeat a member or contain `NaN`. Unknown fields are rejected, so a caller cannot choose `status`, `agent_id` or `scopes`. Validation errors name the field but never echo the value.
- **Synthetic data only.** Operator domains and contact emails must use reserved names (RFC 2606/6761: `*.example`, `*.test`, `*.invalid`, `*.localhost`, `example.com/net/org`). The contact email is not written to the ledger.
- **Scopes are refused, not dropped.** A requested scope outside the Phase 1 tool scopes (REFERENCE §10, without `user:ask`) fails the whole registration with `SCOPE_DENIED`.
- **Only public key members are stored.** The stored JWK is `{kty, crv, x}`; client labels such as `kid` are dropped and a JWK carrying `d` is refused.

To mount the routes, the application provides both dependencies:

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from mandit.identity import api
from mandit.identity.repository import SqlUnitOfWork
from mandit.identity.service import RegistrationService

sessions = async_sessionmaker(create_async_engine(DATABASE_URL), expire_on_commit=False)
service = RegistrationService(lambda: SqlUnitOfWork(sessions, event_sink_factory))
app.include_router(api.router)
app.dependency_overrides[api.get_registration_service] = lambda: service
app.dependency_overrides[api.get_principal] = console_or_service_principal
```

`event_sink_factory(session)` returns an `EventSink` that writes through that session; once Team 5 publishes `common.events.emit`, it is a thin adapter over it.

## Status

| Piece | Status |
|---|---|
| Ed25519 JWK validation and RFC 7638 thumbprint (`keys.py`) | Implemented |
| Challenge message and signature check (`challenge.py`) | Implemented; storage, expiry and single use are **Planned** |
| KYA JWT issue and verify (`kya_jwt.py`) | Implemented |
| `AgentContext`, `IdentityError`, `IdentityService` (`schemas.py`, `interface.py`) | Published; no `IdentityService` implementation yet |
| Operator registration, manual verification and read (`POST /v1/operators`, `GET /v1/operators/{id}`, `POST /v1/operators/{id}/verify`) | Implemented; needs console auth and `common.events` to be wired |
| Agent registration and read (`POST /v1/agents/register`, `GET /v1/agents/{id}`) | Implemented; same wiring dependency |
| Challenge and token endpoints; RFC 9421 `verify_request`; nonce store; key rotation; revocation; directory | **Planned** (later branches) |

## Tests

From the repository root, in a Python 3.12 environment with `requirements-dev.txt` installed:

```bash
python -m pytest services/core/tests/identity
```

`test_registration_postgres.py` runs only when `TEST_DATABASE_URL` is set in the environment and names a database containing `test` (for example `mandit_test` from `.env.example`). Each test builds the migration 0001 tables in its own randomly named schema and drops that schema afterwards, so the shared tables of that database are never touched. The tests check that the models match the migration, the round trip through PostgreSQL, the `UNIQUE` thumbprint under concurrent registrations, and the verification lock. Without the variable these tests are skipped.

```bash
TEST_DATABASE_URL=postgresql+psycopg://postgres:mandit@localhost:5432/mandit_test \
  python -m pytest services/core/tests/identity
```

`test_redteam_impersonation.py` replays the T2 corpus cases in `redteam/corpus/impersonation/`
(`ATK-IMP-001` to `ATK-IMP-008`) against this code. Their gateway-level steps run once the
gateway and the red-team harness exist.
