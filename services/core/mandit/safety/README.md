# safety

Local design notes for this module. Spec: see docs/modules/02-safety-scanning.md.

## Web Safety Scanner (`site_scan/`)

| File | Purpose |
|---|---|
| `site_scan/config.py` + `config/site-scan-1.0.0.yaml` | Versioned weights, thresholds and per-signal on/off switches |
| `site_scan/domains.py` | Host normalisation (IDNA), ownership, Damerau-Levenshtein, confusable skeleton, look-alike matching |
| `site_scan/html_checks.py` | Static HTML extraction with browser semantics: first `<base href>`, `formaction`, `form=`, `srcdoc`, `embed`/`object`; unparseable targets fail closed |
| `site_scan/netguard.py` | Egress guard (SSRF / DNS rebinding): port allowlist, global addresses only, pinned connection |
| `site_scan/tls.py` | `TlsProbe` protocol; `SocketTlsProbe` (guarded handshake, coarse error codes, fails closed); `StaticTlsProbe` for fixtures |
| `site_scan/ports.py` | `MerchantRegistry` and `DomainReputationStore` protocols plus YAML fixture implementations |
| `site_scan/scanner.py` | `SiteScanner.scan(url, html, disabled=...)` -> `SiteScanResult` |
| `site_scan/live_reputation.py` | RDAP, Google Safe Browsing and VirusTotal lookups |
| `site_scan/registry_adapter.py` | The scanner's view of the grounding merchant registry |
| `api.py`, `service.py` | `POST /v1/safety/site-scan`, `GET /v1/safety/domain-info`, `X-Mandit-Ablation`, wiring |

Implemented signals: `DOMAIN_NOT_IN_REGISTRY`, `DOMAIN_LOOKALIKE`, `DOMAIN_NEW`, `DOMAIN_REPUTATION_BAD`,
`TLS_INVALID`, `NO_TLS`, `CHECKOUT_PAYEE_MISMATCH`, `EXTERNAL_PAYMENT_IFRAME`.
`SUSPICIOUS_SCRIPT` and `DRIP_PRICING` need the Playwright worker and are disabled in the config.

Decisions:

- One signal per code; its weight counts once however many problems it found (details are joined).
- An unregistered site owns only its own host. Any UPI payee on it is reported as a payee mismatch,
  because no registered merchant can vouch for it.
- A registered merchant owns all its registry domains and their subdomains. A `SUSPENDED` merchant
  counts as not in the registry.
- Plain HTTP is tolerated only in the `local` profile (the mock services run over HTTP).
- TLS probe failures of any kind (DNS, timeout, certificate, refused destination) are reported as
  `TLS_INVALID` with a coarse code; connection-level detail is never returned (no port-scan oracle).
- The confusable table is a subset of UTS #39, enough for Cyrillic/Greek/digit substitutions.
- Ablation header format: `X-Mandit-Ablation: domain_lookalike=off,tls_invalid=off` (signal codes,
  case-insensitive). Only `off` is accepted; refused with `ABLATION_NOT_PERMITTED` outside test/demo.

Phase 1 gaps, pending other teams:

- The merchant registry is a YAML file (`grounding/registry/merchants.yaml`). It records who owns
  a domain but does not prove it (no DNS or well-known-file challenge yet). The `cloud` profile
  refuses to start until the `merchants` and `domain_reputation` table adapters exist.
- No `SERVICE` authentication on any safety route yet (Team 1 middleware). The `cloud` profile is
  refused, so the routes are never served outside local/test/demo. The error envelope and ULIDs are
  built locally (`http.py`, `ids.py`) until `mandit.common` has them.

## Prompt Injection Firewall (`injection/`)

| File | Purpose |
|---|---|
| `injection/extract.py` | HTML to segments (text, comment, attribute, data) with static visibility analysis |
| `injection/normalize.py` | Folding for matching: invisible chars, NFKC, homoglyphs, leetspeak, letter-spacing; tag-character decoding |
| `injection/detectors.py` | Pattern families: AI-addressed, override, role, template markers, concealment, payment directives, authority claims |
| `injection/firewall.py` | Per-segment and joined-stream analysis, location-aware severity, findings, visible text |
| `config/detectors.yaml` | Detector switches and versions (`injection-1.0.0`) |

Decisions:

- Detection runs on a folded copy; nothing returned to anyone is rewritten. `visible_text` holds only
  rendered text nodes (no comments, attributes, data blocks or hidden text).
- Visible payment directives need an explicit override, an unambiguous AI addressee, or an
  AI-addressed instruction in the same sentence. Hidden ones need less. Tuned against the honest
  cases in `fixtures/injection/cases.yaml` and the site-scan fixture pages.
- Comments without instruction content produce no finding (spec says LOW; flagged in module 02).
- Fail closed: severity covers findings dropped by the cap; truncated documents are at least MEDIUM.
- Worst case on 5 MB adversarial pages is ~9 s of CPU; routes run the firewall in a worker thread.

## Content records and risk (`content/`, `interface.py`)

| File | Purpose |
|---|---|
| `interface.py` | `SafetyService` protocol, `ContentRecord` (always `UNTRUSTED`), `RiskSummary`, `RiskSignal` |
| `content/inspector.py` | `SafetyServiceImpl`: `inspect`, `get_content`, `get_risk` |
| `content/store.py` | `ContentStore` and `EventSink` ports with in-memory implementations |
| `content/classify.py` | R7 classification heuristics |

Phase 1 gaps: no SQLAlchemy store over the migration 0002 tables and no Team 5 evidence adapter yet,
so `build_safety_service` refuses the `cloud` profile. Events follow the 05 §12 payloads.

## External lookups

| Provider | Gives | Key | Notes |
|---|---|---|---|
| RDAP (`rdap.org`) | Registration date (`DOMAIN_NEW`), registrar | none | 10 requests per 10 s |
| Google Safe Browsing v4 | Listed threats (`DOMAIN_REPUTATION_BAD`) | `GOOGLE_SAFE_BROWSING_API_KEY` | non-commercial use only |
| VirusTotal v3 | 2+ malicious engines (`DOMAIN_REPUTATION_BAD`) | `VIRUS_TOTAL_API_KEY` | queries are shared with its community |

- Keys are optional. Without one that provider is skipped and absent from `reputation_lookups`; a
  rejected or rate-limited key shows as `UNAVAILABLE`. Neither stops a scan.
- VirusTotal's free API allows 4 lookups per minute and 500 per day, for non-commercial use.
- Only public host names are sent. Fixture rows win over live lookups, and `*.local`, `*.test`,
  `*.example`, `example.com` and IP addresses never leave the machine.
- A failed lookup shows as `UNAVAILABLE` in `reputation_lookups` and adds no score: an outage does
  not block every purchase, but a bad domain is not detected by that provider while it lasts.
- Results are cached in memory for one hour. `MANDIT_LIVE_LOOKUPS=off` disables all of them.

## Local test server

```bash
cp .env.example .env                  # at the repository root; add API keys if you have them
cd services/core
python -m mandit.devserver            # http://127.0.0.1:8000/docs
curl 'http://127.0.0.1:8000/v1/safety/domain-info?domain=wikipedia.org'
curl 'http://127.0.0.1:8000/v1/merchants/mer_croma_demo'
```

## Running the examples

```bash
cd services/core
python -m mandit.safety.site_scan.examples         # all prewritten cases, PASS/FAIL table
python -m mandit.safety.site_scan.examples -v fake_shop_checkout   # full JSON report
pytest tests/safety                                # unit, corpus, property, security and API tests
```

Add an example by dropping an HTML file in `fixtures/site_scan/pages/` and a case in
`fixtures/site_scan/cases.yaml`; the test suite picks it up automatically.
