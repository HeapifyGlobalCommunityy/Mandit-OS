# safety

Local design notes for this module. Spec: see docs/modules/02-safety-scanning.md.

## Web Safety Scanner (`site_scan/`)

| File | Purpose |
|---|---|
| `site_scan/config.py` + `config/site-scan-1.0.0.yaml` | Versioned weights, thresholds and per-signal on/off switches |
| `site_scan/domains.py` | Host normalisation (IDNA), ownership, Damerau-Levenshtein, confusable skeleton, look-alike matching |
| `site_scan/html_checks.py` | Static HTML extraction: payment forms (honours `<base href>`), payment iframes, UPI payees |
| `site_scan/tls.py` | `TlsProbe` protocol; `SocketTlsProbe` (real handshake, fails closed); `StaticTlsProbe` for fixtures |
| `site_scan/ports.py` | `MerchantRegistry` and `DomainReputationStore` protocols plus YAML fixture implementations |
| `site_scan/scanner.py` | `SiteScanner.scan(url, html, disabled=...)` -> `SiteScanResult` |
| `api.py`, `service.py` | `POST /v1/safety/site-scan`, `X-Mandit-Ablation` handling, Phase 1 wiring |

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
- TLS probe failures of any kind (DNS, timeout, certificate) are reported as `TLS_INVALID`.
- The confusable table is a subset of UTS #39, enough for Cyrillic/Greek/digit substitutions.
- Ablation header format: `X-Mandit-Ablation: domain_lookalike=off,tls_invalid=off` (signal codes,
  case-insensitive). Only `off` is accepted; refused with `ABLATION_NOT_PERMITTED` outside test/demo.

Phase 1 gaps, pending other teams:

- Registry and reputation are fixture-backed (`fixtures/site_scan/`). The `cloud` profile refuses to
  build the scanner until the Team 3 registry adapter exists. Look-alike detection needs a
  `list_domains()` call that Team 3's published interface does not have yet.
- No `SERVICE` authentication on the route yet (Team 1 middleware), no `SITE_SCANNED` ledger event
  (needs `mandit.common` events), and the error envelope is built locally until `mandit.common` has it.

## Running the examples

```bash
cd services/core
python -m mandit.safety.site_scan.examples         # all prewritten cases, PASS/FAIL table
python -m mandit.safety.site_scan.examples -v fake_shop_checkout   # full JSON report
pytest tests/safety                                # unit + example + API tests
```

Add an example by dropping an HTML file in `fixtures/site_scan/pages/` and a case in
`fixtures/site_scan/cases.yaml`; the test suite picks it up automatically.
