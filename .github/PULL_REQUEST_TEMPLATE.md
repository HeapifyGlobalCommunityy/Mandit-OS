<!--
Pull requests must target the `main` branch.
Title format (Conventional Commits): <type>(<scope>): <summary>
Do not delete sections. Write "N/A" where a section does not apply.
See CONTRIBUTING.md §8.
-->

## Summary

<!-- What does this change do, and why? -->

## Linked Issue

Closes #

## Module(s) Changed

<!-- Module scopes from CONTRIBUTING.md §6.3, e.g. mandates, tokens -->

## Affected Modules

<!--
REQUIRED. List every OTHER module that is affected by this change or may need changes because of it.
If none, replace the table with the single word: No
-->

| Module | Owning team | Impact | Action (included here / follow-up issue #) |
|---|---|---|---|
| | | | |

## Contract Changes

- [ ] No contract change
- [ ] HTTP endpoint or MCP tool
- [ ] JSON Schema
- [ ] Service interface (`interface.py`)
- [ ] Ledger event type or payload
- [ ] Error or reason code
- [ ] Policy rule, Trust Score weight or threshold
- [ ] Breaking change (`!` in the title; `BREAKING CHANGE:` footer)

## Documentation Updated

<!-- See CONTRIBUTING.md §10. Tick every document updated in this PR. -->

- [ ] Not required (explain why):
- [ ] Module document (`docs/modules/...`)
- [ ] `docs/REFERENCE.md` (endpoint catalogue, conventions, decision model)
- [ ] `docs/REFERENCE.md Appendix C`
- [ ] `docs/REFERENCE.md` appendices / module catalogues (error codes, events, glossary, threat model)
- [ ] Module design note (`services/.../README.md`)

## Evidence

<!-- Ledger events emitted or changed by this PR. "None" if not applicable. -->

## Testing

- [ ] Unit tests added or updated
- [ ] Integration tests added or updated
- [ ] Property or concurrency tests (required for tokens, spend and ledger changes)
- [ ] Red-team corpus case added (required for security fixes and new defences)
- [ ] Tested manually in the integrated environment

How to verify:

```bash

```

## Security Checklist

- [ ] No secrets, real personal data or real payment data
- [ ] Fails closed on dependency errors
- [ ] No credential, token or raw personal data is exposed to the agent
- [ ] Money handled as integer minor units with explicit currency
- [ ] Does not weaken any safety invariant (REFERENCE §2.2), or approval is linked
- [ ] Touches security-sensitive paths (two approvals required, label `security-sensitive`)

## Screenshots / Output

<!-- Console changes, sample responses or evaluation output. -->
