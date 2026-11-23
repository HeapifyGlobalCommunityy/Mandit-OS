---
name: Bug report
about: Report a defect in existing behaviour (not for security vulnerabilities; see the README Security section)
title: "bug(<scope>): <short description>"
labels: ["type:bug"]
---

## Description

A clear description of the defect.

## Module and Team

- Module scope:
- Owning team:

## Steps to Reproduce

1.
2.
3.

Use synthetic fixtures only. Include request and response bodies (redact tokens and signatures).

## Expected Behaviour

## Actual Behaviour

## Environment

- Commit SHA:
- Profile (local / test / demo / cloud):
- Relevant versions (`policy_version`, `trust_model_version`, `scanner_version`):

## Evidence

Transaction ID, relevant ledger event IDs, and logs (with `request_id`).

## Other Modules Possibly Affected

List the modules, or write "No".

## Invariant Impact

Does this violate a safety invariant (REFERENCE §2.2)? If yes, **stop** and report it privately per the README Security section instead.
