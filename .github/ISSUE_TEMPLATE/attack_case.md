---
name: Attack case
about: Propose a threat or bypass scenario for the red-team corpus (for confirmed vulnerabilities in merged code, use the README Security section)
title: "attack(<threat-class>): <short description>"
labels: ["type:test", "team:6-redteam"]
---

## Threat Class

T1–T18 per docs/REFERENCE.md Appendix C, or "New" (describe):

## Attacker

A1–A6 per docs/REFERENCE.md Appendix C:

## Scenario

Step-by-step description of the attack, using synthetic fixtures.

## Expected System Behaviour

- Outcome (BLOCK / DENIED / STEP_UP):
- Token issued: no
- Expected reason codes:
- Expected ledger events:

## Controls Under Test

Which controls should stop this (structural and detective)?

## Ablation Expectation

Should the attack still be blocked with detectors disabled? (yes / no, and why)

## Modules Involved
