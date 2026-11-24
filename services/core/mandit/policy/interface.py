"""Interfaces for Mandit OS Policy Engine.

Defines protocols for individual policy rules and the pure policy engine.
"""
from typing import Protocol

from mandit.policy.schemas import (
    DecisionOutcome,
    DecisionResult,
    FrozenDecisionInputs,
    RuleHit,
)


class PolicyRule(Protocol):
    """Protocol implemented by every hard gate (HG) and step-up (SU) rule."""

    rule_id: str
    code: str
    effect: DecisionOutcome

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        """Evaluate the rule against immutable frozen decision inputs.

        Returns RuleHit if the rule fires, or None if the condition is satisfied.
        Must be a pure function with no side effects or I/O.
        """
        ...


class PolicyEngine(Protocol):
    """Pure Policy Engine protocol per docs/modules/04-policy-and-payments.md §3."""

    version: str

    def decide(self, inputs: FrozenDecisionInputs) -> DecisionResult:
        """Pure evaluation function. No I/O, no clock reads, no randomness.

        Used live by DecisionService and offline by Team 5 replay (INV-11).
        """
        ...
