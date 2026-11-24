"""Hard Gates for Financial constraints, Arithmetic, and Caps (HG-06, HG-07, HG-08, HG-09, HG-10, HG-13).

Enforces Invariants INV-02 and INV-06.
"""
from mandit.policy.schemas import DecisionOutcome, FrozenDecisionInputs, RuleHit


class HG06CurrencyGate:
    """HG-06: Currency differs from the mandate currency.

    Invariant INV-02: Mandate currency constraint is strictly enforced.
    """
    rule_id: str = "HG-06"
    code: str = "CURRENCY_MISMATCH"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        checkout_currency = inputs.verification.checkout.currency
        mandate_currency = inputs.mandate.constraints.currency
        violations = inputs.verification.mandate_match.violations

        if "CURRENCY_MISMATCH" in violations or checkout_currency != mandate_currency:
            return RuleHit(
                rule_id=self.rule_id,
                code="CURRENCY_MISMATCH",
                effect=self.effect,
                detail={"expected": mandate_currency, "actual": checkout_currency},
            )
        return None


class HG07PerTxnCapGate:
    """HG-07: Total exceeds the per-transaction cap.

    Invariant INV-02: Single transaction spend cap cannot be bypassed.
    """
    rule_id: str = "HG-07"
    code: str = "OVER_TXN_CAP"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        amount_minor = inputs.verification.checkout.amount_minor
        cap_minor = inputs.mandate.constraints.max_amount_per_txn_minor
        violations = inputs.verification.mandate_match.violations

        if "OVER_TXN_CAP" in violations or (cap_minor > 0 and amount_minor > cap_minor):
            return RuleHit(
                rule_id=self.rule_id,
                code="OVER_TXN_CAP",
                effect=self.effect,
                detail={"amount_minor": amount_minor, "cap_minor": cap_minor},
            )
        return None


class HG08CumulativeCapsGate:
    """HG-08: Cumulative spend or transaction count would exceed the mandate.

    Invariant INV-02: Total budget and usage limits cannot be exceeded.
    """
    rule_id: str = "HG-08"
    code: str = "OVER_TOTAL_CAP"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        mandate = inputs.mandate
        checkout = inputs.verification.checkout
        constraints = mandate.constraints
        violations = inputs.verification.mandate_match.violations

        # Check total amount cap
        if "OVER_TOTAL_CAP" in violations or (
            constraints.max_amount_total_minor > 0
            and mandate.spent_minor + checkout.amount_minor > constraints.max_amount_total_minor
        ):
            return RuleHit(
                rule_id=self.rule_id,
                code="OVER_TOTAL_CAP",
                effect=self.effect,
                detail={
                    "spent_minor": mandate.spent_minor,
                    "order_minor": checkout.amount_minor,
                    "total_cap_minor": constraints.max_amount_total_minor,
                },
            )

        # Check transaction count cap
        if "TXN_COUNT_EXCEEDED" in violations or (
            constraints.max_txn_count > 0
            and mandate.spend_count + 1 > constraints.max_txn_count
        ):
            return RuleHit(
                rule_id=self.rule_id,
                code="TXN_COUNT_EXCEEDED",
                effect=self.effect,
                detail={"current_count": mandate.spend_count, "max_count": constraints.max_txn_count},
            )

        return None


class HG09CalculationRecomputeGate:
    """HG-09: Deterministic recompute differs from the merchant total or arithmetic unreconciled.

    Invariant INV-06: Totals must be deterministically proven by line item arithmetic.
    """
    rule_id: str = "HG-09"
    code: str = "TOTAL_RECOMPUTE_MISMATCH"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        calc = inputs.verification.calculation

        if (not calc.reconciled) or (calc.computed_total_minor != calc.merchant_total_minor):
            return RuleHit(
                rule_id=self.rule_id,
                code="TOTAL_RECOMPUTE_MISMATCH",
                effect=self.effect,
                detail={
                    "computed_total_minor": calc.computed_total_minor,
                    "merchant_total_minor": calc.merchant_total_minor,
                    "reconciled": calc.reconciled,
                },
            )
        return None


class HG10AgentStatementGate:
    """HG-10: Agent-stated amount, currency or merchant differs from the signed checkout.

    Invariant INV-06: Agent proposal must faithfully reflect the merchant checkout.
    """
    rule_id: str = "HG-10"
    code: str = "AGENT_AMOUNT_MISMATCH"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        calc = inputs.verification.calculation
        checkout = inputs.verification.checkout

        # Amount mismatch
        if calc.agent_stated_total_minor != calc.merchant_total_minor:
            return RuleHit(
                rule_id=self.rule_id,
                code="AGENT_AMOUNT_MISMATCH",
                effect=self.effect,
                detail={
                    "agent_stated_minor": calc.agent_stated_total_minor,
                    "merchant_total_minor": calc.merchant_total_minor,
                },
            )

        # Currency mismatch (if agent explicitly stated currency)
        if calc.agent_stated_currency and calc.agent_stated_currency != checkout.currency:
            return RuleHit(
                rule_id=self.rule_id,
                code="AGENT_AMOUNT_MISMATCH",
                effect=self.effect,
                detail={
                    "agent_stated_currency": calc.agent_stated_currency,
                    "checkout_currency": checkout.currency,
                },
            )

        # Merchant mismatch (if agent explicitly stated merchant_id)
        if calc.agent_stated_merchant_id and calc.agent_stated_merchant_id != checkout.merchant_id:
            return RuleHit(
                rule_id=self.rule_id,
                code="AGENT_MERCHANT_MISMATCH",
                effect=self.effect,
                detail={
                    "agent_stated_merchant": calc.agent_stated_merchant_id,
                    "checkout_merchant": checkout.merchant_id,
                },
            )

        return None


class HG13PaymentMethodGate:
    """HG-13: Payment method not allowed by the mandate.

    Invariant INV-02: Payment rails are constrained by user consent.
    """
    rule_id: str = "HG-13"
    code: str = "PAYMENT_METHOD_NOT_ALLOWED"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        violations = inputs.verification.mandate_match.violations
        allowed_methods = inputs.mandate.constraints.payment_methods
        chosen_method = inputs.payment_method

        if "PAYMENT_METHOD_NOT_ALLOWED" in violations or (
            allowed_methods and chosen_method not in allowed_methods
        ):
            return RuleHit(
                rule_id=self.rule_id,
                code="PAYMENT_METHOD_NOT_ALLOWED",
                effect=self.effect,
                detail={"chosen_method": chosen_method, "allowed_methods": allowed_methods},
            )
        return None
