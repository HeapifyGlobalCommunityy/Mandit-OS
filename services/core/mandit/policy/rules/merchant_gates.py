"""Hard Gates for Merchant and Checkout integrity (HG-03, HG-04, HG-05).

Enforces Invariants INV-03, INV-04, and INV-05.
"""

from mandit.policy.schemas import DecisionOutcome, FrozenDecisionInputs, RuleHit


class HG03MerchantAllowlistGate:
    """HG-03: Merchant or domain not in the mandate allowlist.

    Invariant INV-03: Agents may only transact with merchants explicitly permitted by the mandate.
    """

    rule_id: str = "HG-03"
    code: str = "MERCHANT_NOT_ALLOWED"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        checkout = inputs.verification.checkout
        constraints = inputs.mandate.constraints
        violations = inputs.verification.mandate_match.violations

        if "MERCHANT_NOT_ALLOWED" in violations or (
            constraints.allowed_merchants
            and checkout.merchant_id not in constraints.allowed_merchants
        ):
            return RuleHit(
                rule_id=self.rule_id,
                code="MERCHANT_NOT_ALLOWED",
                effect=self.effect,
                detail={
                    "merchant_id": checkout.merchant_id,
                    "allowed": constraints.allowed_merchants,
                },
            )

        if "DOMAIN_NOT_ALLOWED" in violations or (
            constraints.allowed_domains
            and checkout.merchant_domain not in constraints.allowed_domains
        ):
            return RuleHit(
                rule_id=self.rule_id,
                code="DOMAIN_NOT_ALLOWED",
                effect=self.effect,
                detail={"domain": checkout.merchant_domain, "allowed": constraints.allowed_domains},
            )

        return None


class HG04MerchantRegistryGate:
    """HG-04: Merchant not in registry, suspended, or payee differs from registry payee.

    Invariant INV-04: Money can only move to legitimate, verified payees matching registry.
    """

    rule_id: str = "HG-04"
    code: str = "MERCHANT_NOT_IN_REGISTRY"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        violations = inputs.verification.mandate_match.violations

        if "MERCHANT_NOT_IN_REGISTRY" in violations:
            return RuleHit(
                rule_id=self.rule_id,
                code="MERCHANT_NOT_IN_REGISTRY",
                effect=self.effect,
                detail={"merchant_id": inputs.verification.checkout.merchant_id},
            )

        if "MERCHANT_SUSPENDED" in violations:
            return RuleHit(
                rule_id=self.rule_id,
                code="MERCHANT_SUSPENDED",
                effect=self.effect,
                detail={"merchant_id": inputs.verification.checkout.merchant_id},
            )

        if "PAYEE_MISMATCH" in violations:
            return RuleHit(
                rule_id=self.rule_id,
                code="PAYEE_MISMATCH",
                effect=self.effect,
                detail={"payee_id": inputs.verification.checkout.payee_id},
            )

        return None


class HG05CheckoutIntegrityGate:
    """HG-05: Checkout signature invalid or checkout expired.

    Invariant INV-05: Financial terms must be cryptographically attested and unexpired.
    """

    rule_id: str = "HG-05"
    code: str = "CHECKOUT_SIGNATURE_INVALID"
    effect: DecisionOutcome = DecisionOutcome.BLOCK

    def evaluate(self, inputs: FrozenDecisionInputs) -> RuleHit | None:
        checkout = inputs.verification.checkout
        now = inputs.evaluated_at

        if not checkout.merchant_signature_valid:
            return RuleHit(
                rule_id=self.rule_id,
                code="CHECKOUT_SIGNATURE_INVALID",
                effect=self.effect,
                detail={"checkout_id": checkout.checkout_id, "signature_valid": False},
            )

        if now >= checkout.expires_at:
            return RuleHit(
                rule_id=self.rule_id,
                code="CHECKOUT_EXPIRED",
                effect=self.effect,
                detail={"now": now.isoformat(), "expires_at": checkout.expires_at.isoformat()},
            )

        return None
