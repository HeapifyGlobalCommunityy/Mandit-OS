"""Registry and export of all Mandit OS Hard Gates (HG-01 to HG-16)."""
from mandit.policy.rules.financial_gates import (
    HG06CurrencyGate,
    HG07PerTxnCapGate,
    HG08CumulativeCapsGate,
    HG09CalculationRecomputeGate,
    HG10AgentStatementGate,
    HG13PaymentMethodGate,
)
from mandit.policy.rules.identity_gates import (
    HG01AgentIdentityGate,
    HG02MandateValidityGate,
)
from mandit.policy.rules.merchant_gates import (
    HG03MerchantAllowlistGate,
    HG04MerchantRegistryGate,
    HG05CheckoutIntegrityGate,
)
from mandit.policy.rules.safety_gates import (
    HG14PromptInjectionGate,
    HG15SiteRiskGate,
)
from mandit.policy.rules.terms_gates import (
    HG11LineTypeAndCategoryGate,
    HG12CriticalClaimsGate,
    HG16DeliveryAndReturnsGate,
)

# Canonical ordering of all 16 Hard Gates per REFERENCE §11.1
ALL_HARD_GATES = (
    HG01AgentIdentityGate(),
    HG02MandateValidityGate(),
    HG03MerchantAllowlistGate(),
    HG04MerchantRegistryGate(),
    HG05CheckoutIntegrityGate(),
    HG06CurrencyGate(),
    HG07PerTxnCapGate(),
    HG08CumulativeCapsGate(),
    HG09CalculationRecomputeGate(),
    HG10AgentStatementGate(),
    HG11LineTypeAndCategoryGate(),
    HG12CriticalClaimsGate(),
    HG13PaymentMethodGate(),
    HG14PromptInjectionGate(),
    HG15SiteRiskGate(),
    HG16DeliveryAndReturnsGate(),
)

__all__ = [
    "ALL_HARD_GATES",
    "HG01AgentIdentityGate",
    "HG02MandateValidityGate",
    "HG03MerchantAllowlistGate",
    "HG04MerchantRegistryGate",
    "HG05CheckoutIntegrityGate",
    "HG06CurrencyGate",
    "HG07PerTxnCapGate",
    "HG08CumulativeCapsGate",
    "HG09CalculationRecomputeGate",
    "HG10AgentStatementGate",
    "HG11LineTypeAndCategoryGate",
    "HG12CriticalClaimsGate",
    "HG13PaymentMethodGate",
    "HG14PromptInjectionGate",
    "HG15SiteRiskGate",
    "HG16DeliveryAndReturnsGate",
]
