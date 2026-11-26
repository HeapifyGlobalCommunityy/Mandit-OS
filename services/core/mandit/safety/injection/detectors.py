"""Instruction detectors (modules/02 section 7.2): pattern families over *folded* text.

The families are independent so a miss in one is often caught by another, and every family is
bounded (no unbounded repetition) so matching stays linear on hostile input.

- ``ai_addressed``: text addressed to an AI ("AI assistant: ...", "if you are an AI"), instruction
  overrides ("ignore previous instructions", "you are now", fake chat-template markers) and requests
  to conceal things from the user.
- ``payment_override``: directives that set or change amount, payee, VPA, card, merchant, shipping
  address or quantity. Returns the targets touched.
- ``authority_claim``: claims of pre-approval or authority ("the user has approved", "mandate
  updated", "message from the system").

A match here is a *candidate*; :mod:`firewall` decides whether it becomes a finding based on where
the text sits (visible, hidden, comment, attribute) and what else matched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_ADDRESSEE = (
    r"(?:ai|a\.i\.?|artificial intelligence|assistant|ai assistant|ai agent|agent|llm"
    r"|large language model|language model|ai model|chatbot|gpt|chatgpt|claude|gemini|copilot"
    r"|(?:ai |autonomous |automated )?(?:shopping|purchasing|buying|browsing)"
    r" (?:assistant|agent|bot)"
    r"|autonomous agent|automated (?:system|agent|buyer))s?"
)
_SENT = r"[^.!?\n]"  # stay inside one sentence

AI_ADDRESSED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass|skip|drop|abandon)\b"
            rf"{_SENT}{{0,25}}?\b(?:all|any|every|the|your|previous|prior|above|earlier|preceding|"
            r"original|system|safety|initial|existing)\b"
            rf"{_SENT}{{0,30}}?\b(?:instructions?|prompts?|rules?|directions?|directives?|guidelines?"
            r"|guardrails?|messages?|context|constraints?|polic(?:y|ies)|restrictions?|mandates?)\b"
        ),
    ),
    (
        "role_reassignment",
        re.compile(
            r"\b(?:you are now|you're now|from now on,? you|act as (?:an? )?(?:unrestricted|"
            r"different|new)|new (?:system )?instructions?\s*:|enter (?:developer|debug|admin) mode"
            r"|developer mode (?:enabled|on)|jailbreak|do anything now)\b"
        ),
    ),
    (
        "template_marker",
        re.compile(
            r"(?:<\|?(?:im_start|im_end|system|endoftext)\|?>|\[/?(?:inst|system)\]|^\s*#{2,}\s*"
            r"(?:system|instruction)s?\b|(?:^|\s)(?:system|developer)\s*(?:prompt)?\s*:\s*\w)"
        ),
    ),
    (
        "addressed",
        re.compile(
            rf"(?:^|[.!?:;\n\-\"'(\[>{{]\s*|\b(?:attention|note to|notice to|dear|hey|hi|hello|"
            rf"instructions? (?:to|for)|message (?:to|for)|to (?:the|any|all)"
            rf"|for (?:the|any|all))\s+"
            rf"(?:the |any |all |every )?){_ADDRESSEE}\b\s*(?:[:,\-]|\b(?:must|should|shall|will|"
            rf"need to|needs to|has to|have to|is required to|are required to|please|reading this))"
        ),
    ),
    (
        "conditional_addressee",
        re.compile(rf"\bif you(?: are|'re| re)? (?:an? )?{_ADDRESSEE}\b"),
    ),
    (
        "concealment",
        re.compile(
            r"\b(?:do not|don't|dont|never|without)\b"
            rf"{_SENT}{{0,15}}?\b(?:tell|telling|inform|informing|notify|notifying|mention|"
            r"mentioning|reveal|revealing|show|showing|alert|alerting|ask|asking|disclose|"
            r"disclosing|warn|warning|confirm|confirming with)\b"
            rf"{_SENT}{{0,15}}?\b(?:the )?(?:user|users|customer|human|buyer|owner|account holder|"
            r"cardholder|shopper|principal)\b"
            r"|\b(?:keep|hide) (?:this|it|these instructions)(?: secret| hidden)? from (?:the )?"
            r"(?:user|customer|human|buyer)\b"
        ),
    ),
)

# Strong override markers: wording that says a value should replace another.
# Loose override markers. "new" and "now" are deliberately absent: "Buy now" and "new model" are
# everywhere in honest (including responsively hidden) storefront copy.
_OVERRIDE = (
    r"\b(?:instead|change|changed|update|updated|replace|replaced|switch|correct|corrected|"
    r"actual|real|only valid|official|override|must|immediately)\b"
)
_DIRECTIVE = (
    r"\b(?:pay|send|transfer|remit|wire|use|set|change|update|enter|apply|charge|ship|deliver|buy|"
    r"purchase|order|add|checkout|complete|proceed|submit|select|choose|switch|replace)\b"
)
_TARGETS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "amount",
        re.compile(
            r"(?:₹|rs\.?|inr|\$|usd|€|eur)\s?\d[\d,]*(?:\.\d+)?|\d[\d,]*(?:\.\d+)?\s?(?:rupees|inr)"
            r"|\b(?:price|amount|total|cost|charge)\b"
        ),
    ),
    (
        "payee",
        re.compile(
            r"\b[a-z0-9.\-_]{2,64}@[a-z][a-z0-9]{1,30}\b(?!\.)|\b(?:payee|recipient|beneficiary|"
            r"account number|iban|ifsc|upi id|vpa|wallet address)\b"
            rf"|\b(?:pay|send|transfer|remit|wire)\b{_SENT}{{0,40}}?\bto\b"
        ),
    ),
    (
        "merchant",
        re.compile(
            rf"\b(?:buy|purchase|order|checkout|shop)\b{_SENT}{{0,30}}?\b(?:from|at|on|via)\b"
            r"|\b(?:merchant|seller|vendor|store|shop)\b"
        ),
    ),
    (
        "card",
        re.compile(r"\b(?:card|cvv|cvc|expiry)\b|\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}\b"),
    ),
    (
        "shipping_address",
        re.compile(
            rf"\b(?:ship|deliver|send)\b{_SENT}{{0,30}}?\b(?:to|address)\b"
            r"|\b(?:shipping|delivery|billing) address\b"
        ),
    ),
    (
        "quantity",
        re.compile(
            r"\b(?:quantity|qty)\b|\b(?:buy|order|add|purchase)\s\d{1,4}\s(?:units?|items?|pieces?"
            r"|pcs|copies)\b"
        ),
    ),
)
_DIRECTIVE_RE = re.compile(_DIRECTIVE)
_OVERRIDE_RE = re.compile(_OVERRIDE)
_ADDRESSEE_RE = re.compile(rf"\b{_ADDRESSEE}\b")
_VPA_LITERAL_RE = re.compile(r"\b[a-z0-9.\-_]{2,64}@[a-z][a-z0-9]{1,30}\b(?!\.)")
# Evidence strong enough for *visible* text, where honest pages say "Buy now at ₹64,999".
_FIELD = (
    r"(?:payee|recipient|beneficiary|account|bank account|upi(?: id)?|vpa|card|address|merchant|"
    r"seller|vendor|amount|price|total)"
)
_STRONG_OVERRIDE_RE = re.compile(
    rf"\b(?:instead|override|overrides|in place of)\b|\b(?:change|update|switch|replace|modify)"
    rf"(?:d|s)?\b{_SENT}{{0,20}}?\b{_FIELD}\b\s*(?:to|with|=|:|is now)\s"
    rf"|\b(?:correct|actual|real|official|only valid|new|updated|changed)\s(?:\w+\s)?{_FIELD}\b"
    r"(?!\s(?:is shown|shown))"
)
_STRICT_ADDRESSEE_RE = re.compile(
    r"\b(?:ai|a\.i\.?|llm|language model|chatbot|gpt|chatgpt|claude|gemini|copilot|ai assistant"
    r"|ai agent|shopping assistant|shopping agent|browsing agent|autonomous agent)s?\b"
)

AUTHORITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "preapproval",
        re.compile(
            r"\b(?:the |your )?(?:user|customer|owner|buyer|account holder|cardholder|human|"
            r"principal|client)s?\b(?: has| have| had|'s)?(?: already)?(?: been)? "
            r"(?:pre-?approved|approved|authori[sz]ed|confirmed|consented to|agreed to|ok'?d)\b"
            rf"{_SENT}{{0,30}}?\b(?:payment|purchase|transaction|transfer|order|amount|charge|"
            r"checkout|this|it|buying|paying|spend(?:ing)?)\b"
            r"|\b(?:user|customer|buyer|cardholder|account holder) (?:is|has been) pre-?approved"
            r"|\bpre-?(?:approved|authori[sz]ed) (?:payment|purchase|transaction|transfer|order)"
            r"|\b(?:payment|purchase|transaction|transfer|order) (?:is|has been|was) "
            r"(?:pre-?approved|already approved|already authori[sz]ed)"
        ),
    ),
    (
        "delegated_authority",
        re.compile(
            r"\bauthori[sz]ed by (?:the |your )?(?:user|customer|owner|account holder|you|mandit|"
            r"system|administrator|admin|developer|operator)\b"
        ),
    ),
    (
        "mandate_change",
        re.compile(
            r"\b(?:mandate|spending limit|spend limit|transaction limit|payment limit"
            r"|purchase limit"
            r"|merchant allowlist|allowlist|whitelist)s?\b(?: has| have)?(?: been| was| is| were)? "
            r"(?:updated|changed|extended|increased|raised|modified|replaced|removed|lifted|"
            r"expanded|waived)"
        ),
    ),
    (
        "system_message",
        re.compile(
            r"\b(?:message|instruction|notice|directive|override|note|update) from (?:the )?"
            r"(?:system|developer|developers|admin|administrator|anthropic|openai|mandit|"
            r"security team|platform|operator)\b"
            r"|\b(?:system|developer|admin|administrator) (?:override|instruction|directive)s?\b"
        ),
    ),
    (
        "confirmation_waiver",
        re.compile(
            r"\bno (?:further |additional |user )?(?:confirmation|approval|verification|consent)"
            r" (?:is |will be )?(?:needed|required|necessary)"
            r"|\b(?:skip|bypass|waive|do not ask for)\b(?: the| any)? (?:user )?(?:confirmation|"
            r"verification|approval|consent|step-?up|otp|2fa)"
        ),
    ),
)


@dataclass(frozen=True)
class Match:
    family: str
    start: int
    end: int


def find_ai_addressed(text: str) -> list[Match]:
    return [
        Match(name, m.start(), m.end())
        for name, pattern in AI_ADDRESSED_PATTERNS
        for m in pattern.finditer(text)
    ]


def find_authority_claims(text: str) -> list[Match]:
    return [
        Match(name, m.start(), m.end())
        for name, pattern in AUTHORITY_PATTERNS
        for m in pattern.finditer(text)
    ]


def _sentences(text: str) -> list[tuple[int, int]]:
    spans, start = [], 0
    for m in re.finditer(r"[.!?\n]+(?:\s|$)", text):
        spans.append((start, m.end()))
        start = m.end()
    if start < len(text):
        spans.append((start, len(text)))
    return spans


@dataclass(frozen=True)
class PaymentMatch:
    start: int
    end: int
    targets: tuple[str, ...]
    has_override: bool  # loose: "new", "now", "must", ...
    has_addressee: bool  # loose: includes "agent", "model", "bot"
    strong_override: bool  # "instead", "change the payee", "correct account", ...
    strict_addressee: bool  # unambiguous AI addressee
    has_vpa: bool  # a literal UPI VPA in the sentence


def find_payment_directives(text: str) -> list[PaymentMatch]:
    """Sentences containing a directive verb and at least one payment target.

    The evidence flags let the caller require more for visible text, where honest pages
    legitimately say "Pay ₹76,499" on a button (see ``firewall.payment_finding_applies``).
    """
    out: list[PaymentMatch] = []
    for start, end in _sentences(text):
        sentence = text[start:end]
        if not _DIRECTIVE_RE.search(sentence):
            continue
        targets = tuple(name for name, pattern in _TARGETS if pattern.search(sentence))
        if not targets:
            continue
        out.append(
            PaymentMatch(
                start,
                end,
                targets,
                has_override=bool(_OVERRIDE_RE.search(sentence)),
                has_addressee=bool(_ADDRESSEE_RE.search(sentence)),
                strong_override=bool(_STRONG_OVERRIDE_RE.search(sentence)),
                strict_addressee=bool(_STRICT_ADDRESSEE_RE.search(sentence)),
                has_vpa=bool(_VPA_LITERAL_RE.search(sentence)),
            )
        )
    return out
