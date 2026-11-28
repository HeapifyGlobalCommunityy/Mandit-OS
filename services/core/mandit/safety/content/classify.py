"""Content classification (modules/02 R7). Coarse, deterministic heuristics over URL and text.

The class is descriptive metadata for Team 3 and the console. Nothing is trusted because of it.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from ..interface import Classification, SourceType

_CHECKOUT_PATH = re.compile(r"/(?:checkout|cart|basket|payment|pay)(?:/|$|\?)", re.I)
_POLICY_PATH = re.compile(
    r"(?:polic(?:y|ies)|terms|returns?|refunds?|privacy|shipping-info|tos)", re.I
)
_REVIEW_PATH = re.compile(r"/reviews?(?:/|$)", re.I)
_SEARCH_PATH = re.compile(r"/(?:search|s|find)(?:/|$)", re.I)
_PRICE = re.compile(r"(?:₹|rs\.?|inr|\$|€)\s?\d", re.I)
_BUY = re.compile(r"\b(?:add to (?:cart|bag|basket)|buy now|in stock|out of stock)\b", re.I)
_PAYMENT_FIELDS = re.compile(r"\b(?:card number|cvv|upi id|pay now|place order)\b", re.I)
_POLICY_TEXT = re.compile(r"\b(?:return policy|refund policy|terms (?:and|&) conditions)\b", re.I)
_REVIEW_TEXT = re.compile(r"\b(?:\d(?:\.\d)? out of 5|customer reviews|verified purchase)\b", re.I)


def classify(source_type: SourceType, url: str, visible_text: str) -> Classification:
    if source_type == "SEARCH_RESULT":
        return "SEARCH_RESULT"
    try:
        parts = urlsplit(url)
        path, query = parts.path, parse_qs(parts.query)
    except ValueError:
        path, query = "", {}
    text = visible_text[:20_000]
    if _CHECKOUT_PATH.search(path) or _PAYMENT_FIELDS.search(text):
        return "CHECKOUT"
    if _SEARCH_PATH.search(path) or "q" in query or "query" in query:
        return "SEARCH_RESULT"
    if _REVIEW_PATH.search(path) or len(_REVIEW_TEXT.findall(text)) >= 2:
        return "REVIEW"
    if _POLICY_PATH.search(path) or _POLICY_TEXT.search(text[:2_000]):
        return "POLICY"
    if _PRICE.search(text) and _BUY.search(text):
        return "PRODUCT_PAGE"
    return "OTHER"
