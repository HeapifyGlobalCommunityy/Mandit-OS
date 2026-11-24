"""Domain helpers: host normalisation, ownership, edit distance, confusable skeletons, look-alikes.

The confusable table is a deliberately small subset of Unicode UTS #39 (confusables.txt), covering
the Cyrillic, Greek and digit substitutions seen in shopping-site phishing. Swapping in the full
table later only changes ``_CONFUSABLES``.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit


class InvalidScanTarget(ValueError):
    """The URL cannot be scanned (no host, or a scheme other than http/https)."""


@dataclass(frozen=True)
class Host:
    ascii: str  # punycode form, what DNS and the registry use
    display: str  # unicode form, what a human sees in the address bar


def _label_to_unicode(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            return label
    return label


def _label_to_ascii(label: str) -> str:
    try:
        return label.encode("idna").decode("ascii")
    except UnicodeError:
        return label


def normalize_host(host: str) -> Host:
    host = host.strip().rstrip(".").lower()
    if not host:
        raise InvalidScanTarget("empty host")
    labels = host.split(".")
    display = ".".join(_label_to_unicode(lbl) for lbl in labels)
    ascii_ = ".".join(_label_to_ascii(lbl) for lbl in display.split("."))
    return Host(ascii=ascii_, display=display)


def parse_target(url: str) -> tuple[str, Host]:
    """Return (scheme, host) for a scannable URL, or raise InvalidScanTarget."""
    try:
        parts = urlsplit(url.strip())
    except ValueError as exc:
        raise InvalidScanTarget(f"malformed URL: {exc}") from exc
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise InvalidScanTarget(f"unsupported scheme {scheme!r}")
    if not parts.hostname:
        raise InvalidScanTarget("URL has no host")
    return scheme, normalize_host(parts.hostname)


def host_of(url: str) -> Host | None:
    """Host of an absolute http(s) URL, or None for anything else (mailto:, javascript:, ...)."""
    try:
        return parse_target(url)[1]
    except InvalidScanTarget:
        return None


def is_owned(host: str, domain: str) -> bool:
    """True if ``host`` is ``domain`` or one of its subdomains (pay.croma.x is owned by croma.x)."""
    return host == domain or host.endswith("." + domain)


def is_owned_by_any(host: str, domains: tuple[str, ...] | list[str] | frozenset[str]) -> bool:
    return any(is_owned(host, d) for d in domains)


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal-string-alignment distance: insertions, deletions, substitutions, adjacent swaps."""
    if a == b:
        return 0
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[len(b)]


_CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i", "ј": "j", "к": "k",
    "ӏ": "l", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "ѕ": "s", "т": "t", "у": "y",
    "х": "x", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    # Greek
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
    "τ": "t", "υ": "u", "χ": "x",
    # Latin look-alikes and digits
    "ı": "i", "ℓ": "l", "ł": "l", "ø": "o", "0": "o", "1": "l", "3": "e", "5": "s", "|": "l",
}  # fmt: skip
_MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"))


def skeleton(text: str) -> str:
    """Map a string to a canonical form in which visually confusable strings compare equal."""
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")  # drop accents
    text = "".join(_CONFUSABLES.get(ch, ch) for ch in text)
    for seq, rep in _MULTI:
        text = text.replace(seq, rep)
    return text


@dataclass(frozen=True)
class LookalikeMatch:
    target_domain: str
    reason: str  # HOMOGLYPH | TYPO | BRAND_EMBEDDED
    detail: str


def _brand_label(domain: str) -> str:
    labels = domain.split(".")
    return labels[1] if labels[0] == "www" and len(labels) > 2 else labels[0]


def find_lookalike(
    host: Host,
    registry_domains: list[str],
    *,
    max_edit_distance: int,
    min_brand_label_length: int,
) -> LookalikeMatch | None:
    """Return the first registry domain that ``host`` imitates, or None.

    Callers must check ownership first: a host owned by a registry domain is never a look-alike.
    """
    host_skel = skeleton(host.display)
    raw_labels = [lbl for lbl in re.split(r"[.\-]", host.display) if lbl]

    for domain in registry_domains:
        if host_skel == skeleton(domain):
            return LookalikeMatch(
                domain,
                "HOMOGLYPH",
                f"'{host.display}' renders like {domain} (confusable characters)",
            )
        dist = damerau_levenshtein(host.ascii, domain)
        if dist <= max_edit_distance:
            return LookalikeMatch(domain, "TYPO", f"Edit distance {dist} from {domain}")
        if host.ascii.startswith(domain + "."):
            return LookalikeMatch(
                domain,
                "BRAND_EMBEDDED",
                f"Registered domain {domain} used as a prefix of {host.ascii}",
            )

        brand = skeleton(_brand_label(domain))
        if len(brand) < min_brand_label_length:
            continue
        for raw in raw_labels:
            label = skeleton(raw)
            if label == brand:
                if raw != _brand_label(domain):
                    return LookalikeMatch(
                        domain,
                        "HOMOGLYPH",
                        f"Label '{raw}' renders like brand '{brand}' ({domain})",
                    )
                return LookalikeMatch(
                    domain,
                    "BRAND_EMBEDDED",
                    f"Brand label '{brand}' of {domain} on an unrelated domain",
                )
            if damerau_levenshtein(label, brand) == 1:
                return LookalikeMatch(
                    domain,
                    "TYPO",
                    f"Label '{label}' is edit distance 1 from brand '{brand}' ({domain})",
                )
    return None
