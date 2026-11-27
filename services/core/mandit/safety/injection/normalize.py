"""Text normalisation for the Prompt Injection Firewall (modules/02 section 7.2).

Detection runs on a *folded* copy of the text, never on the text returned to anyone. Folding undoes
the cheap obfuscations attackers use to slip past keyword lists:

- invisible characters (zero-width, word joiner, BOM, bidi controls) are removed;
- Unicode tag characters U+E0020..U+E007E ("ASCII smuggling") are decoded into a separate payload,
  which is scanned as hidden content;
- NFKC compatibility folding (full-width letters, ligatures, mathematical alphanumerics);
- accents are dropped and common Cyrillic/Greek homoglyphs are mapped to Latin;
- leetspeak digits and symbols inside words (``1gn0re``) are mapped back to letters;
- letter-spaced words (``i g n o r e``, ``i.g.n.o.r.e``) are joined;
- whitespace is collapsed.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Spec 7.2 ZERO_WIDTH set, plus bidi embedding/override/isolate controls (also invisible, also used
# to reorder displayed text).
INVISIBLE_RE = re.compile("[​-‏⁠-⁤﻿‪-‮⁦-⁩\U000e0000-\U000e007f]")
_TAG_CHARS_RE = re.compile("[\U000e0020-\U000e007e]+")
# ZWNJ/ZWJ and LRM/RLM are legitimate in Indic, Arabic and Hebrew text and in emoji sequences.
_CONTEXT_SENSITIVE = {"‌", "‍", "‎", "‏"}

_HOMOGLYPHS = str.maketrans(
    {
        # Cyrillic
        "а": "a", "в": "b", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i", "ј": "j", "к": "k",
        "ӏ": "l", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "ѕ": "s", "т": "t", "у": "y",
        "х": "x", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ɡ": "g",
        # Greek
        "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
        "τ": "t", "υ": "u", "χ": "x",
        # Latin look-alikes
        "ı": "i", "ℓ": "l", "ł": "l", "ø": "o", "ß": "ss",
    }
)  # fmt: skip
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})
# A leet character only counts inside a word, so prices such as "₹64,999" are not rewritten. "@" is
# not mapped: it would corrupt UPI VPAs and e-mail addresses, which detectors need intact.
# Runs are short (<= 2 between letters, 1 at a word edge) so model numbers such as "A15" or
# "RTX4060" are not turned into words ("ais").
_LEET_IN_WORD = re.compile(
    r"(?<=[a-z])[013457$]{1,2}(?=[a-z])|(?<=[a-z]{2})[013457$](?![\w])|(?<![\w])[013457$](?=[a-z]{2})"
)
# Five or more single letters separated by one space, dot, dash, underscore or asterisk.
_SPACED = re.compile(r"\b(?:[a-z][ .\-_*]){4,}[a-z]\b")
_WS = re.compile(r"\s+")


@dataclass(frozen=True)
class InvisibleRun:
    start: int
    end: int
    chars: str


def find_invisible(text: str) -> list[InvisibleRun]:
    """Suspicious invisible characters, excluding legitimate script-joining uses."""
    runs: list[InvisibleRun] = []
    for m in re.finditer(INVISIBLE_RE.pattern + "+", text):
        chars = m.group()
        if set(chars) <= _CONTEXT_SENSITIVE:
            before = text[m.start() - 1] if m.start() > 0 else ""
            after = text[m.end()] if m.end() < len(text) else ""
            # Only suspicious when splitting a Latin word, e.g. "ig‍nore".
            if not (before.isascii() and before.isalnum() and after.isascii() and after.isalnum()):
                continue
        if chars == "﻿" and m.start() == 0:  # byte-order mark
            continue
        runs.append(InvisibleRun(m.start(), m.end(), chars))
    return runs


def decode_tag_smuggling(text: str) -> str:
    """ASCII text hidden in Unicode tag characters (invisible in every renderer)."""
    return " ".join(
        "".join(chr(ord(c) - 0xE0000) for c in m.group()) for m in _TAG_CHARS_RE.finditer(text)
    )


def strip_invisible(text: str) -> str:
    return INVISIBLE_RE.sub("", text)


def fold(text: str) -> str:
    """Canonical form used only for matching."""
    text = strip_invisible(text)
    text = unicodedata.normalize("NFKC", text).casefold()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = text.translate(_HOMOGLYPHS)
    text = _LEET_IN_WORD.sub(lambda m: m.group().translate(_LEET), text)
    text = _SPACED.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group()), text)
    return _WS.sub(" ", text).strip()


def display_excerpt(text: str, limit: int = 500) -> str:
    """Excerpt for findings: invisible characters made visible as escapes, capped at ``limit``."""
    shown = INVISIBLE_RE.sub(lambda m: f"\\u{ord(m.group()):04x}", text)
    shown = _WS.sub(" ", shown).strip()
    return shown if len(shown) <= limit else shown[: limit - 1] + "…"
