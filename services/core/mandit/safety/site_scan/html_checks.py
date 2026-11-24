"""Static HTML extraction for checkout-integrity checks.

Only the raw HTML is used here; nothing is executed. Script-driven rewrites (SUSPICIOUS_SCRIPT) need
the Playwright worker and are out of scope for this module.
"""

from __future__ import annotations

import html as html_lib
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlsplit

# Substrings that mark a form, field or iframe as payment-related.
_PAYMENT_HINT = re.compile(
    r"card|cc-?(number|csc|exp)|cvv|cvc|upi|vpa|payment|pay[-_ ]?now|checkout|\bpay\b", re.I
)
_UPI_URI = re.compile(r"upi://pay\?[^\"'\s<>]+", re.I)
_VPA = re.compile(r"^[a-z0-9.\-_]{2,256}@[a-z][a-z0-9.\-]{1,64}$", re.I)


@dataclass
class Form:
    action_url: str
    hints: list[str] = field(default_factory=list)  # attribute text used for payment detection
    vpas: list[str] = field(default_factory=list)  # VPAs set in hidden/visible inputs

    @property
    def is_payment(self) -> bool:
        return any(_PAYMENT_HINT.search(h) for h in self.hints)


@dataclass(frozen=True)
class Frame:
    src_url: str
    is_payment: bool


@dataclass
class PageStructure:
    forms: list[Form] = field(default_factory=list)
    frames: list[Frame] = field(default_factory=list)
    upi_vpas: list[str] = field(default_factory=list)  # from upi://pay?pa=... anywhere in the page

    @property
    def payment_forms(self) -> list[Form]:
        return [f for f in self.forms if f.is_payment]

    @property
    def all_vpas(self) -> list[str]:
        seen: dict[str, None] = {}
        for vpa in [*self.upi_vpas, *(v for f in self.forms for v in f.vpas)]:
            seen.setdefault(vpa.lower(), None)
        return list(seen)


_FIELD_ATTRS = ("name", "id", "autocomplete", "placeholder", "aria-label", "value")


class _Extractor(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = page_url
        self.page = PageStructure()
        self._form: Form | None = None
        self._in_button = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and a.get("href"):
            # <base href> changes where relative form actions go; attackers use it.
            self.base = urljoin(self.base, a["href"])
        elif tag == "form":
            action = urljoin(self.base, a.get("action", "")) if a.get("action") else self.base
            self._form = Form(
                action_url=action,
                hints=[
                    urlsplit(action).path,
                    a.get("id", ""),
                    a.get("name", ""),
                    a.get("class", ""),
                ],
            )
            self.page.forms.append(self._form)
        elif tag in ("input", "select", "textarea", "button") and self._form is not None:
            self._form.hints.extend(a.get(k, "") for k in _FIELD_ATTRS)
            name = (a.get("name", "") + " " + a.get("id", "")).lower()
            value = a.get("value", "").strip()
            if ("vpa" in name or a.get("name", "").lower() == "pa") and _VPA.match(value):
                self._form.vpas.append(value)
            if tag == "button":
                self._in_button = True
        elif tag == "iframe" and a.get("src"):
            src = urljoin(self.base, a["src"])
            hint = " ".join([src, a.get("name", ""), a.get("id", ""), a.get("title", "")])
            self.page.frames.append(Frame(src_url=src, is_payment=bool(_PAYMENT_HINT.search(hint))))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
        elif tag == "button":
            self._in_button = False

    def handle_data(self, data: str) -> None:
        if self._in_button and self._form is not None:
            self._form.hints.append(data.strip())


def extract_vpas_from_upi_uris(raw_html: str) -> list[str]:
    vpas = []
    for uri in _UPI_URI.findall(html_lib.unescape(raw_html)):
        for pa in parse_qs(urlsplit(uri).query).get("pa", []):
            if _VPA.match(pa.strip()):
                vpas.append(pa.strip())
    return vpas


def extract_page_structure(raw_html: str, page_url: str) -> PageStructure:
    parser = _Extractor(page_url)
    parser.feed(raw_html)
    parser.close()
    # Regex over the whole document also catches UPI links built inside inline scripts.
    parser.page.upi_vpas = extract_vpas_from_upi_uris(raw_html)
    return parser.page
