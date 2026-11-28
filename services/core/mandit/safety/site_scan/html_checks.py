"""Static HTML extraction for checkout-integrity checks.

Only the raw HTML is used here; nothing is executed. Script-driven rewrites (SUSPICIOUS_SCRIPT) need
the Playwright worker and are out of scope for this module.

The extraction follows browser semantics where an attacker could otherwise hide a payment target:

- ``<base href>``: browsers use the **first** ``<base>`` with an ``href`` for the whole document,
  wherever it appears. URLs are therefore resolved after parsing, against that first base.
- ``formaction`` on a submit button or input overrides the form's ``action``. Every such target is
  recorded as an additional submission target of its form.
- ``form="<id>"`` attaches a field or button that sits outside a ``<form>`` element to that form.
- ``<iframe srcdoc>`` is parsed as a nested document (bounded depth); ``<frame>``, ``<embed>`` and
  ``<object data>`` are treated like iframes.
- A URL that cannot be parsed is kept as unresolvable. The scanner treats an unresolvable payment
  target as a payee problem (fail closed) instead of crashing.
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
_UPI_URI = re.compile(r"upi://pay\?[^\"'\s<>]{1,2048}", re.I)
# A UPI handle (the part after @) has no dots; an e-mail domain does. This keeps e-mail fields
# (newsletter forms) from being mistaken for payees.
_VPA = re.compile(r"^[a-z0-9.\-_]{2,256}@[a-z][a-z0-9]{1,64}$", re.I)

MAX_SRCDOC_DEPTH = 2
_FIELD_ATTRS = ("name", "id", "autocomplete", "placeholder", "aria-label", "value", "type")
_SUBMITTERS = ("button", "input")
_FRAME_SRC_ATTR = {"iframe": "src", "frame": "src", "embed": "src", "object": "data"}


def safe_urljoin(base: str | None, ref: str) -> str | None:
    """``urljoin`` that returns None instead of raising on malformed input."""
    if base is None:
        return None
    try:
        joined = urljoin(base, ref.strip())
        urlsplit(joined).port  # noqa: B018 - raises ValueError on an invalid port
    except ValueError:
        return None
    return joined


@dataclass
class Form:
    # Raw (unresolved) submission targets: the action plus every formaction of its submitters.
    raw_targets: list[str] = field(default_factory=list)
    target_urls: list[str | None] = field(default_factory=list)  # resolved; None = unparseable
    hints: list[str] = field(default_factory=list)  # attribute text used for payment detection
    vpas: list[str] = field(default_factory=list)  # VPAs set in hidden/visible inputs

    @property
    def is_payment(self) -> bool:
        return any(_PAYMENT_HINT.search(h) for h in self.hints)

    @property
    def action_url(self) -> str | None:
        """The form's own action (first target); kept for callers of the original API."""
        return self.target_urls[0] if self.target_urls else None


@dataclass(frozen=True)
class Frame:
    src_url: str | None  # None = unparseable
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


@dataclass
class _PendingFrame:
    raw_src: str
    hint: str


class _Extractor(HTMLParser):
    def __init__(self, depth: int) -> None:
        super().__init__(convert_charrefs=True)
        self.depth = depth
        self.base_href: str | None = None  # first <base href> only, as browsers do
        self.forms: list[Form] = []
        self.forms_by_id: dict[str, Form] = {}
        self.frames: list[_PendingFrame] = []
        self.srcdocs: list[str] = []
        self._form: Form | None = None
        self._button_form: Form | None = None
        self._orphans: list[tuple[str, dict[str, str], str]] = []  # (form id, attrs, tag)

    def _attach(self, form: Form, tag: str, a: dict[str, str]) -> None:
        form.hints.extend(a.get(k, "") for k in _FIELD_ATTRS)
        name = (a.get("name", "") + " " + a.get("id", "")).lower()
        value = a.get("value", "").strip()
        # Any input value shaped like a VPA is a payee, whatever the field is called.
        if value and (_VPA.match(value) or ("vpa" in name and "@" in value)):
            form.vpas.append(value)
        if tag in _SUBMITTERS and "formaction" in a:
            form.raw_targets.append(a["formaction"])

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and "href" in a and self.base_href is None:
            self.base_href = a["href"]
        elif tag == "form":
            form = Form(
                raw_targets=[a.get("action", "")],
                hints=[a.get("action", ""), a.get("id", ""), a.get("name", ""), a.get("class", "")],
            )
            self.forms.append(form)
            if a.get("id"):
                self.forms_by_id.setdefault(a["id"], form)
            self._form = form
        elif tag in ("input", "select", "textarea", "button"):
            target_form = self._form
            if a.get("form"):
                # An explicit form= wins over the enclosing form (HTML spec).
                self._orphans.append((a["form"], a, tag))
                target_form = None
            if target_form is not None:
                self._attach(target_form, tag, a)
            if tag == "button":
                self._button_form = target_form
        elif tag in _FRAME_SRC_ATTR:
            hint = " ".join([a.get("name", ""), a.get("id", ""), a.get("title", "")])
            src = a.get(_FRAME_SRC_ATTR[tag], "")
            if src:
                self.frames.append(_PendingFrame(raw_src=src, hint=hint))
            if tag == "iframe" and a.get("srcdoc") and self.depth < MAX_SRCDOC_DEPTH:
                self.srcdocs.append(a["srcdoc"])

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Browsers ignore the "/" on non-void elements: <form/> still opens a form.
        self.handle_starttag(tag, attrs)
        if tag == "button":
            self._button_form = None

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None
        elif tag == "button":
            self._button_form = None

    def handle_data(self, data: str) -> None:
        if self._button_form is not None and data.strip():
            self._button_form.hints.append(data.strip())

    def finish(self) -> None:
        for form_id, a, tag in self._orphans:
            form = self.forms_by_id.get(form_id)
            if form is not None:
                self._attach(form, tag, a)


def extract_vpas_from_upi_uris(raw_html: str) -> list[str]:
    vpas = []
    for uri in _UPI_URI.findall(html_lib.unescape(raw_html)):
        try:
            query = urlsplit(uri).query
        except ValueError:
            continue
        for pa in parse_qs(query).get("pa", []):
            if _VPA.match(pa.strip()):
                vpas.append(pa.strip())
    return vpas


def _extract(raw_html: str, page_url: str, depth: int) -> PageStructure:
    parser = _Extractor(depth)
    parser.feed(raw_html)
    parser.close()
    parser.finish()

    base = page_url if parser.base_href is None else safe_urljoin(page_url, parser.base_href)
    page = PageStructure()
    for form in parser.forms:
        # An empty action submits to the document URL (not the base URL).
        form.target_urls = [
            safe_urljoin(base, raw) if raw.strip() else page_url for raw in form.raw_targets
        ]
        page.forms.append(form)
    for pending in parser.frames:
        src = safe_urljoin(base, pending.raw_src)
        hint = " ".join([src or pending.raw_src, pending.hint])
        page.frames.append(Frame(src_url=src, is_payment=bool(_PAYMENT_HINT.search(hint))))

    for srcdoc in parser.srcdocs:
        # srcdoc content is same-origin with the embedding page; its forms count as the page's.
        nested = _extract(srcdoc, page_url, depth + 1)
        page.forms.extend(nested.forms)
        page.frames.extend(nested.frames)
        page.upi_vpas.extend(nested.upi_vpas)

    # Regex over the whole document also catches UPI links built inside inline scripts.
    page.upi_vpas.extend(extract_vpas_from_upi_uris(raw_html))
    return page


def extract_page_structure(raw_html: str, page_url: str) -> PageStructure:
    return _extract(raw_html, page_url, depth=0)
