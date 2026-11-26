"""Static HTML segmentation with visibility analysis (modules/02 section 7.2, HIDDEN_CSS).

The page is split into segments: text nodes, comments, instruction-bearing attributes, and data
blocks (JSON-LD). Each text segment is classified VISIBLE or HIDDEN from what a browser would
render:

- hiding elements and attributes: ``<script>``, ``<style>``, ``<template>``, ``<noscript>``,
  ``hidden``, ``<input type=hidden>``;
- inline ``style`` declarations and the rules of ``<style>`` blocks for simple selectors (tag,
  ``.class``, ``#id``, ``tag.class``; for compound selectors the last part is used, which can only
  over-report hidden text): ``display:none``, ``visibility:hidden``, ``opacity < 0.1``,
  ``font-size < 2px`` (and equivalents), off-screen positioning or ``text-indent``, zero-size boxes
  with ``overflow:hidden``, ``clip``/``clip-path`` to nothing, ``transform: scale(0)``, transparent
  text, and text whose colour is within CIE76 ΔE < 5 of its background (white is assumed when no
  background is set);
- visibility is inherited: anything inside a hidden element is hidden.

This is a static approximation of the Playwright computed-style check in the spec. It needs no
browser and runs on untrusted input with bounded work, but it does not execute scripts or resolve
external stylesheets. The Playwright worker (week 5) should feed computed visibility through the
same ``Segment`` structure when it exists.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Literal

Visibility = Literal["VISIBLE", "HIDDEN"]
SegmentKind = Literal["TEXT", "COMMENT", "ATTRIBUTE", "DATA"]

MAX_DEPTH = 256
# Input size is capped by the caller (5 MB); this is only a memory backstop. Truncation is reported
# and makes the scan fail closed (firewall.py), so padding cannot push an instruction out of view.
MAX_SEGMENTS = 1_000_000

_VOID = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
}  # fmt: skip
_HIDING_TAGS = {"script", "style", "template", "noscript", "head"}
# <head> children that render: the title is shown in the tab and read by agents.
_VISIBLE_IN_HEAD = {"title"}
_BLOCK = {
    "address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt", "fieldset",
    "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr",
    "li", "main", "nav", "ol", "p", "pre", "section", "table", "td", "th", "tr", "ul", "title",
    "button", "option", "label",
}  # fmt: skip
INSTRUCTION_ATTRS = ("alt", "title", "aria-label", "aria-description", "placeholder")
_DATA_SCRIPT_TYPES = {"application/ld+json", "application/json", "text/plain", "text/markdown"}

_SIMPLE_SELECTOR_RE = re.compile(r"^([a-z][a-z0-9-]*)?((?:[.#][a-z0-9_-]+)*)$", re.I)
_NUM_RE = re.compile(r"(-?\d*\.?\d+)\s*([a-z%]*)")


@dataclass(frozen=True)
class Segment:
    index: int
    kind: SegmentKind
    text: str
    visibility: Visibility
    hidden_reason: str | None
    selector: str
    char_start: int
    char_end: int
    attribute: str | None = None
    glue_before: bool = False  # no whitespace/block boundary before this text node
    block_before: bool = False  # a block element boundary precedes this text node


# --- CSS evaluation -------------------------------------------------------------------------------


def parse_declarations(style: str) -> dict[str, str]:
    decls: dict[str, str] = {}
    for part in style.split(";"):
        prop, sep, value = part.partition(":")
        if sep:
            value = value.replace("!important", "").strip().lower()
            decls[prop.strip().lower()] = value
    return decls


def _length(value: str) -> tuple[float, str] | None:
    m = _NUM_RE.match(value.strip())
    if not m:
        return None
    try:
        return float(m.group(1)), m.group(2)
    except ValueError:
        return None


def _tiny_font(value: str) -> bool:
    parsed = _length(value)
    if parsed is None:
        return False
    num, unit = parsed
    limits = {"px": 2.0, "pt": 1.5, "em": 0.15, "rem": 0.15, "%": 15.0, "": 0.0001,
              "vw": 0.15, "vh": 0.15, "ex": 0.3, "ch": 0.3}  # fmt: skip
    return unit in limits and num < limits[unit]


def _far_offscreen(value: str) -> bool:
    parsed = _length(value)
    return parsed is not None and parsed[0] <= -999


def _zero(value: str) -> bool:
    parsed = _length(value)
    return parsed is not None and abs(parsed[0]) <= 1 and parsed[1] in ("px", "", "em", "rem", "%")


_NAMED_COLOURS = {
    "white": (255, 255, 255), "black": (0, 0, 0), "red": (255, 0, 0), "green": (0, 128, 0),
    "blue": (0, 0, 255), "gray": (128, 128, 128), "grey": (128, 128, 128),
    "silver": (192, 192, 192), "whitesmoke": (245, 245, 245), "snow": (255, 250, 250),
    "ivory": (255, 255, 240), "ghostwhite": (248, 248, 255), "yellow": (255, 255, 0),
}  # fmt: skip
_RGB_RE = re.compile(
    r"rgba?\(\s*([\d.]+%?)[\s,]+([\d.]+%?)[\s,]+([\d.]+%?)(?:[\s,/]+([\d.]+%?))?\s*\)"
)


def parse_colour(value: str) -> tuple[tuple[int, int, int], float] | None:
    """(rgb, alpha) for hex, rgb()/rgba(), a few named colours and ``transparent``."""
    v = value.strip().lower()
    if v == "transparent":
        return (0, 0, 0), 0.0
    if v in _NAMED_COLOURS:
        return _NAMED_COLOURS[v], 1.0
    if v.startswith("#") and len(v) in (4, 5, 7, 9):
        h = v[1:]
        try:
            if len(h) in (3, 4):
                rgb = tuple(int(c * 2, 16) for c in h[:3])
                alpha = int(h[3] * 2, 16) / 255 if len(h) == 4 else 1.0
            else:
                rgb = tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))
                alpha = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
        except ValueError:
            return None
        return (rgb[0], rgb[1], rgb[2]), alpha
    m = _RGB_RE.match(v)
    if m:

        def chan(s: str) -> int:
            return round(float(s[:-1]) * 2.55) if s.endswith("%") else round(float(s))

        try:
            r, g, b = (min(255, chan(m.group(i))) for i in (1, 2, 3))
            a = m.group(4)
            alpha = 1.0 if a is None else (float(a[:-1]) / 100 if a.endswith("%") else float(a))
        except ValueError:
            return None
        return (r, g, b), alpha
    return None


def _lab(rgb: tuple[int, int, int]) -> tuple[float, float, float]:
    def lin(c: int) -> float:
        x = c / 255
        return x / 12.92 if x <= 0.04045 else ((x + 0.055) / 1.055) ** 2.4

    r, g, b = (lin(c) for c in rgb)
    x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047
    y = 0.2126 * r + 0.7152 * g + 0.0722 * b
    z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883

    def f(t: float) -> float:
        return t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116

    fx, fy, fz = f(x), f(y), f(z)
    return 116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)


def delta_e(a: tuple[int, int, int], b: tuple[int, int, int]) -> float:
    la, lb = _lab(a), _lab(b)
    return sum((p - q) ** 2 for p, q in zip(la, lb, strict=True)) ** 0.5


def hiding_reason(decls: dict[str, str]) -> str | None:
    """Why these declarations hide an element's own box, or None."""
    if decls.get("display") == "none":
        return "display:none"
    if decls.get("visibility") in ("hidden", "collapse"):
        return "visibility:hidden"
    if "opacity" in decls:
        parsed = _length(decls["opacity"])
        if parsed is not None:
            op = parsed[0] / 100 if parsed[1] == "%" else parsed[0]
            if op < 0.1:
                return "opacity<0.1"
    if "font-size" in decls and _tiny_font(decls["font-size"]):
        return "font-size<2px"
    if decls.get("position") in ("absolute", "fixed") and any(
        _far_offscreen(decls.get(side, "")) for side in ("left", "top", "right", "bottom")
    ):
        return "off-screen"
    if _far_offscreen(decls.get("text-indent", "")):
        return "off-screen"
    if "hidden" in decls.get("overflow", "") and (
        _zero(decls.get("width", "9")) or _zero(decls.get("height", "9"))
        or _zero(decls.get("max-height", "9")) or _zero(decls.get("max-width", "9"))
    ):  # fmt: skip
        return "zero-size"
    clip = decls.get("clip", "") + " " + decls.get("clip-path", "")
    if re.search(
        r"rect\(\s*0[a-z]*[\s,]+0[a-z]*[\s,]+0[a-z]*[\s,]+0|inset\(\s*50%|circle\(\s*0", clip
    ):
        return "clipped"
    if re.search(r"scale[xy]?\(\s*0(?:\.0+)?\s*[,)]", decls.get("transform", "")):
        return "scale(0)"
    return None


@dataclass
class _Style:
    hidden: str | None
    colour: tuple[tuple[int, int, int], float] | None
    background: tuple[int, int, int] | None


def _css_rules(css: str) -> list[tuple[str, str]]:
    """``selector { body }`` pairs, found with linear string splitting.

    A regex with bounded repetition here was quadratic on a large brace-free ``<style>`` block
    (1 MB took ~9 s). Nested at-rules (``@media x { .a { ... } }``) yield their inner rules.
    """
    rules: list[tuple[str, str]] = []
    for block in css.split("}"):
        selectors, sep, body = block.rpartition("{")
        if not sep:
            continue
        # For "@media x { .a" the selector is the text after the last "{" boundary.
        selectors = selectors.rpartition("{")[2].rpartition(";")[2]
        if 0 < len(selectors.strip()) <= 500:
            rules.append((selectors, body[:4000]))
    return rules


class StyleSheet:
    """Simple-selector rules from <style> blocks."""

    def __init__(self) -> None:
        self.by_tag: dict[str, dict[str, str]] = {}
        self.by_class: dict[str, dict[str, str]] = {}
        self.by_id: dict[str, dict[str, str]] = {}

    @classmethod
    def from_css(cls, css: str) -> StyleSheet:
        sheet = cls()
        for selectors, body in _css_rules(css):
            decls = parse_declarations(body)
            if not decls:
                continue
            for sel in selectors.split(","):
                parts = re.split(r"[\s>+~]+", sel.strip())
                last = re.sub(r"::?[a-z-]+(\([^)]*\))?", "", parts[-1]) if parts else ""
                m = _SIMPLE_SELECTOR_RE.match(last)
                if not m:
                    continue
                tag, rest = m.group(1), m.group(2)
                keys = re.findall(r"([.#])([a-z0-9_-]+)", rest, re.I)
                if not keys and tag:
                    sheet.by_tag.setdefault(tag.lower(), {}).update(decls)
                for kind, name in keys[-1:]:
                    target = sheet.by_class if kind == "." else sheet.by_id
                    target.setdefault(name, {}).update(decls)
        return sheet

    def declarations(self, tag: str, attrs: dict[str, str]) -> dict[str, str]:
        decls: dict[str, str] = {}
        decls.update(self.by_tag.get(tag, {}))
        for cls_name in attrs.get("class", "").split():
            decls.update(self.by_class.get(cls_name, {}))
        if attrs.get("id"):
            decls.update(self.by_id.get(attrs["id"], {}))
        decls.update(parse_declarations(attrs.get("style", "")))
        return decls


_STYLE_BLOCK_RE = re.compile(r"<style\b[^>]*>(.*?)</style\s*>", re.I | re.S)


def collect_stylesheet(raw_html: str) -> StyleSheet:
    return StyleSheet.from_css("\n".join(_STYLE_BLOCK_RE.findall(raw_html)))


# --- Segmenter ------------------------------------------------------------------------------------


@dataclass
class _Frame:
    tag: str
    hidden: str | None
    colour: tuple[tuple[int, int, int], float] | None
    background: tuple[int, int, int] | None
    selector: str
    data_script: bool = False


@dataclass
class SegmentedDocument:
    segments: list[Segment] = field(default_factory=list)
    truncated: bool = False


class _Segmenter(HTMLParser):
    def __init__(self, raw: str, sheet: StyleSheet) -> None:
        super().__init__(convert_charrefs=True)
        self.sheet = sheet
        self.doc = SegmentedDocument()
        self.stack: list[_Frame] = [_Frame("#root", None, None, None, "")]
        self.counts: list[dict[str, int]] = [{}]
        self._line_starts = [0]
        for m in re.finditer("\n", raw):
            self._line_starts.append(m.end())
        self._glue = False
        self._block = True

    # positions -----------------------------------------------------------------------------------
    def _offset(self) -> int:
        line, col = self.getpos()
        return self._line_starts[min(line - 1, len(self._line_starts) - 1)] + col

    def _add(self, kind: SegmentKind, text: str, hidden: str | None, attribute: str | None = None,
             glue: bool = False) -> None:  # fmt: skip
        if not text.strip():
            return
        if len(self.doc.segments) >= MAX_SEGMENTS:
            self.doc.truncated = True
            return
        start = self._offset()
        self.doc.segments.append(
            Segment(
                index=len(self.doc.segments),
                kind=kind,
                text=text,
                visibility="HIDDEN" if hidden else "VISIBLE",
                hidden_reason=hidden,
                selector=self.stack[-1].selector or ":root",
                char_start=start,
                char_end=start + len(text),
                attribute=attribute,
                glue_before=glue,
                block_before=self._block if kind == "TEXT" else True,
            )
        )
        if kind == "TEXT":
            self._block = False

    # element handling ----------------------------------------------------------------------------
    def _selector(self, tag: str, attrs: dict[str, str]) -> str:
        counts = self.counts[-1]
        counts[tag] = counts.get(tag, 0) + 1
        part = f"{tag}:nth-of-type({counts[tag]})"
        if attrs.get("id"):
            part = f"{tag}#{attrs['id'][:64]}"
        parent = self.stack[-1].selector
        return f"{parent} > {part}" if parent else part

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = {k.lower(): (v or "") for k, v in attrs_list}
        parent = self.stack[-1]
        decls = self.sheet.declarations(tag, attrs)
        hidden = parent.hidden
        if hidden is None:
            if tag in _HIDING_TAGS:
                hidden = f"<{tag}>"
            elif "hidden" in attrs:
                hidden = "hidden attribute"
            elif tag == "input" and attrs.get("type", "").lower() == "hidden":
                hidden = "input type=hidden"
            else:
                hidden = hiding_reason(decls)
        if parent.tag == "head" and tag in _VISIBLE_IN_HEAD and parent.hidden == "<head>":
            hidden = None
        colour = parent.colour
        background = parent.background
        if "color" in decls:
            colour = parse_colour(decls["color"]) or colour
        bg_raw = decls.get("background-color") or decls.get("background", "").split(" ")[0]
        if bg_raw:
            parsed_bg = parse_colour(bg_raw)
            if parsed_bg is not None and parsed_bg[1] >= 0.5:
                background = parsed_bg[0]
        if hidden is None and "color" in decls and colour is not None:
            rgb, alpha = colour
            if alpha < 0.1:
                hidden = "transparent text"
            elif delta_e(rgb, background or (255, 255, 255)) < 5:
                hidden = "text colour matches background"

        selector = self._selector(tag, attrs)
        # Attributes that carry text an agent may read.
        for name in INSTRUCTION_ATTRS:
            if attrs.get(name):
                self._add("ATTRIBUTE", attrs[name], hidden, attribute=name)
        for name, value in attrs.items():
            if name.startswith("data-") and value:
                self._add("ATTRIBUTE", value, hidden, attribute=name)
        if tag == "meta" and attrs.get("content"):
            self._add("ATTRIBUTE", attrs["content"], hidden, attribute="content")
        if tag == "input" and attrs.get("value") and attrs.get("type", "").lower() == "hidden":
            self._add("ATTRIBUTE", attrs["value"], hidden or "input type=hidden", attribute="value")

        if tag in _BLOCK:
            self._glue = False
            self._block = True
        if tag in _VOID or len(self.stack) >= MAX_DEPTH:
            return
        data_script = tag == "script" and attrs.get("type", "").lower() in _DATA_SCRIPT_TYPES
        self.stack.append(_Frame(tag, hidden, colour, background, selector, data_script))
        self.counts.append({})

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                del self.counts[i + 1 :]
                break
        if tag in _BLOCK:
            self._glue = False
            self._block = True

    def handle_data(self, data: str) -> None:
        frame = self.stack[-1]
        if frame.tag in ("script", "style") and not frame.data_script:
            return  # executable code and CSS are not text an agent reads
        kind: SegmentKind = "DATA" if frame.data_script else "TEXT"
        glue = self._glue and not data[:1].isspace()
        self._add(kind, data, frame.hidden, glue=glue)
        self._glue = bool(data) and not data[-1:].isspace()

    def handle_comment(self, data: str) -> None:
        self._add("COMMENT", data, "html comment")


def segment_html(raw_html: str) -> SegmentedDocument:
    seg = _Segmenter(raw_html, collect_stylesheet(raw_html))
    seg.feed(raw_html)
    seg.close()
    return seg.doc


def segment_text(text: str) -> SegmentedDocument:
    doc = SegmentedDocument()
    doc.segments.append(Segment(0, "TEXT", text, "VISIBLE", None, ":text", 0, len(text)))
    return doc


def segment_json(value: object) -> SegmentedDocument:
    """Every string in a JSON document (merchant API responses) as a visible text segment."""
    doc = SegmentedDocument()
    stack: list[tuple[str, object]] = [("", value)]
    while stack:
        pointer, node = stack.pop()
        if isinstance(node, dict):
            stack.extend((f"{pointer}/{k}", v) for k, v in reversed(list(node.items())))
        elif isinstance(node, list):
            stack.extend((f"{pointer}/{i}", v) for i, v in reversed(list(enumerate(node))))
        elif isinstance(node, str) and node.strip():
            if len(doc.segments) >= MAX_SEGMENTS:
                doc.truncated = True
                break
            doc.segments.append(
                Segment(len(doc.segments), "TEXT", node, "VISIBLE", None, pointer or "/", 0, 0)
            )
    return doc
