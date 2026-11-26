"""Prompt Injection Firewall (modules/02 section 7): is this content trying to manipulate the agent?

Layers, each independent of the others:

1. **Structure** (:mod:`extract`): which text a human would see. Hidden text, comments,
   attributes and data blocks are separate segments with their own location.
2. **Normalisation** (:mod:`normalize`): zero-width characters, homoglyphs, leetspeak, full-width
   letters and letter-spacing are undone before matching; Unicode tag-character payloads are
   decoded.
3. **Detection** (:mod:`detectors`): independent pattern families, run on every segment **and** on
   joined streams of segments, so an instruction split across elements (``ig<b>nore</b> previous``,
   or several hidden spans) is still seen.
4. **Severity** (this module): the spec 7.2 table, driven by where the text sits.

The firewall never rewrites or "cleans" content into something trusted. It returns structured
evidence plus the visible text; hidden text is never part of ``visible_text``.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from ..ids import new_id
from .detectors import (
    PaymentMatch,
    find_ai_addressed,
    find_authority_claims,
    find_payment_directives,
)
from .extract import Segment, SegmentedDocument, segment_html, segment_json, segment_text
from .normalize import decode_tag_smuggling, display_excerpt, find_invisible, fold, strip_invisible

Severity = Literal["NONE", "LOW", "MEDIUM", "HIGH"]
Location = Literal["VISIBLE", "HIDDEN", "COMMENT", "ATTRIBUTE", "DATA", "SMUGGLED"]

SEVERITY_ORDER: dict[str, int] = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
DETECTOR_TECHNIQUE = {
    "hidden_text": "HIDDEN_CSS",
    "zero_width": "ZERO_WIDTH",
    "html_comment": "HTML_COMMENT",
    "attribute_text": "ATTRIBUTE_TEXT",
    "ai_addressed": "AI_ADDRESSED_INSTRUCTION",
    "payment_override": "PAYMENT_FIELD_OVERRIDE",
    "authority_claim": "AUTHORITY_CLAIM",
}
DETECTORS = tuple(DETECTOR_TECHNIQUE)
SUPPORTED_MIME_TYPES = ("text/html", "application/xhtml+xml", "text/plain", "application/json")
MAX_FINDINGS = 200
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "detectors.yaml"

_LOCATION_TECHNIQUE = {
    "HIDDEN": ("hidden_text", "HIDDEN_CSS"),
    "DATA": ("hidden_text", "HIDDEN_CSS"),
    "COMMENT": ("html_comment", "HTML_COMMENT"),
    "ATTRIBUTE": ("attribute_text", "ATTRIBUTE_TEXT"),
    "SMUGGLED": ("zero_width", "ZERO_WIDTH"),
}
_LOCATION_RANK = {"VISIBLE": 0, "ATTRIBUTE": 1, "DATA": 2, "COMMENT": 3, "HIDDEN": 4, "SMUGGLED": 5}
_AI_CONFIDENCE = {
    "instruction_override": 0.9,
    "role_reassignment": 0.85,
    "template_marker": 0.85,
    "addressed": 0.8,
    "conditional_addressee": 0.85,
    "concealment": 0.85,
}


class UnsupportedContent(ValueError):
    """The MIME type is not supported, or the body does not parse as that type."""


@dataclass(frozen=True)
class FirewallConfig:
    firewall_version: str
    enabled: frozenset[str]
    versions: dict[str, str]


def load_firewall_config(path: Path = DEFAULT_CONFIG_PATH) -> FirewallConfig:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    detectors = raw.get("detectors") or {}
    if set(detectors) != set(DETECTORS):
        raise ValueError(f"detector set mismatch: {sorted(set(detectors) ^ set(DETECTORS))}")
    return FirewallConfig(
        firewall_version=str(raw["firewall_version"]),
        enabled=frozenset(n for n, d in detectors.items() if d.get("enabled", True)),
        versions={n: str(d.get("version", "1.0.0")) for n, d in detectors.items()},
    )


@dataclass(frozen=True)
class Finding:
    finding_id: str
    technique: str
    severity: Severity
    targets: tuple[str, ...]
    locator: dict[str, Any]
    excerpt: str
    confidence: float
    location: Location
    pattern: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "technique": self.technique,
            "severity": self.severity,
            "targets": list(self.targets),
            "locator": self.locator,
            "excerpt": self.excerpt,
            "confidence": self.confidence,
            "location": self.location,
            "pattern": self.pattern,
        }


@dataclass(frozen=True)
class Chunk:
    chunk_id: str
    text: str
    visibility: Literal["VISIBLE", "HIDDEN"]
    kind: str
    flags: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"chunk_id": self.chunk_id, "text": self.text, "visibility": self.visibility,
                "kind": self.kind, "flags": list(self.flags)}  # fmt: skip


@dataclass(frozen=True)
class InjectionReport:
    injection_detected: bool
    severity: Severity
    findings: tuple[Finding, ...]
    visible_text: str
    visible_text_hash: str
    chunks: tuple[Chunk, ...]
    firewall_version: str
    detector_versions: dict[str, str]
    detectors_enabled: tuple[str, ...]
    truncated: bool

    def to_dict(self) -> dict[str, Any]:
        """Response body of POST /v1/safety/injection-scan (modules/02 section 7.1)."""
        return {
            "injection_detected": self.injection_detected,
            "severity": self.severity,
            "findings": [f.to_dict() for f in self.findings],
            "visible_text_hash": self.visible_text_hash,
            "detector_versions": self.detector_versions,
            "detectors_enabled": list(self.detectors_enabled),
            "firewall_version": self.firewall_version,
            "truncated": self.truncated,
        }


# --- analysis units -------------------------------------------------------------------------------


@dataclass
class _Unit:
    """Folded text with a map from folded offsets back to segments."""

    text: str
    pieces: list[tuple[int, int, int]] = field(default_factory=list)  # (start, end, segment index)
    smuggled: bool = False

    def segments_for(self, start: int, end: int) -> list[int]:
        return [idx for s, e, idx in self.pieces if s < end and e > start] or [
            self.pieces[0][2] if self.pieces else 0
        ]


def _unit(segments: Iterable[Segment], glue: bool, folds: dict[int, str]) -> _Unit:
    unit = _Unit("")
    parts: list[str] = []
    pos = 0
    for seg in segments:
        folded = folds.get(seg.index)
        if folded is None:
            folded = folds[seg.index] = fold(seg.text)
        if not folded:
            continue
        if parts:
            # A block boundary is a sentence boundary: "Add to cart" in one block and a price in
            # another are not one directive.
            sep = "" if (glue and seg.glue_before) else ("\n" if seg.block_before else " ")
            parts.append(sep)
            pos += len(sep)
        parts.append(folded)
        unit.pieces.append((pos, pos + len(folded), seg.index))
        pos += len(folded)
    unit.text = "".join(parts)
    return unit


def _location(seg: Segment, hidden_text_on: bool) -> Location:
    if seg.kind == "COMMENT":
        return "COMMENT"
    if seg.kind == "ATTRIBUTE":
        return "ATTRIBUTE"
    if seg.kind == "DATA":
        return "DATA"
    if seg.visibility == "HIDDEN" and hidden_text_on:
        return "HIDDEN"
    return "VISIBLE"


def payment_finding_applies(pm: PaymentMatch, location: Location) -> bool:
    """Evidence needed before a payment directive is a finding.

    Visible text must carry an explicit override ("instead", "change the payee") or an unambiguous
    AI addressee: honest checkouts say "Pay ₹76,499" in plain sight. Non-visible text needs less,
    because legitimate pages have no reason to hide payment directives, but still more than a bare
    "deliver to" so that responsively hidden marketing copy does not fire.
    """
    if location == "VISIBLE":
        return pm.strong_override or pm.strict_addressee
    return pm.strong_override or pm.has_addressee or pm.has_override or pm.has_vpa


# --- firewall -------------------------------------------------------------------------------------


class InjectionFirewall:
    def __init__(self, config: FirewallConfig | None = None) -> None:
        self._cfg = config or load_firewall_config()

    @property
    def config(self) -> FirewallConfig:
        return self._cfg

    def scan(
        self,
        raw: str,
        mime_type: str = "text/html",
        *,
        disabled: frozenset[str] = frozenset(),
    ) -> InjectionReport:
        unknown = disabled - set(DETECTORS)
        if unknown:
            raise ValueError(f"unknown detectors: {sorted(unknown)}")
        enabled = self._cfg.enabled - disabled
        doc = self._segment(raw, mime_type)
        segments = [
            s
            for s in doc.segments
            if not (s.kind == "COMMENT" and "html_comment" not in enabled)
            and not (s.kind == "ATTRIBUTE" and "attribute_text" not in enabled)
        ]
        by_index = {s.index: s for s in doc.segments}
        hidden_on = "hidden_text" in enabled

        builder = _FindingBuilder(by_index, hidden_on, enabled)
        folds: dict[int, str] = {}
        # 1. every segment on its own
        for seg in segments:
            builder.analyse(_unit([seg], glue=False, folds=folds), split=False)
        # 2. joined streams (split instructions)
        text_segs = [s for s in segments if s.kind in ("TEXT", "DATA")]
        visible = [s for s in text_segs if s.visibility == "VISIBLE"]
        hidden = [s for s in text_segs if s.visibility == "HIDDEN"]
        for stream in (visible, hidden, text_segs):
            if len(stream) > 1:
                builder.analyse(_unit(stream, glue=True, folds=folds), split=True)
                builder.analyse(_unit(stream, glue=False, folds=folds), split=True)
        for kind in ("COMMENT", "ATTRIBUTE"):
            stream = [s for s in segments if s.kind == kind]
            if len(stream) > 1:
                builder.analyse(_unit(stream, glue=False, folds=folds), split=True)
        # 3. zero-width characters and tag-character smuggling
        if "zero_width" in enabled:
            smuggled_parts = []
            for seg in doc.segments:
                payload = decode_tag_smuggling(seg.text)
                if payload.strip():
                    smuggled_parts.append((seg, payload))
            for seg, payload in smuggled_parts:
                unit = _Unit(fold(payload), [(0, len(fold(payload)), seg.index)], smuggled=True)
                builder.analyse(unit, split=False)
            builder.zero_width(doc.segments, {s.index for s, _ in smuggled_parts})

        findings = builder.finish()
        # Severity covers every hit, including findings dropped by the MAX_FINDINGS cap.
        severity: Severity = builder.max_severity
        if doc.truncated and SEVERITY_ORDER[severity] < SEVERITY_ORDER["MEDIUM"]:
            # Part of the document was not analysed: fail closed instead of reporting it clean.
            severity = "MEDIUM"
        visible_text = _visible_text(doc.segments)
        flags: dict[int, set[str]] = {}
        for f in findings:
            for idx in f.locator.get("segments", []):
                flags.setdefault(idx, set()).add(f.technique)
        chunks = tuple(
            Chunk(
                chunk_id=f"chk_{seg.index:05d}",
                text=_clean(seg.text),
                visibility="VISIBLE"
                if seg.kind == "TEXT" and seg.visibility == "VISIBLE"
                else "HIDDEN",
                kind=seg.kind,
                flags=tuple(sorted(flags.get(seg.index, ()))),
            )
            for seg in doc.segments
        )
        return InjectionReport(
            injection_detected=bool(findings) or severity != "NONE",
            severity=severity,
            findings=findings,
            visible_text=visible_text,
            visible_text_hash="sha256:" + hashlib.sha256(visible_text.encode()).hexdigest(),
            chunks=chunks,
            firewall_version=self._cfg.firewall_version,
            detector_versions={n: self._cfg.versions[n] for n in DETECTORS},
            detectors_enabled=tuple(n for n in DETECTORS if n in enabled),
            truncated=doc.truncated or builder.truncated,
        )

    @staticmethod
    def _segment(raw: str, mime_type: str) -> SegmentedDocument:
        mime = mime_type.split(";", 1)[0].strip().lower()
        if mime in ("text/html", "application/xhtml+xml"):
            return segment_html(raw)
        if mime == "text/plain":
            return segment_text(raw)
        if mime == "application/json":
            try:
                return segment_json(json.loads(raw))
            except (ValueError, RecursionError) as exc:
                raise UnsupportedContent("body is not valid JSON") from exc
        raise UnsupportedContent(f"unsupported mime_type {mime_type!r}")


def _clean(text: str) -> str:
    return " ".join(unicodedata.normalize("NFC", strip_invisible(text)).split())


def _visible_text(segments: list[Segment]) -> str:
    """Rendered text only: visible text nodes. Never comments, attributes, data or hidden text."""
    parts: list[str] = []
    for seg in segments:
        if seg.kind != "TEXT" or seg.visibility != "VISIBLE":
            continue
        text = unicodedata.normalize("NFC", strip_invisible(seg.text))
        if parts and not seg.glue_before:
            parts.append(" ")
        parts.append(text)
    return " ".join("".join(parts).split())


class _FindingBuilder:
    def __init__(self, by_index: dict[int, Segment], hidden_on: bool, enabled: frozenset[str]):
        self.by_index = by_index
        self.hidden_on = hidden_on
        self.enabled = enabled
        self.findings: dict[tuple[str, tuple[int, ...]], Finding] = {}
        self.truncated = False
        self.max_severity: Severity = "NONE"

    # helpers -------------------------------------------------------------------------------------
    def _loc(self, seg_ids: list[int], unit: _Unit) -> Location:
        if unit.smuggled:
            return "SMUGGLED"
        locs = [_location(self.by_index[i], self.hidden_on) for i in seg_ids]
        return max(locs, key=_LOCATION_RANK.__getitem__)

    def _locator(self, seg_ids: list[int]) -> dict[str, Any]:
        segs = [self.by_index[i] for i in seg_ids]
        loc: dict[str, Any] = {
            "selector": segs[0].selector,
            "segments": seg_ids,
            "char_range": [segs[0].char_start, segs[-1].char_end],
            "kind": segs[0].kind,
        }
        if segs[0].attribute:
            loc["attribute"] = segs[0].attribute
        if len(segs) > 1:
            loc["split"] = True
        return loc

    def _excerpt(self, seg_ids: list[int], unit: _Unit, start: int, end: int) -> str:
        if unit.smuggled:
            return display_excerpt("[decoded tag characters] " + unit.text)
        original = " ".join(self.by_index[i].text for i in seg_ids)
        if len(original) <= 500 or not unit.text:
            return display_excerpt(original)
        lo, hi = max(0, start - 120), min(len(unit.text), end + 200)
        return display_excerpt(("…" if lo else "") + unit.text[lo:hi])

    def _add(self, technique: str, severity: Severity, seg_ids: list[int], unit: _Unit,
             start: int, end: int, confidence: float, pattern: str,
             targets: tuple[str, ...] = ()) -> None:  # fmt: skip
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[self.max_severity]:
            self.max_severity = severity
        key = (technique, tuple(sorted(seg_ids)))
        existing = self.findings.get(key)
        if existing is not None:
            if SEVERITY_ORDER[severity] <= SEVERITY_ORDER[existing.severity] and set(
                targets
            ) <= set(existing.targets):
                return
            targets = tuple(sorted(set(targets) | set(existing.targets)))
            severity = max(severity, existing.severity, key=SEVERITY_ORDER.__getitem__)
            confidence = max(confidence, existing.confidence)
        elif len(self.findings) >= MAX_FINDINGS:
            self.truncated = True
            return
        self.findings[key] = Finding(
            finding_id=existing.finding_id if existing else new_id("inj"),
            technique=technique,
            severity=severity,
            targets=tuple(sorted(targets)),
            locator=self._locator(sorted(seg_ids)),
            excerpt=self._excerpt(sorted(seg_ids), unit, start, end),
            confidence=round(min(confidence, 0.99), 3),
            location=self._loc(seg_ids, unit),
            pattern=pattern,
        )

    # analysis ------------------------------------------------------------------------------------
    def analyse(self, unit: _Unit, split: bool) -> None:
        if not unit.text or (self.truncated and self.max_severity == "HIGH"):
            return  # nothing to add: the cap is reached and severity cannot rise further
        hits: list[tuple[str, Severity, list[int], int, int, float, str, tuple[str, ...]]] = []
        if "ai_addressed" in self.enabled:
            for m in find_ai_addressed(unit.text):
                ids = unit.segments_for(m.start, m.end)
                loc = self._loc(ids, unit)
                sev: Severity = "MEDIUM" if loc == "VISIBLE" else "HIGH"
                hits.append(("AI_ADDRESSED_INSTRUCTION", sev, ids, m.start, m.end,
                             _AI_CONFIDENCE[m.family], m.family, ()))  # fmt: skip
        if "authority_claim" in self.enabled:
            for m in find_authority_claims(unit.text):
                ids = unit.segments_for(m.start, m.end)
                hits.append(("AUTHORITY_CLAIM", "HIGH", ids, m.start, m.end, 0.85, m.family, ()))
        if "payment_override" in self.enabled:
            for pm in find_payment_directives(unit.text):
                ids = unit.segments_for(pm.start, pm.end)
                if payment_finding_applies(pm, self._loc(ids, unit)):
                    conf = 0.9 if pm.strict_addressee or pm.strong_override else 0.75
                    hits.append(("PAYMENT_FIELD_OVERRIDE", "HIGH", ids, pm.start, pm.end, conf,
                                 "payment_directive", pm.targets))  # fmt: skip
        if split:
            # Stream matches only count when they need more than one segment.
            hits = [h for h in hits if len(h[2]) > 1]
        if not hits:
            return
        families = {h[0] for h in hits}
        bonus = 0.05 * (len(families) - 1)
        for technique, sev, ids, start, end, conf, pattern, targets in hits:
            self._add(technique, sev, ids, unit, start, end, conf + bonus, pattern, targets)
            loc = self._loc(ids, unit)
            if loc in _LOCATION_TECHNIQUE:
                detector, loc_technique = _LOCATION_TECHNIQUE[loc]
                if detector in self.enabled:
                    # Instruction content in a non-visible location: the location is evidence too.
                    loc_sev: Severity = "HIGH" if sev == "HIGH" else "MEDIUM"
                    self._add(loc_technique, loc_sev, ids, unit, start, end, 0.95,
                              f"{loc.lower()}_instruction", targets)  # fmt: skip

    def zero_width(self, segments: list[Segment], smuggled: set[int]) -> None:
        instruction_segments = {
            i for (_, ids), f in self.findings.items() for i in ids if f.severity != "LOW"
        }
        for seg in segments:
            runs = find_invisible(seg.text)
            if not runs:
                continue
            count = sum(len(r.chars) for r in runs)
            carries = seg.index in instruction_segments or seg.index in smuggled
            severity: Severity = "LOW"
            if carries:
                severity = max(
                    (f.severity for (_, ids), f in self.findings.items() if seg.index in ids),
                    key=SEVERITY_ORDER.__getitem__,
                    default="MEDIUM",
                )
            unit = _Unit("", [(0, 0, seg.index)])
            self._add("ZERO_WIDTH", severity, [seg.index], unit, 0, 0,
                      0.95 if carries else 0.6, f"invisible_chars:{count}")  # fmt: skip

    def finish(self) -> tuple[Finding, ...]:
        return tuple(
            sorted(
                self.findings.values(),
                key=lambda f: (
                    -SEVERITY_ORDER[f.severity],
                    f.locator["char_range"][0],
                    f.technique,
                ),
            )
        )
