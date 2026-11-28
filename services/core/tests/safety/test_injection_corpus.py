"""Corpus tests for the Prompt Injection Firewall (modules/02 section 11, G3 rows).

- every attack case produces its expected technique codes and severity;
- every honest case produces no MEDIUM or HIGH finding;
- hidden text never appears in visible_text.
"""

from pathlib import Path

import pytest
import yaml

from mandit.safety.injection import InjectionFirewall
from mandit.safety.injection.firewall import SEVERITY_ORDER
from mandit.safety.site_scan.config import FIXTURES_DIR as SITE_FIXTURES

CASES_PATH = Path(SITE_FIXTURES).parent / "injection" / "cases.yaml"
CASES = yaml.safe_load(CASES_PATH.read_text(encoding="utf-8"))
FW = InjectionFirewall()


def _html(case: dict) -> str:
    html = case["html"]
    if "tag_smuggle" in case:
        tags = "".join(chr(0xE0000 + ord(c)) for c in case["tag_smuggle"])
        html = html.replace("{TAG}", tags)
    return html


@pytest.mark.parametrize("case", CASES["attacks"], ids=lambda c: c["id"])
def test_attack_case(case):
    report = FW.scan(_html(case), case.get("mime_type", "text/html"))
    expect = case["expect"]
    techniques = {f.technique for f in report.findings}
    assert report.severity == expect["severity"], [f.to_dict() for f in report.findings]
    assert set(expect["techniques"]) <= techniques
    assert report.injection_detected
    if "targets" in expect:
        payment_targets = {
            t for f in report.findings if f.technique == "PAYMENT_FIELD_OVERRIDE" for t in f.targets
        }
        assert set(expect["targets"]) <= payment_targets
    for needle in expect.get("not_in_visible", []):
        assert needle.lower() not in report.visible_text.lower()


@pytest.mark.parametrize("case", CASES["legit"], ids=lambda c: c["id"])
def test_legit_case_has_no_medium_or_high(case):
    report = FW.scan(case["html"])
    assert SEVERITY_ORDER[report.severity] < SEVERITY_ORDER["MEDIUM"], [
        f.to_dict() for f in report.findings
    ]


@pytest.mark.parametrize("page", sorted((SITE_FIXTURES / "pages").glob("*.html")), ids=str)
def test_site_scan_fixture_pages_have_no_injection(page):
    assert FW.scan(page.read_text(encoding="utf-8")).severity == "NONE"


def test_corpus_meets_family_coverage():
    families = {c["family"] for c in CASES["attacks"]}
    assert {
        "hidden_text",
        "zero_width",
        "html_comment",
        "attribute_text",
        "visible_ai_addressed",
        "authority_claim",
        "payment_override",
        "split",
    } <= families
    assert len(CASES["attacks"]) >= 30


def test_corpus_ids_are_unique():
    ids = [c["id"] for c in CASES["attacks"] + CASES["legit"]]
    assert len(ids) == len(set(ids))


def test_redteam_corpus_cases_reference_existing_fixtures():
    repo = Path(__file__).resolve().parents[4]
    fixture_ids = {c["id"] for c in CASES["attacks"]}
    corpus_files = sorted((repo / "redteam" / "corpus" / "injection").glob("ATK-INJ-2*.yaml"))
    assert corpus_files, "Team 2 injection corpus cases are missing"
    for path in corpus_files:
        case = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert case["id"] == path.stem
        assert case["scanner_fixture"]["case"] in fixture_ids
        linked = next(c for c in CASES["attacks"] if c["id"] == case["scanner_fixture"]["case"])
        assert linked.get("corpus_id") == case["id"]
