"""Every prewritten example in safety/fixtures/site_scan/cases.yaml gives its expected result."""

import asyncio

import pytest

from mandit.safety.site_scan.examples import check, load_cases, run_case

TODAY, CASES = load_cases()


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_example_case(case):
    result = asyncio.run(run_case(case, TODAY))
    assert check(case, result) == []


def test_case_ids_are_unique():
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids))


def test_honest_pages_never_reach_medium():
    """False-positive guard: honest merchant pages must stay LOW (modules/02 section 11)."""
    for case in (c for c in CASES if c.id.startswith("honest_")):
        result = asyncio.run(run_case(case, TODAY))
        assert result.site_risk_level == "LOW", case.id
