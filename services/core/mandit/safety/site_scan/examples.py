"""Runs the prewritten site-scan examples in safety/fixtures/site_scan/cases.yaml.

Usage (from services/core):
    python -m mandit.safety.site_scan.examples            # summary table
    python -m mandit.safety.site_scan.examples -v         # full report per case
    python -m mandit.safety.site_scan.examples fake_shop_checkout   # selected cases only

Everything is offline: registry, reputation and TLS results come from fixtures.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from pathlib import Path

import yaml

from .config import FIXTURES_DIR, load_config
from .domains import parse_target
from .ports import FixtureMerchantRegistry, FixtureReputationStore
from .scanner import Profile, SiteScanner, SiteScanResult
from .tls import StaticTlsProbe, TlsResult

FIXTURES = FIXTURES_DIR


@dataclass(frozen=True)
class Case:
    id: str
    description: str
    url: str
    html: str | None
    profile: Profile
    tls: TlsResult | None
    disabled: frozenset[str]
    expect_codes: frozenset[str]
    expect_level: str
    expect_score: Decimal | None = None


def load_cases(fixtures: Path = FIXTURES) -> tuple[date, list[Case]]:
    raw = yaml.safe_load((fixtures / "cases.yaml").read_text(encoding="utf-8"))
    cases = []
    for c in raw["cases"]:
        tls = c.get("tls")
        expect = c["expect"]
        cases.append(
            Case(
                id=c["id"],
                description=c.get("description", ""),
                url=c["url"],
                html=(fixtures / "pages" / c["page"]).read_text(encoding="utf-8")
                if c.get("page")
                else None,
                profile=c.get("profile", "test"),
                tls=TlsResult(**tls) if tls else None,
                disabled=frozenset(c.get("disabled", [])),
                expect_codes=frozenset(expect["codes"]),
                expect_level=expect["level"],
                expect_score=Decimal(str(expect["score"])) if "score" in expect else None,
            )
        )
    return raw["today"], cases


def build_scanner(case: Case, today: date, fixtures: Path = FIXTURES) -> SiteScanner:
    host = parse_target(case.url)[1].ascii
    return SiteScanner(
        config=load_config(),
        registry=FixtureMerchantRegistry.from_yaml(fixtures / "registry.yaml"),
        reputation=FixtureReputationStore.from_yaml(fixtures / "reputation.yaml"),
        tls_probe=StaticTlsProbe({host: case.tls} if case.tls else {}),
        profile=case.profile,
        today=lambda: today,
    )


async def run_case(case: Case, today: date) -> SiteScanResult:
    return await build_scanner(case, today).scan(case.url, case.html, disabled=case.disabled)


def check(case: Case, result: SiteScanResult) -> list[str]:
    """Differences between the expected and actual result; empty means the case passed."""
    problems = []
    got = set(result.codes)
    if got != case.expect_codes:
        problems.append(
            f"codes: missing {sorted(case.expect_codes - got)}, "
            f"unexpected {sorted(got - case.expect_codes)}"
        )
    if result.site_risk_level != case.expect_level:
        problems.append(f"level: expected {case.expect_level}, got {result.site_risk_level}")
    if case.expect_score is not None and result.site_risk_score != case.expect_score:
        problems.append(f"score: expected {case.expect_score}, got {result.site_risk_score}")
    return problems


async def _main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("ids", nargs="*", help="case ids to run (default: all)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print the full JSON report")
    args = ap.parse_args(argv)

    today, cases = load_cases()
    if args.ids:
        unknown = set(args.ids) - {c.id for c in cases}
        if unknown:
            print(f"unknown case ids: {sorted(unknown)}", file=sys.stderr)
            return 2
        cases = [c for c in cases if c.id in args.ids]

    failures = 0
    for case in cases:
        result = await run_case(case, today)
        problems = check(case, result)
        failures += bool(problems)
        status = "PASS" if not problems else "FAIL"
        print(f"{status}  {case.id:<40} {result.site_risk_level:<6} {result.site_risk_score:<6}"
              f" {', '.join(result.codes) or '-'}")  # fmt: skip
        for p in problems:
            print(f"      {p}")
        if args.verbose:
            print(f"      {case.description}")
            print(
                "      "
                + json.dumps(result.to_dict(), indent=2, ensure_ascii=False).replace(
                    "\n", "\n      "
                )
            )
    print(f"\n{len(cases) - failures}/{len(cases)} cases passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_main(sys.argv[1:])))
