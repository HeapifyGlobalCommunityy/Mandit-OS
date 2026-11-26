import pytest

from mandit.safety.site_scan.domains import (
    InvalidScanTarget,
    damerau_levenshtein,
    find_lookalike,
    is_owned,
    normalize_host,
    parse_target,
    skeleton,
)

REGISTRY = ["croma.mock.mandit.local", "reliancedigital.mock.mandit.local"]


def lookalike(host: str):
    return find_lookalike(
        normalize_host(host), REGISTRY, max_edit_distance=2, min_brand_label_length=5
    )


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [("croma", "croma", 0), ("croma", "corma", 1), ("croma", "crma", 1), ("croma", "cromaa", 1),
     ("croma", "cr0ma", 1), ("abc", "cba", 2), ("", "abc", 3)],
)  # fmt: skip
def test_damerau_levenshtein(a, b, expected):
    assert damerau_levenshtein(a, b) == expected
    assert damerau_levenshtein(b, a) == expected


def test_skeleton_maps_confusables():
    assert skeleton("сroma") == "croma"  # Cyrillic с
    assert skeleton("cr0ma") == "croma"
    assert skeleton("crorna") == "croma"  # rn -> m
    assert skeleton("CRÓMA") == "croma"  # accent dropped


def test_normalize_host_handles_punycode_and_unicode():
    from_unicode = normalize_host("сroma.mock.mandit.local.")
    from_puny = normalize_host("XN--ROMA-K6D.mock.mandit.local")
    assert from_unicode == from_puny
    assert from_puny.ascii == "xn--roma-k6d.mock.mandit.local"
    assert from_puny.display == "сroma.mock.mandit.local"


@pytest.mark.parametrize(
    "url", ["ftp://croma.example/", "javascript:alert(1)", "https:///nohost", ""]
)
def test_parse_target_rejects_unscannable(url):
    with pytest.raises(InvalidScanTarget):
        parse_target(url)


def test_ownership_includes_subdomains_only():
    assert is_owned("croma.mock.mandit.local", "croma.mock.mandit.local")
    assert is_owned("pay.croma.mock.mandit.local", "croma.mock.mandit.local")
    assert not is_owned("evilcroma.mock.mandit.local", "croma.mock.mandit.local")
    assert not is_owned("croma.mock.mandit.local.evil.example", "croma.mock.mandit.local")


@pytest.mark.parametrize(
    ("host", "reason"),
    [
        ("cr0ma.mock.mandit.local", "HOMOGLYPH"),
        ("xn--roma-k6d.mock.mandit.local", "HOMOGLYPH"),
        ("corma.mock.mandit.local", "TYPO"),
        ("croma.mock.mandit.local.verify.example", "BRAND_EMBEDDED"),
        ("croma-offers.example", "BRAND_EMBEDDED"),
        ("cromma.shop.example", "TYPO"),
        ("reliancedigitall.example", "TYPO"),
    ],
)
def test_lookalikes_detected(host, reason):
    match = lookalike(host)
    assert match is not None and match.reason == reason


@pytest.mark.parametrize("host", ["fastlaptopdeals.example.com", "amazon.example", "example.org"])
def test_unrelated_domains_are_not_lookalikes(host):
    assert lookalike(host) is None
