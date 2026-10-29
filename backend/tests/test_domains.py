"""Foreign-alphabet look-alike addresses, and the stand-alone website check."""

import pytest

from app.signals.idn import analyze_host
from app.signals.links import extract_urls, static_checks
from tests.fakes import FakeAnalyzer
from tests.test_api import make_client


def names(url: str) -> set[str]:
    return {c.name for c in static_checks(url).checks}


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://аррӏе.com/login", "homograph"),  # every letter Cyrillic
        ("https://xn--80ak6aa92e.com", "homograph"),  # the same address in its encoded form
        ("https://pаypal.com", "mixed_scripts"),  # one Cyrillic "а" among Latin letters
        ("https://gοogle.com", "homograph"),  # Greek omicron
        ("https://páypal.com", "homograph"),  # an accent
        ("https://chаse-alerts.top", "brand_impersonation"),  # look-alike brand inside a longer name
        ("https://pay­pal.com", "hidden_characters_in_address"),
        ("https://сосо.com", "fake_latin_letters"),  # Cyrillic that reads as "coco"
    ],
)
def test_foreign_letter_disguises_are_caught(url, expected):
    assert expected in names(url)


def test_real_addresses_are_left_alone():
    for url in ("https://apple.com", "https://www.paypal.com/signin", "https://ｐａｙｐａｌ.com"):
        report = static_checks(url)
        assert report.official_brand and report.checks == []


def test_genuine_international_sites_are_only_noted():
    for url in ("https://яндекс.рф", "https://bücher.de", "https://日本語.jp"):
        assert names(url) == {"international_domain"}


def test_both_forms_of_the_address_are_reported():
    report = static_checks("https://аррӏе.com")
    assert report.host_ascii == "xn--80ak6aa92e.com" and report.host_unicode == "аррӏе.com"
    assert report.scripts == ["Cyrillic", "Latin"]


def test_japanese_mixing_latin_and_kana_is_normal():
    assert analyze_host("sonyストア.jp").mixed_labels == []
    assert analyze_host("pаypal.com").mixed_labels == [("pаypal", ["Latin", "Cyrillic"])]


def test_ideographic_full_stop_counts_as_a_dot():
    assert extract_urls("Sign in at аррӏе。com/verify") == ["http://аррӏе.com/verify"]


def test_look_alike_link_sets_the_score_floor(tmp_path):
    with make_client(tmp_path, FakeAnalyzer()) as c:
        body = c.post("/api/scan", data={"text": "Your Apple ID is locked: https://аррӏе.com/unlock"}).json()
    assert body["risk_score"] >= 90 and body["verdict"] == "scam"


# --- the stand-alone website check


def check(c, domain: str):
    return c.post("/api/domain", json={"domain": domain})


def test_domain_check_official(tmp_path):
    with make_client(tmp_path, FakeAnalyzer()) as c:
        body = check(c, "https://www.paypal.com/us/signin").json()
    assert body["verdict"] == "likely_safe" and body["risk_score"] <= 5
    assert "official" in body["headline"]


def test_domain_check_homograph(tmp_path):
    with make_client(tmp_path, FakeAnalyzer()) as c:
        body = check(c, "аррӏе.com").json()
    assert body["verdict"] == "scam" and body["risk_score"] >= 90
    assert body["link"]["host_ascii"] == "xn--80ak6aa92e.com" and body["link"]["scripts"] == ["Cyrillic", "Latin"]
    assert body["link"]["checks"][0]["name"] == "homograph" and body["link"]["looks_like"] == "apple.com"
    assert body["headline"].startswith("This is not apple.com")


def test_domain_check_unknown_site(tmp_path):
    with make_client(tmp_path, FakeAnalyzer()) as c:
        body = check(c, "my-neighborhood-bakery.com").json()
    assert body["verdict"] == "likely_safe" and "don't know" in body["headline"]


def test_domain_check_rejects_non_addresses(tmp_path):
    with make_client(tmp_path, FakeAnalyzer()) as c:
        assert check(c, "hello there").status_code == 400
        assert check(c, "x" * 3000).status_code == 422


def test_blocklist_matches_every_form_of_the_address():
    import asyncio

    import httpx

    from app.config import Settings
    from app.pipeline import LinkAnalyzer
    from app.signals.blocklist import Blocklist

    bl = Blocklist()
    bl.urls.add("xn--80ak6aa92e.com/verify")
    links = LinkAnalyzer(Settings(network_checks=False), httpx.AsyncClient(), bl)
    for url in (
        "https://аррӏе.com/verify",
        "https://xn--80ak6aa92e.com/verify/",
        "https://аррӏе.com@аррӏе.com/verify",  # the host also appears in the user@ part
        "https://АРРӀЕ.com/verify",  # uppercase Cyrillic
    ):
        assert asyncio.run(links.analyze(url)).on_blocklist, url


def test_official_government_subdomains():
    assert static_checks("https://www.dmv.ca.gov/renew").official_brand
    assert static_checks("https://dmv.ca.gov").checks == []
    assert not static_checks("https://dmv-renew.ca.gov.example.com").official_brand


def test_text_model_features_stay_fast_on_hostile_input():
    import time

    from app.signals.textmodel import _unmask, features

    assert _unmask("pаypal.com и привет") == "paypal.com и привет"
    for text in ("а" * 20_000, "\ufdfa" * 20_000, ("а" * 99 + "a ") * 200):
        start = time.perf_counter()
        features(text)
        assert time.perf_counter() - start < 1.0
