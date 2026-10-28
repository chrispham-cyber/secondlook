import httpx
import pytest
import respx

from app.signals import links
from app.signals.blocklist import Blocklist
from app.signals.links import domain_age_days, extract_urls, static_checks


def names(url: str) -> set[str]:
    return {c.name for c in static_checks(url).checks}


def test_extracts_urls_and_bare_domains():
    text = "Your toll is unpaid. Pay at https://sunpass-tollpay.top/pay?id=9 or visit usps.com-redelivery.info now."
    assert extract_urls(text) == [
        "https://sunpass-tollpay.top/pay?id=9",
        "http://usps.com-redelivery.info",
    ]


def test_ignores_emails_and_filenames():
    assert extract_urls("email me at john@gmail.com, see report.pdf and file.txt") == []


def test_defanged_and_ip_urls():
    assert extract_urls("go to hxxps://evil[.]com/x") == ["https://evil.com/x"]
    assert extract_urls("open http://192.168.4.20/login") == ["http://192.168.4.20/login"]


def test_official_domain_is_clean():
    rep = static_checks("https://www.usps.com/manage/package")
    assert rep.official_brand == "usps"
    assert rep.checks == []


def test_brand_impersonation():
    assert "brand_impersonation" in names("http://usps.com-redelivery.info")
    assert "brand_impersonation" in names("https://paypal-secure-login.net/verify")
    assert "brand_impersonation" in names("https://ezpass-toll-services.com")


def test_short_brand_needs_whole_label():
    # "purchase" contains "chase" but is not an impersonation of Chase.
    assert "brand_impersonation" not in names("https://purchase-orders.com")
    assert "brand_impersonation" in names("https://chase-alerts.com")


def test_lookalike_domain():
    assert "lookalike_domain" in names("https://paypa1.com")
    assert "lookalike_domain" in names("https://arnazon.com")


def test_other_static_signals():
    assert "ip_address" in names("http://45.13.22.8/verify")
    assert "punycode" in names("https://xn--pypal-4ve.com")
    assert "url_shortener" in names("https://bit.ly/3xYz")
    assert "risky_tld" in names("https://claim-reward.top")


@respx.mock
async def test_domain_age_from_rdap():
    links._rdap_cache.clear()
    respx.get("https://rdap.org/domain/brand-new-site.com").mock(
        return_value=httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": "2099-01-01T00:00:00Z"}]})
    )
    respx.get("https://rdap.org/domain/gone-site.com").mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as client:
        age, exists = await domain_age_days(client, "brand-new-site.com", 2)
        assert exists and age == 0
        age, exists = await domain_age_days(client, "gone-site.com", 2)
        assert not exists and age is None


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://evil.example/path", True),
        ("https://evil.example/other", True),  # host-level match
        ("https://sites.google.com/view/phish", True),  # exact URL on shared host
        ("https://sites.google.com/view/legit", False),  # shared host: no host-level match
    ],
)
def test_blocklist(url, expected):
    bl = Blocklist()
    bl.load_lines(["https://evil.example/path", "https://sites.google.com/view/phish", "# comment"])
    assert bl.match(url) is expected


def test_disguised_brand_spellings():
    assert "lookalike_domain" in names("https://netf1ix-billing.com")
    assert "brand_impersonation" in names("https://appleid-support-center.com/verify")
    assert "brand_impersonation" in names("https://boa-online-verify.com")
    assert "brand_impersonation" in names("https://amzn-customs-help.shop")


def test_official_domain_uses_main_brand_name():
    assert static_checks("https://www.amazon.com/orders").official_brand == "amazon"
    assert static_checks("https://www.bankofamerica.com").official_brand == "bankofamerica"


@pytest.mark.parametrize(
    "text",
    [
        "Verify now: https://www.paypal.com@evil-login.top/secure",
        "go to paypal.com@evil-login.top today",
        "http://user:pass@usps.com.track-pkg.info/x",
    ],
)
def test_userinfo_link_checks_the_real_host(text):
    [url] = extract_urls(text)
    report = static_checks(url)
    assert report.official_brand is None
    assert report.registrable_domain != "paypal.com"
    assert "userinfo_trick" in {c.name for c in report.checks}


def test_plain_emails_are_not_userinfo_links():
    assert extract_urls("Email john.smith@gmail.com or help@paypal.com") == []


def test_backslash_link_checks_the_host_a_browser_opens():
    [url] = extract_urls("Log in: https://evil.top\\@paypal.com/login")
    report = static_checks(url)
    assert report.host == "evil.top" and report.official_brand is None
