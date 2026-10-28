"""Deterministic link analysis: URL extraction, lookalike/impersonation checks, domain age."""

from __future__ import annotations

import ipaddress
import re
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
import tldextract

from app.schemas import LinkCheck, LinkReport
from app.signals.brands import (
    BRANDS,
    OFFICIAL_DOMAINS,
    RISKY_TLDS,
    SHORT_BRANDS,
    URL_SHORTENERS,
)

# Offline Public Suffix List snapshot bundled with tldextract: no network at startup.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_URL_RE = re.compile(
    r"""(?ix)
    (?<![@\w.-])                              # not part of an email or longer token
    (?:(?:https?|hxxps?)://(?:[^\s/\\@<>"'`]+@)?)?  # optional scheme, then optional "user@" that hides the real host
    (?:[a-z0-9¡-￿](?:[a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?(?:\.|\[\.\]))+
    [a-z¡-￿]{2,24}                   # TLD
    (?::\d{2,5})?
    (?:/[^\s<>"'`]*)?
    """
)
# A schemeless "paypal.com@evil.top": the part before "@" looks like a domain, so it is a disguise, not an email.
_SCHEMELESS_USERINFO_RE = re.compile(
    r"(?i)(?<![\w.-])((?:[a-z0-9-]+\.)+[a-z]{2,24})@((?:[a-z0-9-]+\.)+[a-z]{2,24}(?::\d{2,5})?(?:/[^\s<>\"'`]*)?)"
)
_IP_URL_RE = re.compile(r"(?i)\bhttps?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/[^\s<>\"']*)?")
_TRAILING = ".,;:!?)]}'\"…"


def extract_urls(text: str) -> list[str]:
    """Find URLs and bare domains in free text. Returns normalized, de-duplicated URLs."""
    found: list[str] = []
    # "paypal.com@evil.top" is a disguise, "john.smith@gmail.com" is an email: only the first counts.
    disguised = [
        m
        for m in _SCHEMELESS_USERINFO_RE.finditer(text)
        if text[max(0, m.start() - 3) : m.start()] != "://" and _extract(m.group(1)).suffix
    ]
    raws = [m.group(0) for m in _IP_URL_RE.finditer(text)] + [m.group(0) for m in disguised]
    # Skip plain matches inside a disguised link, so "paypal.com" isn't also checked on its own.
    raws += [m.group(0) for m in _URL_RE.finditer(text) if not any(d.start() <= m.start() < d.end() for d in disguised)]
    for raw in raws:
        raw = raw.rstrip(_TRAILING)
        url = normalize_url(raw)
        if url and url not in found:
            found.append(url)
    return found


def normalize_url(raw: str) -> str | None:
    # Browsers read "\\" as "/" in web addresses, so "https://evil.top\\@paypal.com" opens evil.top.
    raw = raw.strip().strip("<>").replace("[.]", ".").replace("\\", "/")
    raw = re.sub(r"(?i)^hxxp", "http", raw)
    if not re.match(r"(?i)^https?://", raw):
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    if not _is_ip(host):
        ext = _extract(host)
        if not ext.suffix or not ext.domain:
            return None  # "file.txt", "e.g", etc.
    # Keep any "user@" part: it is what makes "https://paypal.com@evil.top" a trick, and the
    # checks must see it. The host is always the real destination after the "@".
    userinfo = parts.netloc.rpartition("@")[0]
    userinfo = f"{userinfo}@" if userinfo else ""
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or ""
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme.lower()}://{userinfo}{host}{port}{path}{query}"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str:
    if _is_ip(host):
        return host
    ext = _extract(host)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else host


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_CONFUSABLES = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "8": "b"})


def _deconfuse(label: str) -> str:
    return label.translate(_CONFUSABLES).replace("rn", "m").replace("vv", "w").replace("-", "")


def official_brand_for(reg_domain: str) -> str | None:
    return OFFICIAL_DOMAINS.get(reg_domain)


def _mentioned_brands(host: str) -> list[tuple[str, bool]]:
    """Brands named in the host as (brand, disguised). disguised=True when the name only
    appears after undoing look-alike swaps (netf1ix-billing -> netflix)."""
    labels = re.split(r"[.\-]", host)
    labels_dc = {_deconfuse(label) for label in labels}
    flat = host.replace("-", "").replace(".", "")
    flat_dc = _deconfuse(flat)
    hits = []
    for brand in BRANDS:
        if brand in SHORT_BRANDS or len(brand) < 5:
            plain, disguised = brand in labels, brand in labels_dc
        else:
            plain, disguised = brand in flat, brand in flat_dc
        if plain or disguised:
            hits.append((brand, not plain))
    return sorted(hits, key=lambda h: h[1])  # plain mentions first


def _lookalike_of(reg_domain: str) -> str | None:
    """Return the official domain this one imitates (paypa1.com, arnazon.com), if any.
    Each hyphen-separated part is compared too, so 'paypai-support.com' is caught."""
    label = reg_domain.split(".")[0]
    tokens = {t for t in [label, *label.split("-")] if len(t) >= 4}
    for official in OFFICIAL_DOMAINS:
        off_label = official.split(".")[0].replace("-", "")
        if len(off_label) < 4 or reg_domain == official:
            continue
        limit = 1 if len(off_label) < 8 else 2
        for token in tokens:
            if token != off_label and _deconfuse(token) == off_label:
                return official
            if abs(len(token) - len(off_label)) <= limit and 0 < _levenshtein(token, off_label) <= limit:
                return official
    return None


def static_checks(url: str) -> LinkReport:
    """Checks that need no network access."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    reg = registrable_domain(host)
    report = LinkReport(url=url, host=host, registrable_domain=reg)
    checks: list[LinkCheck] = []

    official = official_brand_for(reg)
    report.official_brand = official

    if _is_ip(host):
        checks.append(
            LinkCheck(
                name="ip_address", severity="high", detail="The link points to a raw IP address instead of a company website."
            )
        )
    if "xn--" in host:
        checks.append(
            LinkCheck(
                name="punycode",
                severity="high",
                detail="The address uses look-alike international characters, a common disguise.",
            )
        )
    if "@" in (parts.netloc or ""):
        checks.append(
            LinkCheck(name="userinfo_trick", severity="high", detail="The link contains '@', which hides the real destination.")
        )

    if not official and not _is_ip(host):
        brands = _mentioned_brands(host)
        if brands and not brands[0][1]:
            b = brands[0][0]
            real = ", ".join(BRANDS[b][:2]) if BRANDS[b] else "an official site"
            checks.append(
                LinkCheck(
                    name="brand_impersonation", severity="high", detail=f"Mentions '{b}' but the site is {reg}, not {real}."
                )
            )
        else:
            twin = BRANDS[brands[0][0]][0] if brands and BRANDS[brands[0][0]] else _lookalike_of(reg)
            if twin:
                checks.append(
                    LinkCheck(
                        name="lookalike_domain", severity="high", detail=f"{reg} imitates {twin} by swapping look-alike letters."
                    )
                )

    if reg in URL_SHORTENERS or host in URL_SHORTENERS:
        checks.append(
            LinkCheck(name="url_shortener", severity="medium", detail="Shortened link: you can't see where it really goes.")
        )

    tld = reg.rsplit(".", 1)[-1] if "." in reg else ""
    if tld in RISKY_TLDS and not official:
        checks.append(
            LinkCheck(
                name="risky_tld",
                severity="medium",
                detail=f"Ends in .{tld}, a cheap domain ending that scam campaigns use heavily.",
            )
        )

    sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) else ""
    if sub and sub.count(".") >= 2:
        checks.append(
            LinkCheck(
                name="deep_subdomain",
                severity="low",
                detail="Unusually long address with many parts, often used to look official.",
            )
        )

    report.checks = checks
    return report


# ---------- Domain age via RDAP ----------

_rdap_cache: dict[str, tuple[float, int | None, bool]] = {}
_RDAP_TTL = 24 * 3600


async def domain_age_days(client: httpx.AsyncClient, reg_domain: str, timeout: float) -> tuple[int | None, bool]:
    """Returns (age_in_days or None, exists). Uses the public rdap.org bootstrap redirector."""
    now = time.time()
    cached = _rdap_cache.get(reg_domain)
    if cached and now - cached[0] < _RDAP_TTL:
        return cached[1], cached[2]
    age: int | None = None
    exists = True
    try:
        resp = await client.get(f"https://rdap.org/domain/{reg_domain}", timeout=timeout, follow_redirects=True)
        if resp.status_code == 404:
            exists = False
        elif resp.status_code == 200:
            for event in resp.json().get("events", []):
                if event.get("eventAction") == "registration" and event.get("eventDate"):
                    created = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                    age = max(0, (datetime.now(UTC) - created).days)
                    break
        else:
            return None, True  # unknown; don't cache transient errors
    except (httpx.HTTPError, ValueError):
        return None, True
    _rdap_cache[reg_domain] = (now, age, exists)
    return age, exists


def age_checks(report: LinkReport, age: int | None, exists: bool) -> None:
    report.domain_age_days = age
    if not exists:
        report.checks.append(
            LinkCheck(
                name="unregistered_domain",
                severity="medium",
                detail="This domain isn't registered (any more). Scam sites are often taken down fast.",
            )
        )
    elif age is not None and age < 30:
        report.checks.append(
            LinkCheck(name="new_domain", severity="high", detail=f"This website was registered only {age} day(s) ago.")
        )
    elif age is not None and age < 180:
        report.checks.append(
            LinkCheck(name="young_domain", severity="medium", detail=f"This website is only about {age // 30} month(s) old.")
        )
