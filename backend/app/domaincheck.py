"""Check one website address on its own: is it the real company, a look-alike, or unknown?

Uses the same link checks as message scans (official domains, look-alike spellings, foreign alphabets,
blocklists, domain age) and no AI, so it is instant and free.
"""

from __future__ import annotations

from app.pipeline import LinkAnalyzer
from app.schemas import DomainCheckResponse
from app.scoring import LINK_FLOORS, verdict_for
from app.signals.brands import BRANDS
from app.signals.links import normalize_url

_POINTS = {"low": 5, "medium": 15, "high": 30}

_ADVICE = {
    "scam": [
        "Don't open this website, and don't type a password, card number, or code into it.",
        "If you already did, change that password from a device you trust and call your bank using the number on your card.",
        "Go to the company by typing its address yourself or using its official app.",
        "Report it at reportfraud.ftc.gov.",
    ],
    "likely_scam": [
        "Don't sign in or pay on this website.",
        "Go to the company by typing its address yourself or using its official app.",
        "If a message sent you here, delete it.",
    ],
    "suspicious": [
        "Don't enter passwords, payment details, or codes until you are sure who runs this site.",
        "Look up the company yourself and compare its real address with this one.",
    ],
    "likely_safe": [
        "This address passed our checks, but we can only vouch for sites we know.",
        "Before paying or signing in, make sure the address is exactly the one you expected.",
    ],
}


class NotAnAddress(ValueError):
    pass


def _brand_name(brand: str) -> str:
    official = BRANDS.get(brand) or []
    return official[0] if official else brand


async def check_domain(raw: str, links: LinkAnalyzer, *, network: bool) -> DomainCheckResponse:
    url = normalize_url(raw.strip().split()[0] if raw.strip() else "")
    if not url:
        raise NotAnAddress(raw)
    report = await links.analyze(url)

    floors = [LINK_FLOORS[c.name][0] for c in report.checks if c.name in LINK_FLOORS]
    base = 10 + sum(_POINTS[c.severity] for c in report.checks if c.name not in LINK_FLOORS)
    score = min(100, max([base, *floors]))
    if report.official_brand and not report.on_blocklist:
        score = min(score, 5)
    verdict = verdict_for(score)

    # A disguised address renders like the real one, so name it by its real form, never its look.
    shown = report.host_ascii if report.host_ascii and report.host_ascii != report.host_unicode else report.host
    if report.looks_like:
        headline = f"This is not {report.looks_like}. It is a fake address made to look exactly like it."
    elif report.official_brand and score <= 5:
        headline = f"This is an official website: {report.registrable_domain}."
    elif verdict == "scam":
        headline = f"Don't visit {shown}. It is built to trick people."
    elif verdict == "likely_scam":
        headline = f"{shown} is very likely a fake website."
    elif verdict == "suspicious":
        headline = f"Be careful with {shown}."
    else:
        headline = f"We found no warning signs for {shown}, but we don't know this website."

    facts: list[str] = []
    if report.official_brand:
        facts.append(f"It is on our list of official addresses ({_brand_name(report.official_brand)}).")
    # How the address appears and which alphabets it uses are in `link` (host_unicode, scripts).
    if report.domain_age_days is not None:
        years = report.domain_age_days // 365
        facts.append(f"Registered {years} year(s) ago." if years else f"Registered {report.domain_age_days} day(s) ago.")
    elif network and not report.official_brand:
        facts.append("We couldn't find when this website was registered.")
    if network:
        facts.append(
            "It is on a public list of known phishing or malware sites."
            if report.on_blocklist
            else "It is not on the public phishing lists we check."
        )

    return DomainCheckResponse(
        url=url,
        risk_score=score,
        verdict=verdict,
        headline=headline,
        facts=facts,
        what_to_do=_ADVICE[verdict],
        link=report,
        network_checked=network,
    )
