"""Classic keyword/pattern signals. Deliberately simple: they act as a transparent baseline
(evals compare them against the AI) and as a safety net the AI can't talk its way out of."""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.schemas import Severity


@dataclass(frozen=True)
class Pattern:
    category: str
    title: str
    severity: Severity
    regex: re.Pattern[str]


def _p(category: str, title: str, severity: Severity, *phrases: str) -> Pattern:
    return Pattern(category, title, severity, re.compile("|".join(phrases), re.IGNORECASE))


PATTERNS: list[Pattern] = [
    _p(
        "payment_method",
        "Asks for hard-to-reverse payment",
        "high",
        r"\bgift ?cards?\b",
        r"\bitunes card",
        r"\bgoogle play card",
        r"\bbitcoin\b",
        r"\bcrypto(currency)?\b",
        r"\bUSDT\b",
        r"\bwire (the )?(money|funds|transfer)",
        r"\bwestern union\b",
        r"\bmoneygram\b",
        r"\bbitcoin atm\b",
        r"\bsend (it|money|payment) (via|through|on) (zelle|cash ?app|venmo)\b",
    ),
    _p(
        "urgency",
        "Creates time pressure",
        "medium",
        r"\bwithin (24|48|12) ?(hours|hrs|h)\b",
        r"\bimmediately\b",
        r"\burgent(ly)?\b",
        r"\bfinal (notice|warning|reminder)\b",
        r"\bact now\b",
        r"\blast chance\b",
        r"\bexpires? today\b",
        r"\btoday only\b",
        r"\bavoid (late fees?|penalt|suspension)",
    ),
    _p(
        "threat",
        "Threatens consequences",
        "high",
        r"\barrest\b",
        r"\bwarrant\b",
        r"\blaw ?suit\b",
        r"\blegal action\b",
        r"\bsuspended\b",
        r"\bsuspension\b",
        r"\bdeactivat",
        r"\bdisconnect(ed|ion)?\b",
        r"\bshut ?off\b",
        r"\bfrozen\b",
        r"\blicen[cs]e (will be )?(suspended|revoked)",
    ),
    _p(
        "credentials",
        "Asks for codes, passwords, or personal IDs",
        "high",
        r"\b(verify|confirm|update|validate) (your )?(account|identity|information|details|payment)",
        r"\b(send|tell|give|share|read) (me )?(the|your|that) (code|verification code|otp|pin)\b",
        r"\bsocial security( number)?\b",
        r"\bSSN\b",
        r"\bpassword\b",
        r"\blog ?in to (restore|unlock|verify)",
    ),
    _p(
        "prize",
        "Promises a prize or free money",
        "medium",
        r"\byou('ve| have)? won\b",
        r"\bwinner\b",
        r"\bclaim (your )?(prize|reward|gift|refund)\b",
        r"\bcongratulations\b",
        r"\bfree (iphone|gift|money)\b",
        r"\bunclaimed\b",
        r"\brefund (is )?(pending|available)\b",
    ),
    _p(
        "job",
        "Too-good-to-be-true job offer",
        "medium",
        r"\$\d{2,4} ?(/|per|a) ?(day|hour|hr)\b",
        r"\bwork from home\b",
        r"\bpart[- ]time (job|position|opportunity)",
        r"\bno experience (needed|required)\b",
        r"\b(whatsapp|telegram|signal)\b.{0,40}\b(hr|recruit|interview|job)",
        r"\b(like|rate|review) (videos|products|apps) (to|and) earn",
    ),
    _p(
        "delivery_toll",
        "Unpaid toll or failed delivery notice",
        "medium",
        r"\bunpaid toll",
        r"\btoll (balance|charges?|violation)",
        r"\boutstanding (toll|balance)\b",
        r"\bredeliver",
        r"\b(package|parcel|shipment) (could not|cannot|can't) be delivered",
        r"\baddress (is )?(incomplete|incorrect)\b",
        r"\bdelivery (failed|attempt)",
    ),
    _p(
        "secrecy",
        "Asks you to keep it secret",
        "high",
        r"\bdon'?t tell (anyone|mom|dad|your)",
        r"\bkeep (this|it) (between us|secret|confidential)\b",
        r"\bdo not (contact|call) (the )?(bank|police)",
    ),
    _p(
        "remote_access",
        "Wants control of your device",
        "high",
        r"\banydesk\b",
        r"\bteamviewer\b",
        r"\bremote (access|desktop|support)\b",
        r"\bcall (microsoft|apple) support\b",
        r"\byour (computer|device|pc) (is|has been) (infected|hacked|compromised|locked)",
    ),
    _p(
        "reply_bait",
        "Unusual instruction to reply or re-open the message",
        "low",
        r"\breply (with )?['\"]?Y['\"]?\b.{0,40}(re-?open|activate|link)",
        r"\bcopy (the|this) link (into|to) (your )?browser",
    ),
]


@dataclass
class PatternHit:
    category: str
    title: str
    severity: Severity
    evidence: str


def find_patterns(text: str) -> list[PatternHit]:
    hits: list[PatternHit] = []
    for pat in PATTERNS:
        m = pat.regex.search(text)
        if m:
            hits.append(PatternHit(pat.category, pat.title, pat.severity, m.group(0)))
    return hits
