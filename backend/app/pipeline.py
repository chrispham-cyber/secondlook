"""Orchestrates one scan: AI analysis + link checks + pattern signals -> final ScanResponse."""

from __future__ import annotations

import asyncio
import time
import uuid
from urllib.parse import urlsplit

import httpx

from app.config import Settings
from app.files import Inspection
from app.llm import LLMResult, LLMUnavailable
from app.providers import Analyzer
from app.schemas import FileCheck, LinkCheck, LinkReport, RedFlag, ScanMeta, ScanResponse, ScoreAdjustment, ScoreBreakdown
from app.scoring import combine, text_model_caps, verdict_for
from app.signals.blocklist import Blocklist
from app.signals.content import content_floors, scan_content
from app.signals.links import (
    age_checks,
    ascii_domain,
    domain_age_days,
    extract_urls,
    normalize_url,
    static_checks,
)
from app.signals.patterns import find_patterns
from app.signals.textmodel import load_default as load_text_model

MAX_LINKS = 15

DEFAULT_ADVICE = {
    "likely_safe": [
        "Nothing obviously wrong was found, but if it asks for money or personal details, check with the company using its official app or phone number."
    ],
    "suspicious": [
        "Don't click links or reply until you've checked.",
        "Contact the company directly using its official app, website, or the phone number on your card or bill.",
    ],
    "likely_scam": [
        "Don't click any links, call any numbers, or reply.",
        "If it claims to be a company you use, contact them through their official app or website instead.",
        "Forward scam texts to 7726 (SPAM) and report it at reportfraud.ftc.gov.",
    ],
    "scam": [
        "Don't click any links, call any numbers, or reply.",
        "If you already paid or shared a code or password, call your bank right away and change that password.",
        "Forward scam texts to 7726 (SPAM) and report it at reportfraud.ftc.gov.",
    ],
}

DANGEROUS_FILE_ADVICE = [
    "Don't open the file on any computer or phone. Delete it, and delete the message it came with.",
    "Don't reply or click the links in that message.",
    "If it claims to be from a company or person you know, contact them using a phone number or website you already trust.",
    "If you already opened it: disconnect from the internet, run a virus scan, and change important passwords from a different device.",
    "Report it at reportfraud.ftc.gov.",
]
CANT_CHECK_ADVICE = [
    "Don't open the file unless you were expecting it from someone you know, and you've confirmed with them by phone.",
    "Ask the sender for a plain PDF, or open it only on a device you don't use for banking.",
    "If it came with a password in the same message, that is a warning sign: scammers lock files to hide them from security scanners.",
]
# Findings that mean "we couldn't look inside" rather than "we saw something bad".
CANT_CHECK = {
    "password_protected",
    "unsupported_file",
    "legacy_office",
    "file_is_legacy_office",
    "file_is_rtf",
    "file_is_archive",
    "not_a_word_document",
    "unreadable_file",
}

DEGRADED_HEADLINES = {
    "likely_safe": "Our automatic checks didn't find warning signs, but the AI review was unavailable.",
    "suspicious": "Some warning signs were found. Be careful and verify before acting.",
    "likely_scam": "Several warning signs point to a scam.",
    "scam": "Strong warning signs point to a scam.",
}


class ScanUnavailable(Exception):
    pass


class LinkAnalyzer:
    def __init__(self, settings: Settings, http: httpx.AsyncClient, blocklist: Blocklist) -> None:
        self.settings = settings
        self.http = http
        self.blocklist = blocklist

    async def analyze(self, url: str) -> LinkReport:
        report = static_checks(url)
        # Check every form of the host (as written, folded, decoded, encoded) against the parsed path.
        parts = urlsplit(url)
        path = parts.path
        hosts = {parts.hostname or "", report.host, report.host_unicode or "", report.host_ascii or ""} - {""}
        report.on_blocklist = self.blocklist.match(url) or any(self.blocklist.match_host(h, path) for h in hosts)
        if report.on_blocklist:
            report.checks.insert(
                0,
                LinkCheck(
                    name="blocklist", severity="high", detail="This link is on a public list of known phishing or malware sites."
                ),
            )
        is_ip = report.host == report.registrable_domain and report.host.replace(".", "").isdigit()
        if self.settings.network_checks and not report.official_brand and not is_ip:
            age, exists = await domain_age_days(
                self.http, ascii_domain(report.registrable_domain), self.settings.rdap_timeout_seconds
            )
            age_checks(report, age, exists)
        return report


class ScanPipeline:
    def __init__(self, settings: Settings, analyzer: Analyzer, links: LinkAnalyzer) -> None:
        self.settings = settings
        self.analyzer = analyzer
        self.links = links

    def blocked_file(self, inspection: Inspection) -> ScanResponse:
        """A document that failed the safety checks. Its contents were never read or sent to the AI."""
        check = inspection.check
        top = check.findings[0] if check.findings else None
        cant_check = top is not None and top.name in CANT_CHECK
        score = max(inspection.risk, 60)
        verdict = verdict_for(score)
        if cant_check:
            headline = "We couldn't check this file safely, so we didn't open it. Don't open it yourself either."
            advice = CANT_CHECK_ADVICE
        else:
            headline = "This file can harm your device. Don't open it."
            advice = DANGEROUS_FILE_ADVICE
        return ScanResponse(
            id=str(uuid.uuid4()),
            risk_score=score,
            verdict=verdict,
            headline=headline,
            scam_type="malware" if not cant_check else "none",
            channel="unknown",
            claimed_sender="",
            red_flags=[RedFlag(title=f.title, detail=f.detail, severity=f.severity, source="file_check") for f in check.findings],
            safe_signals=[],
            what_to_do=advice,
            links=[],
            extracted_text="",
            score_breakdown=ScoreBreakdown(
                ai_score=None, adjustments=[ScoreAdjustment(reason=top.title if top else "Unsafe file", min_score=score)]
            ),
            meta=ScanMeta(model=None, latency_ms=0, cost_usd=0.0, input_tokens=0, output_tokens=0, degraded=False),
            file_check=check,
        )

    async def run(self, text: str | None, image: tuple[str, str] | None, file_check: FileCheck | None = None) -> ScanResponse:
        started = time.perf_counter()
        reports: dict[str, LinkReport] = {}

        async def check(raw_urls: list[str]) -> list[LinkReport]:
            urls = []
            for raw in raw_urls:
                url = normalize_url(raw)
                if url and url not in reports and url not in urls and len(reports) + len(urls) < MAX_LINKS:
                    urls.append(url)
            for url, rep in zip(urls, await asyncio.gather(*(self.links.analyze(u) for u in urls)), strict=True):
                reports[url] = rep
            wanted = {normalize_url(r) for r in raw_urls}
            return [r for u, r in reports.items() if u in wanted]

        llm: LLMResult | None = None
        degraded_reason: str | None = None
        try:
            llm = await self.analyzer.analyze(text, image, check)
        except LLMUnavailable as exc:
            if image is not None and not text:
                raise ScanUnavailable(str(exc)) from exc
            degraded_reason = str(exc)

        extracted = llm.analysis.extracted_text if llm else ""
        all_text = "\n".join(t for t in (text, extracted) if t)
        # Safety net: check every link we can find, even ones the model didn't pass to the tool.
        await check(extract_urls(all_text) + (llm.analysis.urls if llm else []))
        link_reports = list(reports.values())
        patterns = find_patterns(all_text)
        content = scan_content(all_text)

        ai_score = llm.analysis.scam_probability if llm else None
        text_model = load_text_model()
        tm_score = text_model.score(all_text) if text_model and all_text.strip() else None
        score, applied = combine(ai_score, link_reports, patterns, tm_score, content_floors(content))
        verdict = verdict_for(score)
        capped = text_model_caps(ai_score, tm_score) and not applied and verdict_for(ai_score or 0) != verdict

        flags: list[RedFlag] = []
        if llm:
            flags += [RedFlag(title=f.title, detail=f.detail, severity=f.severity, source="ai") for f in llm.analysis.red_flags]
        seen = {f.title.lower() for f in flags}
        for rep in link_reports:
            for c in rep.checks:
                if c.severity in ("medium", "high"):
                    title = f"Suspicious link: {rep.registrable_domain}"
                    flags.append(RedFlag(title=title, detail=c.detail, severity=c.severity, source="link_check"))
        for c in content:
            flags.append(RedFlag(title=c.title, detail=c.detail, severity=c.severity, source="content_check"))
        if file_check:
            for f in file_check.findings:
                if f.severity != "low":
                    flags.append(RedFlag(title=f.title, detail=f.detail, severity=f.severity, source="file_check"))
        if not llm:
            for hit in patterns:
                if hit.title.lower() not in seen:
                    flags.append(
                        RedFlag(
                            title=hit.title, detail=f'The message says "{hit.evidence}".', severity=hit.severity, source="pattern"
                        )
                    )

        safe = list(llm.analysis.safe_signals) if llm else []
        for rep in link_reports:
            if rep.official_brand and not rep.checks:
                safe.append(f"The link goes to an official website ({rep.registrable_domain}).")

        if llm:
            headline = llm.analysis.headline
            if applied and verdict_for(ai_score or 0) != verdict:
                headline = f"{applied[0].reason}. Treat this as a likely scam, even though the message may look normal."
            advice = llm.analysis.what_to_do or DEFAULT_ADVICE[verdict]
            if capped:
                headline = (
                    "Some things here deserve a second look, but this reads like an ordinary message. Check before you act."
                )
                advice = DEFAULT_ADVICE[verdict]
            if applied and verdict in ("likely_scam", "scam") and verdict_for(ai_score or 0) in ("likely_safe", "suspicious"):
                advice = DEFAULT_ADVICE[verdict]
        else:
            headline = DEGRADED_HEADLINES[verdict]
            advice = DEFAULT_ADVICE[verdict]

        return ScanResponse(
            id=str(uuid.uuid4()),
            risk_score=score,
            verdict=verdict,
            headline=headline,
            scam_type=llm.analysis.scam_type if llm else _guess_scam_type(score, patterns, link_reports),
            channel=llm.analysis.channel if llm else "unknown",
            claimed_sender=llm.analysis.claimed_sender if llm else "",
            red_flags=sorted(flags, key=lambda f: {"high": 0, "medium": 1, "low": 2}[f.severity]),
            safe_signals=safe,
            what_to_do=advice,
            links=link_reports,
            extracted_text=extracted,
            score_breakdown=ScoreBreakdown(ai_score=ai_score, text_model_score=tm_score, adjustments=applied),
            file_check=file_check,
            meta=ScanMeta(
                model=llm.model if llm else None,
                latency_ms=int((time.perf_counter() - started) * 1000),
                cost_usd=round(llm.cost_usd, 6) if llm else 0.0,
                input_tokens=llm.input_tokens if llm else 0,
                output_tokens=llm.output_tokens if llm else 0,
                degraded=llm is None,
                degraded_reason=degraded_reason,
            ),
        )


# Without the AI, name the scam type from the strongest rule that fired.
_PATTERN_TYPES = {
    "remote_access": "tech_support",
    "delivery_toll": "package_delivery",
    "job": "job_or_task",
    "prize": "prize_or_lottery",
    "credentials": "account_login_phishing",
}
_BRAND_TYPES = {
    "sunpass": "toll_or_parking_payment",
    "ezpass": "toll_or_parking_payment",
    "txtag": "toll_or_parking_payment",
    "usps": "package_delivery",
    "ups": "package_delivery",
    "fedex": "package_delivery",
    "dhl": "package_delivery",
    "irs": "government_impersonation",
    "ssa": "government_impersonation",
    "medicare": "government_impersonation",
}


def _guess_scam_type(score: int, patterns, links) -> str:
    if score < 25:
        return "none"
    text = " ".join(f"{c.detail}" for r in links for c in r.checks).lower()
    for brand, kind in _BRAND_TYPES.items():
        if f"'{brand}'" in text or f"imitates {brand}." in text:
            return kind
    for hit in patterns:
        if hit.category in _PATTERN_TYPES:
            kind = _PATTERN_TYPES[hit.category]
            if kind == "package_delivery" and "toll" in hit.evidence.lower():
                return "toll_or_parking_payment"
            return kind
    return "other"
