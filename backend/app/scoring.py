"""Turns AI judgment + deterministic signals into one 0-100 scam-risk score.

Rule: deterministic signals can only RAISE the score (as floors), never lower it.
A screenshot that says "this message is safe" can fool a model; it can't un-register
a 3-day-old lookalike domain.
"""

from __future__ import annotations

from app.schemas import LinkReport, ScoreAdjustment, Verdict
from app.signals.patterns import PatternHit

LINK_FLOORS: dict[str, tuple[int, str]] = {
    "blocklist": (95, "A link is on a public phishing/malware blocklist"),
    "brand_impersonation": (85, "A link pretends to be a well-known company"),
    "lookalike_domain": (85, "A link imitates a real company's web address"),
    "homograph": (90, "A link is spelled with foreign letters to look like a real company's address"),
    "mixed_scripts": (85, "A link mixes letters from different alphabets"),
    "hidden_characters_in_address": (85, "A link hides invisible characters in its address"),
    "fake_latin_letters": (70, "A link is written in foreign letters that look like English ones"),
    "userinfo_trick": (85, "A link hides its real destination"),
    "new_domain": (80, "A link goes to a website registered in the last 30 days"),
    "ip_address": (70, "A link goes to a raw IP address"),
    "dangerous_download": (60, "A link downloads a program or app installer"),
}

_SEVERITY_POINTS = {"low": 5, "medium": 10, "high": 20}


def verdict_for(score: int) -> Verdict:
    if score >= 85:
        return "scam"
    if score >= 60:
        return "likely_scam"
    if score >= 25:
        return "suspicious"
    return "likely_safe"


def heuristic_score(links: list[LinkReport], patterns: list[PatternHit]) -> int:
    """Baseline score from signals alone (used when the AI is unavailable, and in evals)."""
    score = 5
    for link in links:
        for check in link.checks:
            if check.severity == "medium":
                score += 15
    for hit in patterns:
        score += _SEVERITY_POINTS[hit.severity]
    return min(score, 90)


def floors(links: list[LinkReport], patterns: list[PatternHit]) -> list[ScoreAdjustment]:
    adj: dict[str, ScoreAdjustment] = {}

    def add(key: str, min_score: int, reason: str) -> None:
        if key not in adj or adj[key].min_score < min_score:
            adj[key] = ScoreAdjustment(reason=reason, min_score=min_score)

    for link in links:
        if link.on_blocklist:
            add("blocklist", *LINK_FLOORS["blocklist"])
        for check in link.checks:
            if check.name in LINK_FLOORS:
                add(check.name, *LINK_FLOORS[check.name])

    high_cats = {h.category for h in patterns if h.severity == "high"}
    all_cats = {h.category for h in patterns}
    if len(high_cats) >= 2 or len(all_cats) >= 3:
        add("patterns", 55, f"Several classic scam tactics at once ({', '.join(sorted(all_cats))})")
    return sorted(adj.values(), key=lambda a: -a.min_score)


# The trained text model (app/signals/textmodel.py) is very good at recognizing ordinary messages.
# When it is nearly sure a message is ordinary, the AI alone can say "be careful" but not "likely scam".
# Rule floors still apply on top, so a bad link is flagged whatever the two models think.
# Chosen on dev sets only (evals/combine_study.py).
TEXT_MODEL_SURE_SAFE = 10
CAP_WHEN_SURE_SAFE = 59


def text_model_caps(ai_score: int | None, text_model: int | None) -> bool:
    return ai_score is not None and text_model is not None and text_model < TEXT_MODEL_SURE_SAFE and ai_score > CAP_WHEN_SURE_SAFE


def combine(
    ai_score: int | None,
    links: list[LinkReport],
    patterns: list[PatternHit],
    text_model: int | None = None,
    extra_floors: list[ScoreAdjustment] | None = None,
) -> tuple[int, list[ScoreAdjustment]]:
    """extra_floors: from checks outside links and wording, such as hidden characters or a risky file."""
    adjustments = sorted(floors(links, patterns) + (extra_floors or []), key=lambda a: -a.min_score)
    if ai_score is None:
        # No AI: the rules and the text model, whichever is more worried.
        base = max(heuristic_score(links, patterns), text_model or 0)
    else:
        base = max(0, min(100, ai_score))
        if text_model_caps(ai_score, text_model):
            base = CAP_WHEN_SURE_SAFE
    score = max([base] + [a.min_score for a in adjustments])
    # Only report floors that actually changed the outcome.
    applied = [a for a in adjustments if a.min_score > base]
    return score, applied
