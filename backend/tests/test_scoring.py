from app.schemas import LinkCheck, LinkReport
from app.scoring import combine, verdict_for
from app.signals.patterns import find_patterns


def link(*checks: tuple[str, str], blocklisted: bool = False) -> LinkReport:
    return LinkReport(
        url="http://x.top",
        host="x.top",
        registrable_domain="x.top",
        on_blocklist=blocklisted,
        checks=[LinkCheck(name=n, severity=s, detail="") for n, s in checks],
    )


def test_verdict_thresholds():
    assert [verdict_for(s) for s in (0, 24, 25, 59, 60, 84, 85, 100)] == [
        "likely_safe",
        "likely_safe",
        "suspicious",
        "suspicious",
        "likely_scam",
        "likely_scam",
        "scam",
        "scam",
    ]


def test_signals_raise_but_never_lower_ai_score():
    score, applied = combine(5, [link(("lookalike_domain", "high"))], [])
    assert score == 85 and applied[0].min_score == 85
    score, applied = combine(97, [link(("lookalike_domain", "high"))], [])
    assert score == 97 and applied == []


def test_blocklist_floor_wins():
    score, _ = combine(10, [link(("new_domain", "high"), blocklisted=True)], [])
    assert score == 95


def test_heuristic_only_when_ai_missing():
    clean, _ = combine(None, [], find_patterns("See you at dinner tonight!"))
    risky, _ = combine(
        None,
        [link(("risky_tld", "medium"))],
        find_patterns("Final notice: pay your unpaid toll within 24 hours or your license will be suspended"),
    )
    assert clean < 25 <= 60 <= risky


def test_patterns_detect_classic_tactics():
    cats = {h.category for h in find_patterns("Buy Google Play gift cards and don't tell anyone. Send me the code.")}
    assert {"payment_method", "secrecy", "credentials"} <= cats
