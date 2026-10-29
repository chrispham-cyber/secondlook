"""A small trained text classifier: TF-IDF features + logistic regression.

Trained offline by training/train_text_model.py (scikit-learn), then exported to plain JSON so
the app scores messages in pure Python: no scikit-learn at runtime and no pickle files to trust.
Scoring one message takes well under a millisecond.
"""

from __future__ import annotations

import gzip
import json
import math
import re
import unicodedata
from collections import Counter
from functools import lru_cache
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "text_model.json.gz"

_URL = re.compile(
    r"(?:https?://|www\.)\S+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|top|xyz|co|us|io|ly|me|biz|online|site|app|tk)\b\S*"
)
_WORD = re.compile(r"[a-z0-9$£€]+(?:['.][a-z0-9]+)*")
_PHONE = re.compile(r"\+?\d[\d\s().-]{6,}\d")
_MONEY = re.compile(r"[$£€]\s?\d|\d\s?(?:usd|gbp|dollars|pounds)\b")
_HANDLE = re.compile(r"(?<![\w.])@[a-z][a-z0-9_]{2,}\b")  # "@HR_Careers_Dept", not emails
_CODE = re.compile(r"(?<![\d$£€.,-])(?:[a-z]-)?\d{3}[ -]?\d{3,4}(?![\d,]|-\d)|(?<![\d$£€.,-])\d{4,8}(?![\d.,])")


def link_features(text: str) -> list[str]:
    """What the deterministic link checks say about each link, so the model can tell
    tools.usps.com from usps-redelivery.info instead of only reading the words around them."""
    from app.signals.links import extract_urls, static_checks  # local import: links is heavier

    out: list[str] = []
    for url in extract_urls(text)[:5]:
        report = static_checks(url)
        host = report.host or ""
        if report.official_brand:
            out.append("f:link_official")
        elif host.endswith((".gov", ".edu", ".mil")):
            out.append("f:link_gov_edu")
        else:
            out.append("f:link_other")
        out += [f"f:link_{c.name}" for c in report.checks]
    return sorted(set(out))


_TOKEN = re.compile(r"\S+")
_RUN = re.compile(r"(.)\1{8,}", re.DOTALL)
# Well above the longest text the app accepts (20,000 characters) even after normalizing doubles it,
# so padding can't push the real message past the cap.
MAX_FEATURE_CHARS = 50_000


def _normalize(text: str) -> str:
    """NFKC (fullwidth and styled letters to plain ones) without letting a few characters blow the
    text up: characters that expand to 3+ characters (one Arabic ligature becomes 18) count as a
    space, and runs of one repeated character are shortened to 8."""
    text = "".join(
        " " if not ch.isascii() and len(unicodedata.normalize("NFKC", ch)) > 2 else ch
        for ch in _RUN.sub(lambda m: m.group(1) * 8, text)
    )
    return _RUN.sub(lambda m: m.group(1) * 8, unicodedata.normalize("NFKC", text))[:MAX_FEATURE_CHARS]


def _unmask(t: str) -> str:
    """Read look-alike foreign letters inside Latin words as the letters they imitate, so a
    disguised "pаypal" (Cyrillic "а") reads as "paypal". Words written fully in another alphabet
    are left alone, so real Russian or Greek text keeps its own letters."""
    from app.signals.idn import INVISIBLE, STRONG

    def fix(m: re.Match) -> str:
        word = m.group(0)
        if not any("a" <= ch <= "z" for ch in word):
            return word
        word = "".join(ch for ch in word if ch not in INVISIBLE)
        return "".join(STRONG.get(ch, ch) for ch in word) if any(ch in STRONG for ch in word) else word

    return _TOKEN.sub(fix, t)


def features(text: str) -> list[str]:
    """Feature strings for one message. Training and inference both use exactly this function."""
    t = _unmask(" ".join(_normalize(text[: MAX_FEATURE_CHARS * 2]).lower().split()))
    out: list[str] = []
    links = link_features(text)
    if _URL.search(t) or links:
        out.append("f:url")
    if _PHONE.search(t):
        out.append("f:phone")
    if _MONEY.search(t):
        out.append("f:money")
    if _HANDLE.search(t):
        out.append("f:handle")
    if _CODE.search(t):
        out.append("f:code")
    out += links
    # Digits become 0 so "call 0906-123-4567" and "call 0871-999-0000" look alike.
    t = re.sub(r"\d", "0", t)
    words = _WORD.findall(t)
    out += [f"w:{w}" for w in words]
    out += [f"b:{a} {b}" for a, b in zip(words, words[1:], strict=False)]
    padded = f" {t} "
    for n in (3, 4, 5):
        out += [f"c:{padded[i : i + n]}" for i in range(len(padded) - n + 1)]
    return out


def split_features(feats: list[str]) -> tuple[list[str], set[str]]:
    """Wording features (TF-IDF, normalized together) and flag features (kept outside the
    normalization, so a few strong signals like "official link" aren't drowned out by hundreds of
    character n-grams)."""
    return [f for f in feats if not f.startswith("f:")], {f for f in feats if f.startswith("f:")}


class TextModel:
    def __init__(
        self, intercept: float, weights: dict[str, tuple[float, float]], meta: dict, flags: dict[str, float] | None = None
    ) -> None:
        self.intercept = intercept
        self.weights = weights  # wording feature -> (idf, coefficient)
        self.flags = flags or {}  # flag feature -> coefficient (already multiplied by its scale)
        self.meta = meta

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> TextModel:
        data = json.loads(gzip.decompress(path.read_bytes()))
        weights = {k: (v[0], v[1]) for k, v in data["features"].items()}
        return cls(data["intercept"], weights, data.get("meta", {}), data.get("flags"))

    def probability(self, text: str) -> float:
        """Probability (0-1) that the message is a scam. Mirrors scikit-learn's TfidfVectorizer
        (sublinear tf, l2 norm) followed by LogisticRegression.predict_proba."""
        words, flags = split_features(features(text))
        if not self.flags:  # older exports kept flags inside the TF-IDF block
            words, flags = words + sorted(flags), set()
        z = self.intercept + sum(self.flags.get(f, 0.0) for f in flags)
        counts = Counter(f for f in words if f in self.weights)
        if counts:
            vec = {f: (1 + math.log(c)) * self.weights[f][0] for f, c in counts.items()}
            norm = math.sqrt(sum(v * v for v in vec.values()))
            z += sum(v / norm * self.weights[f][1] for f, v in vec.items())
        return 1 / (1 + math.exp(-z))

    def score(self, text: str) -> int:
        return round(self.probability(text) * 100)


@lru_cache(maxsize=1)
def load_default() -> TextModel | None:
    """The bundled model, or None if it hasn't been trained yet."""
    return TextModel.load() if MODEL_PATH.exists() else None
