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


def features(text: str) -> list[str]:
    """Feature strings for one message. Training and inference both use exactly this function."""
    t = " ".join(text.lower().split())
    out: list[str] = []
    if _URL.search(t):
        out.append("f:url")
    if _PHONE.search(t):
        out.append("f:phone")
    if _MONEY.search(t):
        out.append("f:money")
    # Digits become 0 so "call 0906-123-4567" and "call 0871-999-0000" look alike.
    t = re.sub(r"\d", "0", t)
    words = _WORD.findall(t)
    out += [f"w:{w}" for w in words]
    out += [f"b:{a} {b}" for a, b in zip(words, words[1:], strict=False)]
    padded = f" {t} "
    for n in (3, 4, 5):
        out += [f"c:{padded[i : i + n]}" for i in range(len(padded) - n + 1)]
    return out


class TextModel:
    def __init__(self, intercept: float, weights: dict[str, tuple[float, float]], meta: dict) -> None:
        self.intercept = intercept
        self.weights = weights  # feature -> (idf, coefficient)
        self.meta = meta

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> TextModel:
        data = json.loads(gzip.decompress(path.read_bytes()))
        return cls(data["intercept"], {k: (v[0], v[1]) for k, v in data["features"].items()}, data.get("meta", {}))

    def probability(self, text: str) -> float:
        """Probability (0-1) that the message is a scam. Mirrors scikit-learn's TfidfVectorizer
        (sublinear tf, l2 norm) followed by LogisticRegression.predict_proba."""
        counts = Counter(f for f in features(text) if f in self.weights)
        if not counts:
            return 1 / (1 + math.exp(-self.intercept))
        vec = {f: (1 + math.log(c)) * self.weights[f][0] for f, c in counts.items()}
        norm = math.sqrt(sum(v * v for v in vec.values()))
        z = self.intercept + sum(v / norm * self.weights[f][1] for f, v in vec.items())
        return 1 / (1 + math.exp(-z))

    def score(self, text: str) -> int:
        return round(self.probability(text) * 100)


@lru_cache(maxsize=1)
def load_default() -> TextModel | None:
    """The bundled model, or None if it hasn't been trained yet."""
    return TextModel.load() if MODEL_PATH.exists() else None
