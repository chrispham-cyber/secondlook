"""Trains the text classifier in app/signals/textmodel.py and exports it to app/models/text_model.json.gz.

  uv run python -m training.train_text_model

Training data:
  - Real SMS from Mishra & Soni 2022 (evals/data/raw_mendeley/, see evals/data/README.md):
    "smishing" -> scam, "ham" -> legit. Marketing "spam" is left out.
  - The US-style dev sets (evals/data/dev.jsonl, dev_blind.jsonl) and training-only sets
    (evals/data/train_us_*.jsonl, written blind like the test set), weighted higher because they are
    the closest match to the app's real users but there are few of them.
Never trained on: evals/data/test.jsonl and evals/data/public.jsonl. Messages from train_us_*.jsonl
that are 70%+ similar to a blind-test message are dropped, and public messages 80%+ similar to a
public-test message (the same scam campaign, reworded). Any other training message that is a
near-duplicate of a test message (same letters once digits, punctuation and case are ignored, or the
same first 40 letters) is dropped, since the public dataset reuses templates with different numbers.

Also writes training/oof.json: out-of-fold scam probabilities for every dev message (each one scored
by a model that never saw it), used by evals/combine_study.py to pick how to mix this model with the AI.
"""

from __future__ import annotations

import csv
import difflib
import gzip
import html
import json
import re
import sys
from pathlib import Path

import numpy as np
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score
from sklearn.model_selection import StratifiedKFold

from app.signals.textmodel import MODEL_PATH, features, split_features

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "evals" / "data"
RAW = DATA / "raw_mendeley" / "Dataset_5971.csv"
# Miltchev, Rangelov & Genchev 2024, "Phishing validation emails dataset", Zenodo 13474746, CC BY 4.0.
EMAILS = DATA / "raw_zenodo" / "Phishing_validation_emails.csv"
US_WEIGHT = 5.0
GRID_C = [4.0, 16.0, 32.0]
GRID_FLAG_SCALE = [0.3, 0.6, 1.0]
MIN_DF = 3
SEED = 7


def letters(text: str) -> str:
    return re.sub(r"[^a-z]+", "", text.lower())


def read_jsonl(name: str) -> list[dict]:
    return [json.loads(line) for line in (DATA / name).read_text().splitlines() if line.strip()]


def load() -> tuple[list[str], np.ndarray, np.ndarray, list[str]]:
    test_rows = read_jsonl("test.jsonl") + read_jsonl("public.jsonl")
    banned = {letters(r["text"]) for r in test_rows}
    banned_prefix = {letters(r["text"])[:40] for r in test_rows}

    blind_test = [r["text"] for r in test_rows if r["id"].startswith("t")]

    public_test = [r["text"] for r in test_rows if not r["id"].startswith("t")]

    def similar(text: str, others: list[str], threshold: float) -> bool:
        sm = difflib.SequenceMatcher(None, text)
        for t in others:
            sm.set_seq2(t)
            if sm.real_quick_ratio() >= threshold and sm.quick_ratio() >= threshold and sm.ratio() >= threshold:
                return True
        return False

    def similar_to_test(text: str) -> bool:
        # Training-only sets were generated the same way as the blind test, so also drop
        # anything that reads like a close variant of a test message, not just exact copies.
        return similar(text, blind_test, 0.7)

    def near_test(text: str) -> bool:
        k = letters(text)
        return k in banned or k[:40] in banned_prefix

    # Dev messages keep their ids so their out-of-fold scores can be matched to eval reports.
    # Messages are de-duplicated by their letters so near-copies can't land on both sides of a fold.
    rows: dict[str, tuple[str, str, float, str]] = {}
    dropped = 0
    us_files = ["dev.jsonl", "dev_blind.jsonl"] + sorted(p.name for p in DATA.glob("train_us_*.jsonl"))
    for name in us_files:
        for r in read_jsonl(name):
            if name.startswith("train_us") and (near_test(r["text"]) or similar_to_test(r["text"])):
                dropped += 1
                continue
            rows.setdefault(letters(r["text"]), (r["text"], r["label"], US_WEIGHT, f"{name.removesuffix('.jsonl')}:{r['id']}"))
    dev_public = {letters(r["text"]): r["id"] for r in read_jsonl("dev_public.jsonl")}
    for row in csv.DictReader(RAW.open(encoding="utf-8", errors="replace")):
        label = {"smishing": "scam", "ham": "legit"}.get(row["LABEL"].strip().lower())
        text = html.unescape(" ".join(row["TEXT"].split())).replace("\ufffd", "£")
        if not label or len(text) < 20:
            continue
        # Public scams come in campaigns: the same template reworded. Drop close variants of public-test messages too.
        if near_test(text) or similar(text, public_test, 0.8):
            dropped += 1
            continue
        k = letters(text)
        rows.setdefault(k, (text, label, 1.0, f"dev_public:{dev_public[k]}" if k in dev_public else ""))
    # A small email supplement: the Zenodo set repeats ~57 templates, so only one copy of each is kept.
    if EMAILS.exists():
        for row in csv.DictReader(EMAILS.open(encoding="utf-8", errors="replace")):
            text = " ".join(row["Email Text"].split())
            label = {"phishing email": "scam", "safe email": "legit"}.get(row["Email Type"].strip().lower())
            k = letters(re.sub(r"^dear \w+,?", "dear x,", text.lower()))
            if label and not near_test(text) and not similar(text, public_test, 0.8):
                rows.setdefault(k, (text, label, 1.0, ""))
    texts = [r[0] for r in rows.values()]
    labels = [1 if r[1] == "scam" else 0 for r in rows.values()]
    weights = [r[2] for r in rows.values()]
    keys = [r[3] for r in rows.values()]
    print(f"training messages: {len(texts)} ({sum(labels)} scam); dropped {dropped} near-duplicates of test messages")
    return texts, np.array(labels), np.array(weights), keys


class Vectorizer:
    """TF-IDF over the wording features, plus a separate block of 0/1 flag features times `scale`."""

    def __init__(self, scale: float) -> None:
        self.scale = scale
        self.tfidf = TfidfVectorizer(analyzer=lambda f: f, sublinear_tf=True, min_df=MIN_DF, lowercase=False)

    def fit_transform(self, feats: list[tuple[list[str], set[str]]]) -> sp.csr_matrix:
        self.flag_names = sorted({f for _, flags in feats for f in flags})
        return self._stack(self.tfidf.fit_transform([w for w, _ in feats]), feats)

    def transform(self, feats: list[tuple[list[str], set[str]]]) -> sp.csr_matrix:
        return self._stack(self.tfidf.transform([w for w, _ in feats]), feats)

    def _stack(self, words: sp.csr_matrix, feats: list[tuple[list[str], set[str]]]) -> sp.csr_matrix:
        col = {f: i for i, f in enumerate(self.flag_names)}
        flags = sp.lil_matrix((len(feats), len(col)))
        for r, (_, fl) in enumerate(feats):
            for f in fl:
                if f in col:
                    flags[r, col[f]] = self.scale
        return sp.hstack([words, flags.tocsr()]).tocsr()


def fit(feats: list, y: np.ndarray, w: np.ndarray, c: float, scale: float) -> tuple[Vectorizer, LogisticRegression]:
    vec = Vectorizer(scale)
    x = vec.fit_transform(feats)
    clf = LogisticRegression(C=c, class_weight="balanced", max_iter=5000)
    clf.fit(x, y, sample_weight=w)
    return vec, clf


def out_of_fold(feats: list, y: np.ndarray, w: np.ndarray, c: float, scale: float) -> np.ndarray:
    oof = np.zeros(len(feats))
    for train, held in StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED).split(feats, y):
        vec, clf = fit([feats[i] for i in train], y[train], w[train], c, scale)
        oof[held] = clf.predict_proba(vec.transform([feats[i] for i in held]))[:, 1]
    return oof


def export(vec: Vectorizer, clf: LogisticRegression, digits: int = 5) -> dict:
    """The JSON that app/signals/textmodel.py loads. Flag coefficients are stored pre-multiplied by the scale."""
    names = vec.tfidf.get_feature_names_out()
    coef = clf.coef_[0]
    return {
        "intercept": float(clf.intercept_[0]),
        "features": {
            str(f): [round(float(i), digits), round(float(k), digits)]
            for f, i, k in zip(names, vec.tfidf.idf_, coef[: len(names)], strict=True)
        },
        "flags": {f: round(float(k) * vec.scale, digits) for f, k in zip(vec.flag_names, coef[len(names) :], strict=True)},
    }


def main() -> None:
    if not RAW.exists():
        sys.exit(f"Missing {RAW}. See evals/data/make_public.py for the download.")
    texts, y, w, keys = load()
    feats = [split_features(features(t)) for t in texts]
    us = np.array([k.startswith(("dev:", "dev_blind:")) for k in keys])  # scored for model selection

    best = None
    for c in GRID_C:
        for scale in GRID_FLAG_SCALE:
            oof = out_of_fold(feats, y, w, c, scale)
            ap_all, ap_us = average_precision_score(y, oof), average_precision_score(y[us], oof[us])
            f1_us = f1_score(y[us], oof[us] >= 0.5)
            print(
                f"C={c:<5} flags x{scale:<4} cross-validated average precision: all {ap_all:.3f}, "
                f"US-style {ap_us:.3f} (F1 at 0.5: {f1_us:.2f})"
            )
            if best is None or ap_us + ap_all > best[0]:
                best = (ap_us + ap_all, c, scale, oof, ap_all, ap_us)
    _, c, scale, oof, ap_all, ap_us = best
    print(f"chose C={c}, flag scale {scale}")

    (ROOT / "training" / "oof.json").write_text(
        json.dumps({k: round(float(p), 4) for k, p in zip(keys, oof, strict=True) if k}, indent=0)
    )

    vec, clf = fit(feats, y, w, c, scale)
    model = export(vec, clf)
    model["meta"] = {
        "trained_on": len(texts),
        "scam": int(y.sum()),
        "C": c,
        "flag_scale": scale,
        "cv_average_precision": round(ap_all, 3),
        "cv_average_precision_us": round(ap_us, 3),
    }
    MODEL_PATH.parent.mkdir(exist_ok=True)
    MODEL_PATH.write_bytes(gzip.compress(json.dumps(model, separators=(",", ":")).encode(), mtime=0))
    print(
        f"wrote {MODEL_PATH.relative_to(ROOT)}: {len(model['features'])} wording features + "
        f"{len(model['flags'])} flags, {MODEL_PATH.stat().st_size / 1e6:.1f} MB"
    )

    # The exported pure-Python scorer must match scikit-learn exactly.
    from app.signals.textmodel import TextModel

    tm = TextModel.load()
    sk = clf.predict_proba(vec.transform(feats[:200]))[:, 1]
    gap = max(abs(tm.probability(t) - p) for t, p in zip(texts[:200], sk, strict=True))
    print(f"max difference between exported model and scikit-learn on 200 messages: {gap:.2e}")
    assert gap < 1e-3


if __name__ == "__main__":
    main()
