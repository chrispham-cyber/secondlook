"""Trains the text classifier in app/signals/textmodel.py and exports it to app/models/text_model.json.gz.

  uv run python -m training.train_text_model

Training data:
  - Real SMS from Mishra & Soni 2022 (evals/data/raw_mendeley/, see evals/data/README.md):
    "smishing" -> scam, "ham" -> legit. Marketing "spam" is left out.
  - The US-style dev sets (evals/data/dev.jsonl, dev_blind.jsonl) and training-only sets
    (evals/data/train_us_*.jsonl, written blind like the test set), weighted higher because they are
    the closest match to the app's real users but there are few of them.
Never trained on: evals/data/test.jsonl and evals/data/public.jsonl. Messages from train_us_*.jsonl
that are 70%+ similar to a blind-test message are dropped. Any other training message that is a
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
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score
from sklearn.model_selection import StratifiedKFold

from app.signals.textmodel import MODEL_PATH, features

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "evals" / "data"
RAW = DATA / "raw_mendeley" / "Dataset_5971.csv"
# Miltchev, Rangelov & Genchev 2024, "Phishing validation emails dataset", Zenodo 13474746, CC BY 4.0.
EMAILS = DATA / "raw_zenodo" / "Phishing_validation_emails.csv"
US_WEIGHT = 5.0
GRID_C = [1.0, 4.0, 16.0]
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

    def similar_to_test(text: str) -> bool:
        # Training-only sets were generated the same way as the blind test, so also drop
        # anything that reads like a close variant of a test message, not just exact copies.
        return any(difflib.SequenceMatcher(None, text, t).ratio() >= 0.7 for t in blind_test)

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
        if near_test(text):
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
            if label and not near_test(text):
                rows.setdefault(k, (text, label, 1.0, ""))
    texts = [r[0] for r in rows.values()]
    labels = [1 if r[1] == "scam" else 0 for r in rows.values()]
    weights = [r[2] for r in rows.values()]
    keys = [r[3] for r in rows.values()]
    print(f"training messages: {len(texts)} ({sum(labels)} scam); dropped {dropped} near-duplicates of test messages")
    return texts, np.array(labels), np.array(weights), keys


def fit(texts: list[str], y: np.ndarray, w: np.ndarray, c: float) -> tuple[TfidfVectorizer, LogisticRegression]:
    vec = TfidfVectorizer(analyzer=features, sublinear_tf=True, min_df=MIN_DF, lowercase=False)
    x = vec.fit_transform(texts)
    clf = LogisticRegression(C=c, class_weight="balanced", max_iter=3000)
    clf.fit(x, y, sample_weight=w)
    return vec, clf


def out_of_fold(texts: list[str], y: np.ndarray, w: np.ndarray, c: float) -> np.ndarray:
    oof = np.zeros(len(texts))
    for train, held in StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED).split(texts, y):
        vec, clf = fit([texts[i] for i in train], y[train], w[train], c)
        oof[held] = clf.predict_proba(vec.transform([texts[i] for i in held]))[:, 1]
    return oof


def main() -> None:
    if not RAW.exists():
        sys.exit(f"Missing {RAW}. See evals/data/make_public.py for the download.")
    texts, y, w, keys = load()
    us = np.array([k.startswith(("dev:", "dev_blind:")) for k in keys])  # scored for model selection

    best = None
    for c in GRID_C:
        oof = out_of_fold(texts, y, w, c)
        ap_all, ap_us = average_precision_score(y, oof), average_precision_score(y[us], oof[us])
        f1_us = f1_score(y[us], oof[us] >= 0.5)
        print(f"C={c:<5} cross-validated average precision: all {ap_all:.3f}, US-style {ap_us:.3f} (F1 at 0.5: {f1_us:.2f})")
        if best is None or ap_us + ap_all > best[0]:
            best = (ap_us + ap_all, c, oof, ap_all, ap_us)
    _, c, oof, ap_all, ap_us = best
    print(f"chose C={c}")

    (ROOT / "training" / "oof.json").write_text(
        json.dumps({k: round(float(p), 4) for k, p in zip(keys, oof, strict=True) if k}, indent=0)
    )

    vec, clf = fit(texts, y, w, c)
    names = vec.get_feature_names_out()
    model = {
        "intercept": float(clf.intercept_[0]),
        "features": {
            str(f): [round(float(i), 5), round(float(k), 5)] for f, i, k in zip(names, vec.idf_, clf.coef_[0], strict=True)
        },
        "meta": {
            "trained_on": len(texts),
            "scam": int(y.sum()),
            "C": c,
            "cv_average_precision": round(ap_all, 3),
            "cv_average_precision_us": round(ap_us, 3),
        },
    }
    MODEL_PATH.parent.mkdir(exist_ok=True)
    MODEL_PATH.write_bytes(gzip.compress(json.dumps(model, separators=(",", ":")).encode(), mtime=0))
    print(f"wrote {MODEL_PATH.relative_to(ROOT)}: {len(names)} features, {MODEL_PATH.stat().st_size / 1e6:.1f} MB")

    # The exported pure-Python scorer must match scikit-learn exactly.
    from app.signals.textmodel import TextModel

    tm = TextModel.load()
    sk = clf.predict_proba(vec.transform(texts[:200]))[:, 1]
    gap = max(abs(tm.probability(t) - p) for t, p in zip(texts[:200], sk, strict=True))
    print(f"max difference between exported model and scikit-learn on 200 messages: {gap:.2e}")
    assert gap < 1e-3


if __name__ == "__main__":
    main()
