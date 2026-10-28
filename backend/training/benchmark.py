"""Compares model families for the text classifier, plus a learning curve. Dev/training data only.

  uv run python -m training.benchmark            # needs Ollama running for the embedding models

Every model is scored with the same 5 cross-validation folds over the training set from
train_text_model.load(), so each message is predicted by a model that never saw it. Writes
training/BENCHMARK.md. The test sets are never loaded here (load() only uses them to drop near-copies).
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

import httpx
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
from sklearn.model_selection import StratifiedKFold
from sklearn.naive_bayes import ComplementNB
from sklearn.svm import LinearSVC

from app.signals.textmodel import features
from training.train_text_model import MIN_DF, SEED, load

HERE = Path(__file__).parent
CACHE = HERE / "cache"
EMBED_MODELS = ["nomic-embed-text"]
T = 0.6


def embed(texts: list[str], model: str) -> np.ndarray:
    """Embeddings from the local Ollama server, cached on disk."""
    key = hashlib.sha256(("\n".join(texts) + model).encode()).hexdigest()[:16]
    path = CACHE / f"{model.replace(':', '-')}-{key}.npy"
    if path.exists():
        return np.load(path)
    out = []
    with httpx.Client(base_url="http://localhost:11434", timeout=300) as http:
        for i in range(0, len(texts), 64):
            batch = [f"classification: {t[:2000]}" for t in texts[i : i + 64]]
            r = http.post("/api/embed", json={"model": model, "input": batch})
            r.raise_for_status()
            out += r.json()["embeddings"]
    arr = np.array(out, dtype=np.float32)
    arr /= np.linalg.norm(arr, axis=1, keepdims=True)
    CACHE.mkdir(exist_ok=True)
    np.save(path, arr)
    return arr


def tfidf(train: list[str], held: list[str]):
    vec = TfidfVectorizer(analyzer=features, sublinear_tf=True, min_df=MIN_DF, lowercase=False)
    return vec.fit_transform(train), vec.transform(held)


def make_models(emb: dict[str, np.ndarray]):
    """name -> fn(train_idx, held_idx, texts, y, w) -> held probabilities."""

    def tfidf_lr(c):
        def run(tr, he, texts, y, w):
            xa, xb = tfidf([texts[i] for i in tr], [texts[i] for i in he])
            return (
                LogisticRegression(C=c, class_weight="balanced", max_iter=3000)
                .fit(xa, y[tr], sample_weight=w[tr])
                .predict_proba(xb)[:, 1]
            )

        return run

    def tfidf_svm(tr, he, texts, y, w):
        xa, xb = tfidf([texts[i] for i in tr], [texts[i] for i in he])
        svm = CalibratedClassifierCV(LinearSVC(C=0.5, class_weight="balanced"), cv=3)
        return svm.fit(xa, y[tr], sample_weight=w[tr]).predict_proba(xb)[:, 1]

    def tfidf_nb(tr, he, texts, y, w):
        xa, xb = tfidf([texts[i] for i in tr], [texts[i] for i in he])
        return ComplementNB(alpha=0.3).fit(xa, y[tr], sample_weight=w[tr]).predict_proba(xb)[:, 1]

    def emb_lr(name):
        def run(tr, he, texts, y, w):
            x = emb[name]
            return (
                LogisticRegression(C=4, class_weight="balanced", max_iter=3000)
                .fit(x[tr], y[tr], sample_weight=w[tr])
                .predict_proba(x[he])[:, 1]
            )

        return run

    models = {
        "TF-IDF + logistic regression (C=4)": tfidf_lr(4.0),
        "TF-IDF + logistic regression (C=16, shipped)": tfidf_lr(16.0),
        "TF-IDF + linear SVM (calibrated)": tfidf_svm,
        "TF-IDF + complement naive Bayes": tfidf_nb,
    }
    for name in emb:
        models[f"{name} embeddings + logistic regression"] = emb_lr(name)
    return models


def report(y: np.ndarray, p: np.ndarray, mask: np.ndarray) -> tuple[float, float, float]:
    yt, pt = y[mask], p[mask]
    recall = ((pt >= T) & (yt == 1)).sum() / max(1, (yt == 1).sum())
    fpr = ((pt >= T) & (yt == 0)).sum() / max(1, (yt == 0).sum())
    return average_precision_score(yt, pt), recall, fpr


def main() -> None:
    texts, y, w, keys = load()
    us = np.array([k.startswith(("dev:", "dev_blind:")) for k in keys])  # US-style rows that are scored
    us_any = np.array([k.startswith(("dev:", "dev_blind:", "train_us")) for k in keys])  # all US-style rows
    folds = list(StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED).split(texts, y))

    emb: dict[str, np.ndarray] = {}
    for m in EMBED_MODELS:
        try:
            t0 = time.perf_counter()
            emb[m] = embed(texts, m)
            print(f"embedded {len(texts)} messages with {m} in {time.perf_counter() - t0:.0f}s")
        except httpx.HTTPError as exc:
            print(f"skipping {m}: {exc}")

    oof: dict[str, np.ndarray] = {}
    lines = [
        "# Text model benchmark",
        "",
        f"5-fold cross-validation over {len(texts)} training messages ({int(y.sum())} scams; {int(us.sum())} US-style). "
        f"Each message is scored by a model that never saw it. Recall and false alarms at probability {T}.",
        "",
        "| Model | Avg precision (all) | Avg precision (US-style) | US recall | US false alarms | Fit + score time |",
        "|---|---|---|---|---|---|",
    ]
    for name, fn in make_models(emb).items():
        t0 = time.perf_counter()
        p = np.zeros(len(texts))
        for tr, he in folds:
            p[he] = fn(tr, he, texts, y, w)
        oof[name] = p
        ap_all = average_precision_score(y, p)
        ap_us, rec, fpr = report(y, p, us)
        lines.append(f"| {name} | {ap_all:.3f} | {ap_us:.3f} | {rec:.0%} | {fpr:.0%} | {time.perf_counter() - t0:.0f}s |")
        print(lines[-1])
    if emb:
        e = next(k for k in oof if "embeddings" in k)
        avg = (oof["TF-IDF + logistic regression (C=16, shipped)"] + oof[e]) / 2
        ap_us, rec, fpr = report(y, avg, us)
        lines.append(
            f"| Average of shipped TF-IDF model and {e.split(' embeddings')[0]} | {average_precision_score(y, avg):.3f} "
            f"| {ap_us:.3f} | {rec:.0%} | {fpr:.0%} | |"
        )
        print(lines[-1])

    # Learning curve: does more US-style training data still help? All public SMS are always kept.
    lines += [
        "",
        "## Learning curve: US-style training examples",
        "",
        "The shipped model, trained with all public SMS plus a fraction of the US-style messages, "
        "scored on held-out messages from the US-style dev sets.",
        "",
        "| US-style examples in training | Avg precision (US-style) | US recall | US false alarms |",
        "|---|---|---|---|",
    ]
    rng = np.random.default_rng(SEED)
    for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
        p = np.zeros(len(texts))
        n_us = 0
        for tr, he in folds:
            keep = np.array([i for i in tr if not us_any[i] or rng.random() < frac])
            n_us += int(us_any[keep].sum())
            xa, xb = tfidf([texts[i] for i in keep], [texts[i] for i in he])
            clf = LogisticRegression(C=16.0, class_weight="balanced", max_iter=3000).fit(xa, y[keep], sample_weight=w[keep])
            p[he] = clf.predict_proba(xb)[:, 1]
        ap_us, rec, fpr = report(y, p, us)
        lines.append(f"| {n_us // 5} ({frac:.0%}) | {ap_us:.3f} | {rec:.0%} | {fpr:.0%} |")
        print(lines[-1])

    (HERE / "BENCHMARK.md").write_text("\n".join(lines) + "\n")
    print(f"wrote {HERE / 'BENCHMARK.md'}")


if __name__ == "__main__":
    main()
