"""Picks how to mix the trained text model with the AI and the rules, using dev sets only.

  uv run python -m evals.combine_study

Every dev message gets an out-of-fold text-model score (training/oof.json, from a model that never
saw it), and its AI and rules scores come from the newest dev eval reports. Nothing here touches the
test sets.
"""

from __future__ import annotations

import json
from pathlib import Path

from evals.summarize import load_runs

HERE = Path(__file__).parent
OOF = json.loads((HERE.parent / "training" / "oof.json").read_text())
T = 60


def rows_for(dataset: str) -> list[dict]:
    run = next(r for r in load_runs() if r.dataset == dataset and r.model.startswith("ollama/") and r.mode == "text")
    out = []
    for r in run.rows:
        ml = OOF.get(f"{dataset}:{r['id']}")
        if ml is not None and r.get("ai") is not None:
            floor = r["combined"] if r["combined"] > r["ai"] else 0
            out.append(r | {"ml": round(ml * 100), "floor": floor})
    return out


# Each candidate maps (ai, ml, rules-with-floors, floor) -> final score.
WITH_AI = {
    "AI + rules (current)": lambda ai, ml, rules, floor: max(ai, floor),
    "average of AI and model": lambda ai, ml, rules, floor: max(round((ai + ml) / 2), floor),
    "0.7 AI + 0.3 model": lambda ai, ml, rules, floor: max(round(0.7 * ai + 0.3 * ml), floor),
    "model >= 90 raises to 60": lambda ai, ml, rules, floor: max(ai, floor, 60 if ml >= 90 else 0),
    "model < 10 caps AI at 59": lambda ai, ml, rules, floor: max(min(ai, 59) if ml < 10 else ai, floor),
    "both: raise at 90, cap at 10": lambda ai, ml, rules, floor: max(
        min(ai, 59) if ml < 10 else ai, floor, 60 if ml >= 90 else 0
    ),
}
NO_AI = {
    "rules only (current)": lambda ai, ml, rules, floor: rules,
    "max(rules, model)": lambda ai, ml, rules, floor: max(rules, ml),
}


def metrics(rows: list[dict], fn) -> str:
    tp = fp = fn_ = tn = 0
    for r in rows:
        s = fn(r["ai"], r["ml"], r["heuristics"], r["floor"])
        scam = r["label"] == "scam"
        tp += scam and s >= T
        fn_ += scam and s < T
        fp += (not scam) and s >= T
        tn += (not scam) and s < T
    p = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn_)
    f1 = 2 * p * rec / (p + rec) if p + rec else 0
    return f"recall {rec:4.0%}  false alarms {fp / (fp + tn):4.0%}  F1 {f1:.2f}"


def main() -> None:
    sets = {d: rows_for(d) for d in ("dev", "dev_blind", "dev_public")}
    for title, cands in (("Without the AI", NO_AI), ("With the AI", WITH_AI)):
        print(f"\n## {title}")
        for name, fn in cands.items():
            print(f"{name:30}" + " | ".join(f"{d}: {metrics(rows, fn)}" for d, rows in sets.items()))


if __name__ == "__main__":
    main()
