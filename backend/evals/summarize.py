"""Collects every measured number into evals/METRICS.md.

  uv run python -m evals.summarize            # eval results only
  uv run python -m evals.summarize --tests    # also run the test suite for test count and coverage

Uses the newest report for each (dataset, model, input mode) in evals/reports/. Every number in the
output comes from a run on disk, so it can be re-checked. Ranges are 95% Wilson confidence intervals.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).parent
REPORTS = HERE / "reports"
NAME = re.compile(r"^(?P<stamp>\d{8}-\d{6})__(?P<dataset>[^_]+(?:_[^_]+)*?)__(?P<model>.+)__(?P<mode>text|screenshot)\.jsonl$")
DATASETS = {
    "test": "Test set (written blind to the detector, never looked at while tuning)",
    "public": "Real messages from a public dataset (never looked at while tuning)",
    "dev_blind": "Dev: blind-written set (its errors guided the last prompt fix)",
    "dev_public": "Dev: real public messages (its errors guided the last prompt fix)",
    "dev": "Dev: original set (used while building the rules; optimistic)",
}
THRESHOLD = 60


@dataclass
class Run:
    dataset: str
    model: str
    mode: str
    stamp: str
    rows: list[dict]


def load_runs() -> list[Run]:
    latest: dict[tuple[str, str, str], Run] = {}
    for path in sorted(REPORTS.glob("*.jsonl")):
        m = NAME.match(path.name)
        if not m:
            continue
        rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
        model = m["model"].replace("ollama_", "ollama/")
        if model != "rules" and not any(r.get("ai") is not None for r in rows):
            continue  # an AI run where every call failed
        key = (m["dataset"], model, m["mode"])
        if key not in latest or m["stamp"] > latest[key].stamp:
            latest[key] = Run(m["dataset"], model, m["mode"], m["stamp"], rows)
    return list(latest.values())


def shipped(rows: list[dict]) -> list[dict]:
    """What the app would have answered: when the AI call failed, it falls back to the rules score."""
    return [r | {"combined": r.get("offline", r["heuristics"])} if r.get("combined") is None else r for r in rows]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def score(rows: list[dict], system: str) -> dict:
    rows = [r for r in rows if r.get(system) is not None]
    tp = sum(r["label"] == "scam" and r[system] >= THRESHOLD for r in rows)
    fn = sum(r["label"] == "scam" and r[system] < THRESHOLD for r in rows)
    fp = sum(r["label"] == "legit" and r[system] >= THRESHOLD for r in rows)
    tn = sum(r["label"] == "legit" and r[system] < THRESHOLD for r in rows)
    p = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {
        "n": len(rows),
        "tp": tp,
        "fp": fp,
        "scams": tp + fn,
        "legit": fp + tn,
        "precision": p,
        "recall": rec,
        "recall_ci": wilson(tp, tp + fn),
        "f1": 2 * p * rec / (p + rec) if p + rec else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "fpr_ci": wilson(fp, fp + tn),
    }


def injection(rows: list[dict], system: str) -> tuple[int, int]:
    inj = [r for r in rows if r.get("injection") and r.get(system) is not None]
    return sum(r[system] >= THRESHOLD for r in inj), len(inj)


def gained_types(rows: list[dict]) -> str:
    """Scam categories the shipped system flags that the rules alone miss, most common first."""
    gained: dict[str, int] = {}
    for r in rows:
        if r["label"] == "scam" and r.get("combined") is not None and r["combined"] >= THRESHOLD > r["heuristics"]:
            gained[r["category"]] = gained.get(r["category"], 0) + 1
    top = sorted(gained.items(), key=lambda kv: -kv[1])[:3]
    return ", ".join(k.replace("_", " ") for k, _ in top)


def pct(x: float) -> str:
    return f"{x * 100:.0f}%"


def ci(r: tuple[float, float]) -> str:
    return f"{r[0] * 100:.0f}–{r[1] * 100:.0f}%"


def run_tests() -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        cov = Path(tmp) / "cov.json"
        out = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--cov=app", f"--cov-report=json:{cov}"],
            capture_output=True,
            text=True,
            cwd=HERE.parent,
        )
        passed = re.search(r"(\d+) passed", out.stdout)
        failed = re.search(r"(\d+) failed", out.stdout)
        coverage = json.loads(cov.read_text())["totals"]["percent_covered"] if cov.exists() else None
    return {"passed": int(passed[1]) if passed else 0, "failed": int(failed[1]) if failed else 0, "coverage": coverage}


def table(runs: list[Run]) -> tuple[list[str], dict | None]:
    """One table for one dataset. Returns the lines and the best shipped configuration."""
    lines = [
        "| System | Input | Scored | Precision | Scams caught (95% CI) | False alarms (95% CI) | F1 | Injection caught | Median time | Cost / scan |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    best = None
    rules = next((r for r in runs if r.model == "rules"), None) or next(r for r in runs)
    h = score(rules.rows, "heuristics")
    hc, ht = injection(rules.rows, "heuristics")
    rule_ms = [r["heuristics_ms"] for r in rules.rows if r.get("heuristics_ms") is not None]
    rule_time = f"{statistics.median(rule_ms):.2f}ms" if rule_ms else "not measured"
    lines.append(
        f"| Rules only (no AI) | text | {h['n']}/{len(rules.rows)} | {pct(h['precision'])} | {pct(h['recall'])} ({ci(h['recall_ci'])}) | "
        f"{pct(h['fpr'])} ({ci(h['fpr_ci'])}) | {h['f1']:.2f} | {hc}/{ht} | {rule_time} | $0 |"
    )
    for system, label in (("textmodel", "Trained text model only"), ("offline", "Rules + text model (no AI)")):
        if rules.rows and rules.rows[0].get(system) is not None:
            m = score(rules.rows, system)
            c, t = injection(rules.rows, system)
            lines.append(
                f"| {label} | text | {m['n']}/{len(rules.rows)} | {pct(m['precision'])} | {pct(m['recall'])} ({ci(m['recall_ci'])}) | "
                f"{pct(m['fpr'])} ({ci(m['fpr_ci'])}) | {m['f1']:.2f} | {c}/{t} | <1ms | $0 |"
            )
    for run in sorted((r for r in runs if r.model != "rules"), key=lambda r: (r.model, r.mode)):
        done = [r for r in run.rows if r.get("latency_ms") is not None]
        lat = sorted(r["latency_ms"] for r in done)
        med = f"{statistics.median(lat) / 1000:.1f}s" if lat else "?"
        cost = statistics.fmean(r["cost_usd"] for r in done) if done else 0.0
        errors = sum(r.get("error") is not None for r in run.rows)
        for system, label in (("ai", "AI alone"), ("combined", "Shipped: AI + rules + text model")):
            rows = shipped(run.rows) if system == "combined" else run.rows
            m = score(rows, system)
            c, t = injection(rows, system)
            note = f" ({errors} AI errors{', scored by rules' if system == 'combined' else ', left out'})" if errors else ""
            lines.append(
                f"| {label}: {run.model} | {run.mode} | {m['n']}/{len(run.rows)}{note} | {pct(m['precision'])} | "
                f"{pct(m['recall'])} ({ci(m['recall_ci'])}) | {pct(m['fpr'])} ({ci(m['fpr_ci'])}) | {m['f1']:.2f} | "
                f"{c}/{t} | {med} | ${cost:.3f} |"
            )
            if system == "combined" and (best is None or m["f1"] > best["m"]["f1"]):
                best = {"run": run, "m": m, "inj": (c, t), "med": med, "cost": cost, "rules": h}
    return lines, best


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tests", action="store_true", help="run pytest for test count and coverage")
    args = ap.parse_args()

    runs = load_runs()
    if not runs:
        sys.exit("No eval reports yet. Run: uv run python -m evals.run_eval")

    lines = [
        "# Second Look: measured results",
        "",
        f"A message counts as flagged at score {THRESHOLD} or above (the 'likely scam' line). "
        "Ranges are 95% confidence intervals. Regenerate with `uv run python -m evals.summarize --tests`.",
    ]
    quotable: dict | None = None
    for dataset in sorted({r.dataset for r in runs}, key=lambda d: list(DATASETS).index(d) if d in DATASETS else 99):
        ds_runs = [r for r in runs if r.dataset == dataset]
        rows0 = ds_runs[0].rows
        n_scam = sum(r["label"] == "scam" for r in rows0)
        types = len({r["category"] for r in rows0 if r["label"] == "scam"})
        lines += [
            "",
            f"## {DATASETS.get(dataset, dataset)}",
            "",
            f"`evals/data/{dataset}.jsonl`: {len(rows0)} messages ({n_scam} scams across {types} categories, "
            f"{len(rows0) - n_scam} legitimate).",
            "",
        ]
        t, best = table(ds_runs)
        lines += t
        if best and quotable is None and not dataset.startswith("dev"):
            quotable = best | {"dataset": dataset, "n": len(rows0)}
    if quotable is None:  # only the dev set has AI runs so far
        for dataset in ("dev_blind", "dev"):
            ds_runs = [r for r in runs if r.dataset == dataset]
            if ds_runs:
                _, best = table(ds_runs)
                if best:
                    quotable = best | {"dataset": dataset, "n": len(ds_runs[0].rows)}

    facts = []
    if quotable:
        q, m, h = quotable, quotable["m"], quotable["rules"]
        where = f"on a {q['n']}-message {'blind test set' if q['dataset'] == 'test' else q['dataset'] + ' set'}"
        gained = gained_types(shipped(q["run"].rows))
        facts += [
            f"Best shipped configuration ({q['run'].model}, {q['run'].mode} input) {where}: caught {pct(m['recall'])} of scams "
            f"({m['tp']}/{m['scams']}) with {pct(m['fpr'])} false alarms ({m['fp']}/{m['legit']}); precision {pct(m['precision'])}, F1 {m['f1']:.2f}.",
            f"Adding the AI raised scam recall from {pct(h['recall'])} (rules only) to {pct(m['recall'])}"
            + (f"; most newly caught: {gained}." if gained else "."),
            f"Prompt-injection attacks hidden in messages: {q['inj'][0]}/{q['inj'][1]} still flagged.",
            f"Median end-to-end analysis time {q['med']} per message at ${q['cost']:.3f} per scan.",
        ]
        if q["dataset"].startswith("dev"):
            facts.append("These come from the development set. Run the held-out set before quoting them.")
    if args.tests:
        tr = run_tests()
        cov = f", {tr['coverage']:.0f}% line coverage" if tr["coverage"] is not None else ""
        fail = f" ({tr['failed']} failing)" if tr["failed"] else ""
        facts.append(f"{tr['passed']} automated backend tests{fail}{cov}; no network or paid API calls needed.")

    lines += ["", "## Numbers you can quote", ""] + [f"- {f}" for f in facts]
    lines += [
        "",
        "## Caveats",
        "",
        "- Synthetic sets compare systems against each other; real-world accuracy needs real traffic.",
        "- The confidence intervals show how much each number could move with a different sample of the same size.",
        "- Times are measured on the machine that ran the eval.",
        "- The text model was trained partly on dev_blind.jsonl, which was generated the same way as the test set. Shared writing style may flatter the text model on the test set; the public set is the stricter check for it.",
    ]
    out = HERE / "METRICS.md"
    out.write_text("\n".join(lines) + "\n")
    print(out.read_text())


if __name__ == "__main__":
    main()
