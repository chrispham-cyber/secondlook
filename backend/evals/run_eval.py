"""Second Look eval harness.

Compares three systems on a labeled message set:
  heuristics  - link checks + keyword patterns only (no AI; free)
  textmodel   - the trained text classifier alone
  offline     - what the app answers without the AI: rules + text model
  ai          - Claude's scam_probability alone
  combined    - what the product ships: AI score with signal floors

Usage (from backend/):
  uv run python -m evals.run_eval                       # heuristics only, free, offline
  uv run python -m evals.run_eval --ai --provider ollama                  # local model, free
  uv run python -m evals.run_eval --ai --provider ollama --model qwen3.5:35b --as-image
  uv run python -m evals.run_eval --ai --yes            # + Claude (costs money; see estimate)
  uv run python -m evals.run_eval --ai --yes --as-image # send each message as a rendered screenshot
  uv run python -m evals.run_eval --ai --yes --limit 10 --network

Datasets (evals/data/, see its README):
  test.jsonl        written blind to the detector, never looked at while tuning: quote these
  public.jsonl      real messages from a public dataset, never looked at while tuning
  dev*.jsonl        sets whose errors were used to improve the rules or the prompt

Writes evals/reports/<time>__<dataset>__<model>__<mode>.md (summary + error analysis) and .jsonl (per-sample scores).
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import statistics
import sys
import textwrap
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

import httpx
from PIL import Image, ImageDraw, ImageFont

from app.config import Settings
from app.images import prepare_image
from app.llm import LLMUnavailable
from app.pipeline import LinkAnalyzer
from app.providers import make_analyzer, model_label
from app.schemas import LinkReport
from app.scoring import combine
from app.signals.blocklist import Blocklist
from app.signals.links import extract_urls, normalize_url
from app.signals.patterns import find_patterns
from app.signals.textmodel import load_default as load_text_model

HERE = Path(__file__).parent
EST_COST_PER_SAMPLE = 0.04  # USD, Opus 5.5 at medium effort; the report prints the measured number


@dataclass
class Row:
    id: str
    label: str
    category: str
    injection: bool
    text: str
    heuristics: int = 0
    heuristics_ms: float | None = None
    textmodel: int | None = None
    offline: int | None = None
    ai: int | None = None
    combined: int | None = None
    scam_type: str | None = None
    headline: str | None = None
    latency_ms: int | None = None
    cost_usd: float = 0.0
    error: str | None = None
    link_checks: list[str] = field(default_factory=list)


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def render_screenshot(text: str) -> tuple[str, str]:
    """Draws the message as a phone-style chat bubble so the vision path gets exercised."""
    font = ImageFont.load_default(size=30)
    lines = []
    for para in text.split("\n"):
        lines += textwrap.wrap(para, 34) or [""]
    w, line_h = 720, 40
    h = 220 + line_h * len(lines)
    img = Image.new("RGB", (w, h), "#f2f2f7")
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 110], fill="#ffffff")
    # Neutral header on purpose: an earlier version drew a 555 number, which the model rightly called fake,
    # so every legitimate screenshot looked like a scam. The image must carry the same evidence as the text.
    d.text((w // 2 - 95, 40), "Text Message", fill="#111111", font=font)
    d.rounded_rectangle([30, 140, w - 60, 160 + line_h * len(lines)], radius=28, fill="#e5e5ea")
    for i, line in enumerate(lines):
        d.text((55, 150 + i * line_h), line, fill="#111111", font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return prepare_image(buf.getvalue(), 20_000_000)


def eval_settings(args: argparse.Namespace) -> Settings:
    overrides: dict = {"network_checks": args.network}
    if args.provider:
        overrides["llm_provider"] = args.provider
    provider = args.provider or Settings().llm_provider
    if args.model:
        overrides["ollama_model" if provider == "ollama" else "anthropic_model"] = args.model
    if args.think:
        overrides["ollama_think"] = args.think == "true"
    return Settings(**overrides)


def metrics(rows: list[Row], system: str, threshold: int) -> dict:
    scored = [r for r in rows if getattr(r, system) is not None]
    tp = sum(1 for r in scored if r.label == "scam" and getattr(r, system) >= threshold)
    fn = sum(1 for r in scored if r.label == "scam" and getattr(r, system) < threshold)
    fp = sum(1 for r in scored if r.label == "legit" and getattr(r, system) >= threshold)
    tn = sum(1 for r in scored if r.label == "legit" and getattr(r, system) < threshold)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    brier = statistics.fmean(((getattr(r, system) / 100) - (r.label == "scam")) ** 2 for r in scored) if scored else 0.0
    return {
        "n": len(scored),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "accuracy": (tp + tn) / len(scored) if scored else 0.0,
        "brier": brier,
    }


async def run(args: argparse.Namespace) -> Path:
    settings = eval_settings(args)
    samples = load(Path(args.data))[: args.limit or None]
    async with httpx.AsyncClient() as http:
        blocklist = Blocklist()
        if args.network:
            await blocklist.refresh(http)
        linker = LinkAnalyzer(settings, http, blocklist)
        analyzer = make_analyzer(settings) if args.ai else None
        sem = asyncio.Semaphore(args.concurrency)
        text_model = load_text_model()

        async def one(s: dict) -> Row:
            row = Row(id=s["id"], label=s["label"], category=s["category"], injection=s.get("injection", False), text=s["text"])
            cache: dict[str, LinkReport] = {}

            async def check(urls: list[str]) -> list[LinkReport]:
                out = []
                for raw in urls:
                    url = normalize_url(raw)
                    if not url:
                        continue
                    if url not in cache:
                        cache[url] = await linker.analyze(url)
                    out.append(cache[url])
                return out

            # Heuristic baseline sees only the raw text (what a non-AI scanner could read).
            t_rules = time.perf_counter()
            links = await check(extract_urls(s["text"]))
            patterns = find_patterns(s["text"])
            row.heuristics, _ = combine(None, links, patterns)
            row.heuristics_ms = (time.perf_counter() - t_rules) * 1000
            # What the app answers without the AI: rules plus the trained text model.
            if text_model:
                row.textmodel = text_model.score(s["text"])
                row.offline, _ = combine(None, links, patterns, row.textmodel)

            if analyzer:
                async with sem:
                    t0 = time.perf_counter()
                    try:
                        if args.as_image:
                            result = await analyzer.analyze(None, render_screenshot(s["text"]), check)
                        else:
                            result = await analyzer.analyze(s["text"], None, check)
                        row.latency_ms = int((time.perf_counter() - t0) * 1000)
                        row.ai = result.analysis.scam_probability
                        row.cost_usd = result.cost_usd
                        row.scam_type = result.analysis.scam_type
                        row.headline = result.analysis.headline
                        extra = await check(result.analysis.urls + extract_urls(result.analysis.extracted_text))
                        known = extra if args.as_image else links + extra
                        all_links = list({r.url: r for r in known}.values())
                        # A screenshot's text is only known through the AI's reading of it.
                        seen_text = result.analysis.extracted_text if args.as_image else s["text"]
                        tm = text_model.score(seen_text) if text_model and seen_text.strip() else None
                        row.combined, _ = combine(row.ai, all_links, find_patterns(seen_text), tm)
                    except LLMUnavailable as exc:
                        row.error = str(exc)
            row.link_checks = sorted({c.name for r in cache.values() for c in r.checks})
            print(
                f"  {row.id:4} {row.label:5} heur={row.heuristics:3} ai={row.ai!s:>4} comb={row.combined!s:>4} {row.error or ''}",
                file=sys.stderr,
            )
            return row

        rows = await asyncio.gather(*(one(s) for s in samples))

    return write_report(rows, args)


def write_report(rows: list[Row], args: argparse.Namespace) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dataset = Path(args.data).stem
    model = model_label(eval_settings(args)) if args.ai else "rules"
    out_dir = HERE / "reports"
    out_dir.mkdir(exist_ok=True)
    systems = ["heuristics"] + (["textmodel", "offline"] if rows and rows[0].textmodel is not None else [])
    systems += ["ai", "combined"] if args.ai else []
    mode = "screenshot" if args.as_image else "text"

    lines = [
        f"# Second Look eval: {stamp}",
        "",
        f"- Dataset: {dataset}",
        f"- Samples: {len(rows)} ({sum(r.label == 'scam' for r in rows)} scam / {sum(r.label == 'legit' for r in rows)} legit)",
        f"- Input mode: {mode}; network checks: {'on' if args.network else 'off'}",
        f"- Model: {model_label(eval_settings(args)) if args.ai else 'n/a'}",
        "",
        "Scam = score >= threshold. 60 is the 'likely scam' line; 25 is the 'suspicious' line.",
        "",
        "| System | Threshold | Precision | Recall | F1 | False-positive rate | Brier |",
        "|---|---|---|---|---|---|---|",
    ]
    summary = {}
    for system in systems:
        for t in (60, 25):
            m = metrics(rows, system, t)
            summary[f"{system}@{t}"] = m
            lines.append(
                f"| {system} | {t} | {m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} | {m['fpr']:.2f} | {m['brier']:.3f} |"
            )

    inj = [r for r in rows if r.injection]
    if inj:
        lines += ["", "## Prompt-injection samples", "", "| Sample | Heuristics | AI | Combined |", "|---|---|---|---|"]
        lines += [f"| {r.id} | {r.heuristics} | {r.ai} | {r.combined} |" for r in inj]

    if args.ai:
        done = [r for r in rows if r.latency_ms is not None]
        if done:
            lat = sorted(r.latency_ms for r in done)
            p95 = lat[min(len(lat) - 1, int(0.95 * len(lat)))]
            total = sum(r.cost_usd for r in done)
            lines += [
                "",
                "## Cost and latency",
                "",
                f"- Total cost: ${total:.3f} (${total / len(done):.4f} per message)",
                f"- Latency p50 {statistics.median(lat) / 1000:.1f}s, p95 {p95 / 1000:.1f}s",
                f"- Errors: {sum(r.error is not None for r in rows)}",
            ]

    # Error analysis: the rows a reviewer should actually read.
    final = "combined" if args.ai else "heuristics"
    misses = [r for r in rows if getattr(r, final) is not None and (r.label == "scam") != (getattr(r, final) >= 60)]
    lines += ["", f"## Misclassified by `{final}` at 60 ({len(misses)})", ""]
    for r in misses:
        lines.append(
            f"- **{r.id}** ({r.label}, {r.category}) score={getattr(r, final)} ai={r.ai} heur={r.heuristics} "
            f"checks={r.link_checks}: {r.text[:140]}"
        )

    # <time>__<dataset>__<model>__<mode>; evals/summarize.py reads this name back.
    base = "__".join([stamp, dataset, model.replace("/", "_").replace(":", "-"), mode])
    report = out_dir / f"{base}.md"
    report.write_text("\n".join(lines) + "\n")
    (out_dir / f"{base}.jsonl").write_text("\n".join(json.dumps(asdict(r)) for r in rows) + "\n")
    meta = {"dataset": dataset, "model": model, "mode": mode, "network": args.network, "n": len(rows)}
    (out_dir / f"{base}.summary.json").write_text(json.dumps({"meta": meta} | summary, indent=2))
    return report


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default=str(HERE / "data" / "dev.jsonl"), help="a file in evals/data/, e.g. test.jsonl")
    p.add_argument("--ai", action="store_true", help="also run Claude (costs money)")
    p.add_argument("--yes", action="store_true", help="confirm API spend for --ai with Claude")
    p.add_argument("--provider", choices=["anthropic", "ollama"], help="override LLM_PROVIDER")
    p.add_argument("--model", help="override the model for the chosen provider")
    p.add_argument("--think", choices=["true", "false"], help="Ollama only: turn model thinking on or off")
    p.add_argument("--as-image", action="store_true", help="send messages as rendered screenshots")
    p.add_argument("--network", action="store_true", help="enable RDAP domain-age and live blocklists")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--concurrency", type=int, default=0, help="parallel AI calls (default 4 for Claude, 1 for Ollama)")
    args = p.parse_args()

    n = len(load(Path(args.data))[: args.limit or None])
    if not args.concurrency:
        args.concurrency = 1 if eval_settings(args).llm_provider == "ollama" else 4
    if args.ai and eval_settings(args).llm_provider == "anthropic" and not args.yes:
        print(f"--ai will call Claude {n} times, roughly ${n * EST_COST_PER_SAMPLE:.2f}. Re-run with --yes to proceed.")
        sys.exit(1)
    report = asyncio.run(run(args))
    print(report.read_text())
    print(f"Report written to {report}")


if __name__ == "__main__":
    main()
