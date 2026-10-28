"""Builds dev_public.jsonl and public.jsonl: two non-overlapping fixed random samples of real messages from
Mishra & Soni (2022), "SMS Phishing Dataset for Machine Learning and Pattern Recognition",
Mendeley Data, v1, doi:10.17632/f45bkkt8pr.1, licensed CC BY 4.0.

  1. Download Dataset_5971.zip from https://data.mendeley.com/datasets/f45bkkt8pr into evals/data/raw_mendeley/
  2. unzip it there, then run:  uv run python evals/data/make_public.py

Labels are kept exactly as published: "smishing" -> scam, "ham" -> legit. Marketing "spam" is left
out because it is neither a scam nor a message people need protecting from. No message is relabeled,
so known label noise in the source (some marketing texts are tagged smishing) stays in the sample.
"""

import csv
import html
import json
import random
from pathlib import Path

HERE = Path(__file__).parent
SRC = HERE / "raw_mendeley" / "Dataset_5971.csv"
PER_CLASS = 100
SEED = 7

rows = list(csv.DictReader(SRC.open(encoding="utf-8", errors="replace")))
seen: set[str] = set()
pools: dict[str, list[dict]] = {"scam": [], "legit": []}
for r in rows:
    label = {"smishing": "scam", "ham": "legit"}.get(r["LABEL"].strip().lower())
    text = html.unescape(" ".join(r["TEXT"].split())).replace("\ufffd", "£")  # the source lost its £ signs to bad encoding
    key = text.lower()
    if not label or len(text) < 20 or key in seen:
        continue
    seen.add(key)
    pools[label].append({"label": label, "category": f"public_{'smishing' if label == 'scam' else 'ham'}", "text": text})

rng = random.Random(SEED)
dev = rng.sample(pools["scam"], PER_CLASS) + rng.sample(pools["legit"], PER_CLASS)
rng.shuffle(dev)
# The test sample comes only from messages not in the dev sample, so the two never overlap.
used = {r["text"] for r in dev}
rest = {k: [r for r in v if r["text"] not in used] for k, v in pools.items()}
rng = random.Random(SEED + 1)
test = rng.sample(rest["scam"], PER_CLASS) + rng.sample(rest["legit"], PER_CLASS)
rng.shuffle(test)
for name, sample, prefix in (("dev_public", dev, "p"), ("public", test, "q")):
    out = HERE / f"{name}.jsonl"
    out.write_text(
        "".join(json.dumps({"id": f"{prefix}{i:03d}", **r}, ensure_ascii=False) + "\n" for i, r in enumerate(sample, 1))
    )
    print(f"wrote {len(sample)} messages to {out.name}")
print(f"pool after de-dup: {len(pools['scam'])} scam, {len(pools['legit'])} legit")
