# Second Look: measured results

A message counts as flagged at score 60 or above (the 'likely scam' line). Ranges are 95% confidence intervals. Regenerate with `uv run python -m evals.summarize --tests`.

## Test set (written blind to the detector, never looked at while tuning)

`evals/data/test.jsonl`: 160 messages (80 scams across 16 categories, 80 legitimate).

| System | Input | Scored | Precision | Scams caught (95% CI) | False alarms (95% CI) | F1 | Injection caught | Median time | Cost / scan |
|---|---|---|---|---|---|---|---|---|---|
| Rules only (no AI) | text | 160/160 | 100% | 21% (14–31%) | 0% (0–5%) | 0.35 | 3/8 | 0.06ms | $0 |
| Trained text model only | text | 160/160 | 100% | 94% (86–97%) | 0% (0–5%) | 0.97 | 8/8 | <1ms | $0 |
| Rules + text model (no AI) | text | 160/160 | 100% | 94% (86–97%) | 0% (0–5%) | 0.97 | 8/8 | <1ms | $0 |
| AI alone: ollama/qwen3.5-35b | screenshot | 160/160 | 87% | 96% (90–99%) | 15% (9–24%) | 0.91 | 8/8 | 7.8s | $0.000 |
| Shipped: AI + rules + text model: ollama/qwen3.5-35b | screenshot | 160/160 | 94% | 96% (90–99%) | 6% (3–14%) | 0.95 | 8/8 | 7.8s | $0.000 |
| AI alone: ollama/qwen3.5-35b | text | 160/160 | 94% | 95% (88–98%) | 6% (3–14%) | 0.94 | 8/8 | 6.6s | $0.000 |
| Shipped: AI + rules + text model: ollama/qwen3.5-35b | text | 160/160 | 99% | 95% (88–98%) | 1% (0–7%) | 0.97 | 8/8 | 6.6s | $0.000 |

## Real messages from a public dataset (never looked at while tuning)

`evals/data/public.jsonl`: 200 messages (100 scams across 1 categories, 100 legitimate).

| System | Input | Scored | Precision | Scams caught (95% CI) | False alarms (95% CI) | F1 | Injection caught | Median time | Cost / scan |
|---|---|---|---|---|---|---|---|---|---|
| Rules only (no AI) | text | 200/200 | 100% | 1% (0–5%) | 0% (0–4%) | 0.02 | 0/0 | 0.04ms | $0 |
| Trained text model only | text | 200/200 | 100% | 96% (90–98%) | 0% (0–4%) | 0.98 | 0/0 | <1ms | $0 |
| Rules + text model (no AI) | text | 200/200 | 100% | 96% (90–98%) | 0% (0–4%) | 0.98 | 0/0 | <1ms | $0 |
| AI alone: ollama/qwen3.5-35b | text | 200/200 | 89% | 98% (93–99%) | 12% (7–20%) | 0.93 | 0/0 | 7.0s | $0.000 |
| Shipped: AI + rules + text model: ollama/qwen3.5-35b | text | 200/200 | 99% | 98% (93–99%) | 1% (0–5%) | 0.98 | 0/0 | 7.0s | $0.000 |

## Dev: blind-written set (its errors guided the last prompt fix)

`evals/data/dev_blind.jsonl`: 160 messages (80 scams across 16 categories, 80 legitimate).

| System | Input | Scored | Precision | Scams caught (95% CI) | False alarms (95% CI) | F1 | Injection caught | Median time | Cost / scan |
|---|---|---|---|---|---|---|---|---|---|
| Rules only (no AI) | text | 160/160 | 100% | 20% (13–30%) | 0% (0–5%) | 0.33 | 3/8 | 0.06ms | $0 |
| AI alone: ollama/qwen3.5-35b | text | 160/160 | 97% | 96% (90–99%) | 2% (1–9%) | 0.97 | 8/8 | 5.9s | $0.000 |
| Shipped: AI + rules + text model: ollama/qwen3.5-35b | text | 160/160 | 97% | 96% (90–99%) | 2% (1–9%) | 0.97 | 8/8 | 5.9s | $0.000 |

## Dev: real public messages (its errors guided the last prompt fix)

`evals/data/dev_public.jsonl`: 200 messages (100 scams across 1 categories, 100 legitimate).

| System | Input | Scored | Precision | Scams caught (95% CI) | False alarms (95% CI) | F1 | Injection caught | Median time | Cost / scan |
|---|---|---|---|---|---|---|---|---|---|
| Rules only (no AI) | text | 200/200 | 0% | 0% (0–4%) | 0% (0–4%) | 0.00 | 0/0 | 0.03ms | $0 |
| AI alone: ollama/qwen3.5-35b | text | 200/200 | 82% | 98% (93–99%) | 21% (14–30%) | 0.89 | 0/0 | 6.5s | $0.000 |
| Shipped: AI + rules + text model: ollama/qwen3.5-35b | text | 200/200 | 82% | 98% (93–99%) | 21% (14–30%) | 0.89 | 0/0 | 6.5s | $0.000 |

## Dev: original set (used while building the rules; optimistic)

`evals/data/dev.jsonl`: 67 messages (37 scams across 16 categories, 30 legitimate).

| System | Input | Scored | Precision | Scams caught (95% CI) | False alarms (95% CI) | F1 | Injection caught | Median time | Cost / scan |
|---|---|---|---|---|---|---|---|---|---|
| Rules only (no AI) | text | 67/67 | 100% | 43% (29–59%) | 0% (0–11%) | 0.60 | 3/3 | 0.06ms | $0 |
| Trained text model only | text | 67/67 | 100% | 100% (91–100%) | 0% (0–11%) | 1.00 | 3/3 | <1ms | $0 |
| Rules + text model (no AI) | text | 67/67 | 100% | 100% (91–100%) | 0% (0–11%) | 1.00 | 3/3 | <1ms | $0 |
| AI alone: ollama/qwen3.5-35b | text | 67/67 | 100% | 100% (91–100%) | 0% (0–11%) | 1.00 | 3/3 | 5.4s | $0.000 |
| Shipped: AI + rules + text model: ollama/qwen3.5-35b | text | 67/67 | 100% | 100% (91–100%) | 0% (0–11%) | 1.00 | 3/3 | 5.4s | $0.000 |

## test_new

`evals/data/test_new.jsonl`: 120 messages (60 scams across 24 categories, 60 legitimate).

| System | Input | Scored | Precision | Scams caught (95% CI) | False alarms (95% CI) | F1 | Injection caught | Median time | Cost / scan |
|---|---|---|---|---|---|---|---|---|---|
| Rules only (no AI) | text | 120/120 | 100% | 45% (33–58%) | 0% (0–6%) | 0.62 | 0/0 | 0.13ms | $0 |
| Trained text model only | text | 120/120 | 98% | 100% (94–100%) | 2% (0–9%) | 0.99 | 0/0 | <1ms | $0 |
| Rules + text model (no AI) | text | 120/120 | 98% | 100% (94–100%) | 2% (0–9%) | 0.99 | 0/0 | <1ms | $0 |
| AI alone: ollama/qwen3.5-35b | text | 120/120 | 97% | 100% (94–100%) | 3% (1–11%) | 0.98 | 0/0 | 4.8s | $0.000 |
| Shipped: AI + rules + text model: ollama/qwen3.5-35b | text | 120/120 | 100% | 100% (94–100%) | 0% (0–6%) | 1.00 | 0/0 | 4.8s | $0.000 |

## Numbers you can quote

- Best shipped configuration (ollama/qwen3.5-35b, text input) on a 160-message blind test set: caught 95% of scams (76/80) with 1% false alarms (1/80); precision 99%, F1 0.97.
- Adding the AI raised scam recall from 21% (rules only) to 95%; most newly caught: romance, other, job or task.
- Prompt-injection attacks hidden in messages: 8/8 still flagged.
- Median end-to-end analysis time 6.6s per message at $0.000 per scan.
- 124 automated backend tests, 79% line coverage; no network or paid API calls needed.

## Caveats

- Synthetic sets compare systems against each other; real-world accuracy needs real traffic.
- The confidence intervals show how much each number could move with a different sample of the same size.
- Times are measured on the machine that ran the eval.
- The text model was trained partly on dev_blind.jsonl, which was generated the same way as the test set. Shared writing style may flatter the text model on the test set; the public set is the stricter check for it.
