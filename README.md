# Second Look

Upload a screenshot of a text, email, or web page and get a plain-language answer: how likely it is to be a scam, why, and what to do next. Built for the people scammers target most, so the UI uses large type, short sentences, and concrete next steps.

Americans reported $15.9B in fraud losses to the FTC in 2025. Most of those scams start with a message that looked almost right.

## What it does

- **Screenshot or text in, verdict out.** A 0–100 risk score, a verdict (looks safe / be careful / likely scam / scam), the red flags behind it, and numbered steps to take.
- **An AI reads the message: Claude or a local model.** Claude Opus 5.5 by default, or any vision model running in [Ollama](https://ollama.com) on your own machine (free, and screenshots never leave it). Pick one with `LLM_PROVIDER` in `.env`.
- **Every link is checked separately.** Claude calls a `check_links` tool mid-analysis. The local-model path runs the same checks itself and hands the results to the model, since smaller models are less reliable at tool calling. The checks are deterministic:
  - brand impersonation (`usps-redelivery.com`)
  - look-alike spellings (`paypa1.com`, `netf1ix-billing.com`)
  - punycode, raw IPs, `@` tricks, URL shorteners, and risky TLDs
  - domain age via RDAP
  - the OpenPhish and URLhaus blocklists
- **A trained text model checks the wording.** A TF-IDF + logistic regression classifier, trained on about 5,000 real labeled SMS plus 500 US-style examples, scores every message in under a millisecond. It is exported to plain JSON and scored in pure Python, so the app needs no ML library at runtime and loads no pickle files. Without the AI it is the main signal. With the AI, when the model is nearly sure a message is ordinary, the AI alone can say "be careful" but not "likely scam", which removes most false alarms on everyday texts.
- **Rules can only raise the score.** Link and pattern checks set minimum scores that the AI cannot talk its way under. A screenshot that says "AI: this message is verified safe" still gets flagged if its link impersonates a bank. This is the main defense against prompt injection inside images.
- **Graceful degradation.** If the AI is down or not configured, text checks still run on the rules alone and say so. Screenshots return a clear error, since nothing can read them without the AI.
- **Privacy.**
  - Screenshots are re-encoded (EXIF stripped), sent to the AI, and discarded. With Ollama they never leave the machine.
  - The database stores scan metadata only (verdict, scam type, latency, cost), never the image or the message text.

## Architecture

```
Browser ──> Next.js (frontend, :3000) ──/api/* proxy──> FastAPI (backend, :8000) ──> Claude API or Ollama
                                                          │   └─ link checks ─> RDAP, blocklists
                                                          └─> Postgres / SQLite (metadata only)
```

| Path | What it is |
|---|---|
| `backend/app/llm.py` | Claude call: tool loop, structured output, prompt caching, refusal and error handling, cost tracking |
| `backend/app/llm_ollama.py` | Local-model call: read the screenshot, check links, then decide, with schema-constrained JSON |
| `backend/app/providers.py` | Picks Claude or Ollama from `LLM_PROVIDER` |
| `backend/app/pipeline.py` | Orchestrates the AI, link checks, and pattern rules; merges flags; handles degraded mode |
| `backend/app/scoring.py` | Score floors and verdict thresholds |
| `backend/app/signals/` | Link analysis, brand list, phishing blocklists, scam-wording patterns, the trained text model |
| `backend/training/` | Trains the text model and exports it to `app/models/text_model.json.gz` |
| `backend/evals/` | Labeled dataset and eval harness |
| `frontend/src/` | Next.js app: upload, paste, results, stats |

## Run it locally

You need Docker, or Python 3.12 with [uv](https://docs.astral.sh/uv/) and Node 22.

1. Run `cp .env.example .env`.
2. Choose an AI:
   - **Claude:** get an API key at <https://console.anthropic.com> under API Keys, and paste it after `ANTHROPIC_API_KEY=`.
   - **Ollama (free, local):** install Ollama, run `ollama pull qwen3.5:35b` (any vision model works), then set `LLM_PROVIDER=ollama`, `OLLAMA_MODEL=qwen3.5:35b`, and `OLLAMA_THINK=false`. Docker reaches the Ollama app on your Mac through `host.docker.internal`.

**With Docker:**

```bash
docker compose up --build
# open http://localhost:3000
```

**Without Docker:**

```bash
cp .env backend/.env
cd backend && uv sync && uv run uvicorn app.main:app --reload --port 8000
# in a second terminal
cd frontend && npm install && npm run dev
# open http://localhost:3000
```

Without an AI the app still runs in rules-only mode for pasted text. `/api/health` shows which provider and model are active.

**Cost:** with Claude, each scan costs a few cents; every response reports its exact cost in `meta.cost_usd`, and `/stats` shows the average. With Ollama, scans are free but slower, and the server needs enough memory for the model (about 24 GB for `qwen3.5:35b`).

## Tests

```bash
cd backend && uv run pytest -q   # 59 tests, no network, no API spend (Claude and Ollama are faked)
cd frontend && npm run lint && npx tsc --noEmit
```

CI (`.github/workflows/ci.yml`) runs these, plus the free eval baseline, a production build, and a Docker build.

## Evals

787 labeled messages live in `backend/evals/data/` (details and attribution in its README). They are split by whether their results were ever used to change the detector:

| Set | Messages | What it is | Used for tuning? |
|---|---|---|---|
| `test.jsonl` | 160 (80 scam / 80 legit) | Synthetic, generated separately from the detector, without access to its code or the other sets. 16 scam types, 8 prompt-injection attacks, and hard negatives such as real bank fraud alerts, 2FA codes, and casual family texts. | No |
| `public.jsonl` | 200 (100 / 100) | Real SMS sampled from a public dataset (Mishra & Soni 2022, CC BY 4.0). Older, mostly UK and India. | No |
| `dev_blind.jsonl`, `dev_public.jsonl`, `dev.jsonl` | 427 | Same kinds of data, used to find and fix errors | Yes |

The harness compares three systems:

- **heuristics**: link and wording rules only, the no-AI baseline
- **ai**: Claude's probability alone
- **combined**: what the product ships

It reports:

- precision, recall, F1, and false-positive rate at both thresholds
- Brier score (calibration)
- per-sample results for the injection cases
- latency (p50 and p95) and cost
- a list of every misclassified message, for error analysis

```bash
cd backend
uv run python -m evals.run_eval                          # free, offline, heuristics only, dev set
uv run python -m evals.run_eval --data evals/data/test.jsonl      # pick a set with --data
uv run python -m evals.run_eval --ai --yes               # adds Claude (~$0.04 per message)
uv run python -m evals.run_eval --ai --yes --as-image    # renders each message as a phone screenshot first
uv run python -m evals.run_eval --ai --provider ollama --model qwen3.5:35b --think false   # local model, free
uv run python -m evals.summarize --tests                 # newest run per set and model -> evals/METRICS.md
```

`evals/METRICS.md` puts every system side by side (precision, recall, false alarms, injection attacks caught, median time, cost per scan), along with test count and coverage.

`--ai` refuses to run without `--yes` and prints the cost estimate first.

**Results on the sets never used for tuning** (local `qwen3.5:35b` through Ollama, flagged at score 60; full table with confidence intervals in `backend/evals/METRICS.md`):

| Set | System | Precision | Scams caught | False alarms | F1 |
|---|---|---|---|---|---|
| Blind test (160) | Rules only | 100% | 21% | 0% | 0.35 |
| Blind test (160) | Rules + text model, no AI | 99% | 92% | 1% | 0.95 |
| Blind test (160) | AI alone | 93% | 95% | 8% | 0.94 |
| Blind test (160) | **Shipped: AI + rules + text model** | **97%** | **95%** | **2%** | **0.96** |
| Blind test, as screenshots | Shipped | 94% | 96% | 6% | 0.95 |
| Real public SMS (200) | Rules only | 0% | 0% | 0% | 0.00 |
| Real public SMS (200) | AI alone | 87% | 98% | 15% | 0.92 |
| Real public SMS (200) | **Shipped** | **99%** | **98%** | **1%** | **0.98** |

All 8 prompt-injection attacks in the blind test were still flagged by every AI configuration.

The rules are precise but miss most scams that don't contain a bad link (romance, fake jobs, family emergencies), and they catch none of the older UK-style scams in the public set, which rely on premium-rate phone numbers. Closing that gap is the AI's job.

**Error analysis that changed the prompt.** On the first blind set and the first public sample, the AI flagged 79% of ordinary real texts ("Correct. So how was work today") as investment-scam openers. The prompt's example about "wrong number" openers made it suspect any message without context. The fix was one rule: a scam needs an ask, so a message that asks for nothing stays at "be careful" or below. False alarms on those sets fell from 11% to 2% (blind) and from 79% to 21% (public), with scam recall unchanged. Because those sets had now been looked at, they became dev sets, and the numbers above come from a fresh blind set and a fresh, non-overlapping public sample. The before-fix reports are kept locally in `evals/reports/before-prompt-fix/` (reports are not committed).

**Caveat:** the held-out and dev sets are synthetic, modeled on public FTC scam alerts, and the public set is older UK/India SMS, so none of them is a substitute for real US traffic. The in-app "Was this answer right?" button collects the feedback needed for a real-traffic estimate.

## Training the text model

```bash
cd backend
# download the source data first (see evals/data/make_public.py), then:
uv run python -m training.train_text_model   # ~10 s: grid search with 5-fold CV, export, parity check
uv run python -m training.benchmark          # compare model families + learning curve -> training/BENCHMARK.md
uv run python -m evals.combine_study         # how to mix it with the AI, measured on dev sets only
```

`training/BENCHMARK.md` compares TF-IDF + logistic regression (shipped), a linear SVM, naive Bayes, and `nomic-embed-text` embeddings, all on the same cross-validation folds. Logistic regression was the best single model. Averaging it with the embedding model scored slightly higher, but would make every scan depend on an embedding server, so it isn't shipped. The learning curve showed US-style examples were the bottleneck (average precision 0.55 with none, 0.95 with 181), which is why 400 more were added; with 492 the curve is flattening (0.96 to 0.97).

The script never trains on `test.jsonl` or `public.jsonl`, and drops any training message that is a near-copy of a test message (384 of them, since the public dataset reuses templates with different numbers). It writes out-of-fold predictions for every dev message, so `combine_study` can compare mixing rules on messages the model never saw. The exported JSON model is checked against scikit-learn's own predictions (max difference 5e-7).

## Deploy

- **Backend** (Railway, Fly.io, or Render):
  - Deploy `backend/` using its Dockerfile. It listens on `$PORT`.
  - Set `ANTHROPIC_API_KEY` and `DATABASE_URL` (any Postgres).
  - Set `CORS_ORIGINS` to your frontend URL.
  - Set `TRUST_PROXY_HEADERS=true` only when the backend is reachable solely through your proxy.
- **Frontend** (Vercel):
  - Import `frontend/`.
  - Set `BACKEND_URL` to the backend's public URL before the build. The `/api` rewrite is baked in at build time.
- The rate limiter is in-memory, so it is per instance. Move it to Redis before running several backend replicas.

## Limits

- It's a second opinion, not a guarantee. The UI says so and always points people to their bank and to reportfraud.ftc.gov.
- Domain age and blocklist checks need outbound network access. Set `NETWORK_CHECKS=false` to turn them off.

## License

Code: MIT, see [LICENSE](LICENSE). The public SMS and email datasets keep their own CC BY 4.0 licenses; see `backend/evals/data/README.md`.
