# Eval datasets

Sets are split by whether their results were ever used to change the detector. Only the two test sets give numbers worth quoting.

| File | Messages | Source | Used for tuning? |
|---|---|---|---|
| `test.jsonl` | 160 (80 scam / 80 legit) | Synthetic, generated separately from the detector, without access to its code or any other set | No. Main test set. |
| `public.jsonl` | 200 (100 / 100) | Real SMS sampled from Mishra & Soni 2022 (seed 8, no overlap with `dev_public`) | No. Real-world check. |
| `dev_blind.jsonl` | 160 (80 / 80) | Written blind, like `test.jsonl` | Yes: its errors led to the "a scam needs an ask" prompt fix. |
| `dev_public.jsonl` | 200 (100 / 100) | Real SMS from the same public dataset (seed 7) | Yes: same prompt fix. |
| `dev.jsonl` | 67 (37 / 30) | Written while building the rules | Yes: the brand list was adjusted against it. |
| `train_us_a.jsonl`, `train_us_b.jsonl` | 400 (200 / 200) | Synthetic, generated the same way in two batches (money and accounts; people and jobs) | Training data for the text model only. Rows 70%+ similar to a test message are dropped at training time. |

Every line has `id`, `label` (`scam` or `legit`), `category`, `text`, and optionally `injection: true` for scams that also try to manipulate an AI checker. Rebuild both public samples with `uv run python -I evals/data/make_public.py` after downloading the source (see the script).

## Attribution

`public.jsonl` and `dev_public.jsonl` contain messages from: Sandhya Mishra and Devpriya Soni, "SMS Phishing Dataset for Machine Learning and Pattern Recognition", Mendeley Data, V1, 2022, doi:10.17632/f45bkkt8pr.1. Licensed under CC BY 4.0. Changes: kept "smishing" and "ham" only, removed duplicates and messages under 20 characters, fixed HTML entities and lost £ signs, and sampled 100 of each class per file.

The text model also trains on one copy of each of the ~57 templates in "Phishing validation emails dataset" (Miltchev, Rangelov & Genchev, Zenodo, 2024, record 13474746, CC BY 4.0), downloaded to `raw_zenodo/`. Its 2,000 rows contain only 100 distinct texts, so it is not used for evaluation.

Caveats for the public sets: the messages are older and mostly UK and India style (premium-rate numbers, prize draws), and the source labels are kept as published, including some marketing texts tagged as smishing.
