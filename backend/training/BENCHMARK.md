# Text model benchmark

5-fold cross-validation over 5784 training messages (740 scams; 227 US-style). Each message is scored by a model that never saw it. Recall and false alarms at probability 0.6.

| Model | Avg precision (all) | Avg precision (US-style) | US recall | US false alarms | Fit + score time |
|---|---|---|---|---|---|
| TF-IDF + logistic regression (C=4) | 0.989 | 0.990 | 94% | 1% | 12s |
| TF-IDF + logistic regression (C=16) | 0.990 | 0.990 | 94% | 1% | 12s |
| TF-IDF + separate link/handle/code flags + logistic regression (shipped) | 0.988 | 0.992 | 94% | 2% | 10s |
| TF-IDF + linear SVM (calibrated) | 0.976 | 0.977 | 95% | 8% | 14s |
| TF-IDF + complement naive Bayes | 0.958 | 0.967 | 90% | 15% | 12s |
| nomic-embed-text embeddings + logistic regression | 0.964 | 0.978 | 94% | 10% | 0s |
| Average of shipped TF-IDF model and nomic-embed-text | 0.988 | 0.991 | 96% | 1% | |

## Learning curve: US-style training examples

The shipped model, trained with all public SMS plus a fraction of the US-style messages, scored on held-out messages from the US-style dev sets.

| US-style examples in training | Avg precision (US-style) | US recall | US false alarms |
|---|---|---|---|
| 0 (0%) | 0.559 | 59% | 48% |
| 185 (25%) | 0.940 | 89% | 11% |
| 354 (50%) | 0.973 | 91% | 5% |
| 540 (75%) | 0.989 | 96% | 5% |
| 720 (100%) | 0.990 | 94% | 1% |
