# Text model benchmark

5-fold cross-validation over 5540 training messages (627 scams; 227 US-style). Each message is scored by a model that never saw it. Recall and false alarms at probability 0.6.

| Model | Avg precision (all) | Avg precision (US-style) | US recall | US false alarms | Fit + score time |
|---|---|---|---|---|---|
| TF-IDF + logistic regression (C=4) | 0.983 | 0.970 | 91% | 5% | 2s |
| TF-IDF + logistic regression (C=16, shipped) | 0.984 | 0.971 | 91% | 5% | 2s |
| TF-IDF + linear SVM (calibrated) | 0.964 | 0.903 | 93% | 15% | 2s |
| TF-IDF + complement naive Bayes | 0.945 | 0.933 | 89% | 35% | 2s |
| nomic-embed-text embeddings + logistic regression | 0.969 | 0.970 | 95% | 15% | 0s |
| Average of shipped TF-IDF model and nomic-embed-text | 0.987 | 0.980 | 91% | 5% | |

## Learning curve: US-style training examples

The shipped model, trained with all public SMS plus a fraction of the US-style messages, scored on held-out messages from the US-style dev sets.

| US-style examples in training | Avg precision (US-style) | US recall | US false alarms |
|---|---|---|---|
| 0 (0%) | 0.552 | 58% | 48% |
| 126 (25%) | 0.866 | 84% | 22% |
| 234 (50%) | 0.919 | 88% | 17% |
| 364 (75%) | 0.960 | 87% | 11% |
| 492 (100%) | 0.971 | 91% | 5% |
