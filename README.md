# Risk-Weighted Policy-as-Code Security Gates in CI/CD Pipelines

**M.Sc. Thesis — Ashok Venkatesh — SRH University Leipzig — 2026**

This repository is the replication package for the thesis 
"Risk-Weighted Policy-as-Code Security Gates in CI/CD Pipelines."

## What is in this repository

| Folder | Contents |
|---|---|
| `gate/fixed/` | Fixed-threshold gate policy in OPA/Rego (Gate A — control) |
| `gate/risk_weighted/` | Risk-weighted gate policy in OPA/Rego (Gate B — treatment) |
| `corpus/` | CVEfixes extraction scripts and EPSS fetcher |
| `results/` | Experiment results CSV and statistical analysis |
| `.github/workflows/` | GitHub Actions pipeline running both gates |

## How to reproduce the experiment

1. Download CVEfixes v1.0.0 from https://zenodo.org/record/5565330
2. Run `corpus/extract_corpus.py` to extract Python commits
3. Run `corpus/fetch_epss.py` to fetch EPSS scores from FIRST.org
4. Run `corpus/run_experiment.py` to run both gates over the corpus
5. Run `results/statistical_test.py` to reproduce the statistical analysis

## Results

| Metric | Gate A Fixed | Gate B Risk-Weighted |
|---|---|---|
| Build-break rate | 47.2% | 19.9% |
| Break rate reduction | — | 57.9% |
| True-positive retention | 100% | 100% |
| Z-statistic | — | 7.18 |
| P-value | — | < 0.000001 |
| Operating point (θ) | — | 0.1 |

## Requirements

- Python 3.11+
- OPA 1.18.2+
- Trivy 0.69+
- pandas, requests, statsmodels, scipy
