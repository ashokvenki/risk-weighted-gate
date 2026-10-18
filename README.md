# Risk-Weighted Policy-as-Code Security Gates in CI/CD Pipelines

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![OPA](https://img.shields.io/badge/OPA-1.18.2-blue?logo=openpolicyagent)
![Trivy](https://img.shields.io/badge/Trivy-0.69-blue?logo=aqua)
![Python](https://img.shields.io/badge/Python-3.11+-green?logo=python)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-passing-brightgreen?logo=githubactions)

 — Ashok Venkatesh — SRH University of Applied Sciences Leipzig — 2026  

---

## Overview

Most CI/CD security gates break the build on any vulnerability with CVSS ≥ 7.0. This treats a vulnerability with a 0.1% real-world exploitation probability the same as one with a 65% probability — generating noise that developers learn to ignore.

This repository implements and evaluates a **risk-weighted gate** that scores each finding by:

```
S(f) = (EPSS × 0.6) + (CWE_reachability × 0.4)
```

The gate breaks the build only if `S(f) ≥ θ`, where θ is calibrated through sensitivity analysis.

The experiment is run over **307 CVE-labelled Python commits** from CVEfixes v1.0.0, with both gates evaluated on identical Trivy scanner output.

---

## Key Results

| Metric | Gate A (CVSS ≥ 7.0) | Gate B (Risk-Weighted) |
|---|---|---|
| Build-break rate | 47.2% | **19.9%** |
| Break rate reduction | — | **57.9%** |
| True-positive retention | 100% | **100%** |
| NKE break rate | 97.2% | 93.4% |
| Z-statistic | — | **7.18** |
| P-value | — | **< 0.000001** |
| Safe operating point (θ) | — | **0.1** |

> **57.9% fewer unnecessary build breaks with zero loss of high-risk findings.**  
> Result is statistically significant at p < 0.000001.

---

## Repository Structure

```
risk-weighted-gate/
│
├── gate/
│   ├── fixed/
│   │   └── fixed_threshold.rego      # Gate A — CVSS ≥ 7.0 (control)
│   └── risk_weighted/
│       └── risk_weighted.rego        # Gate B — composite scoring (treatment)
│
├── corpus/
│   ├── extract_corpus.py             # Extract Python commits from CVEfixes SQLite
│   ├── fetch_epss.py                 # Fetch EPSS scores from FIRST.org API
│   ├── run_experiment.py             # Run both gates over the full corpus
│   └── sensitivity_analysis.py       # Threshold sweep θ = 0.1 to 0.5
│
├── results/
│   ├── corpus.csv                    # 307 commits with CVE, CVSS, EPSS, CWE
│   ├── experiment_results.csv        # Gate A and Gate B decisions per commit
│   └── statistical_test.py          # Two-proportion z-test
│
└── .github/workflows/
    └── security-gate.yml             # GitHub Actions pipeline
```

---

## How It Works

### Gate A — Fixed Threshold (Control)
```
if CVSS ≥ 7.0 → break build
```
The industry default. No context. No exploitability consideration.

### Gate B — Risk-Weighted (Treatment)
```
S(f) = (EPSS × 0.6) + (CWE_reachability × 0.4)
if S(f) ≥ 0.1 → break build
```

**EPSS** (weight 0.6) — probability of real-world exploitation within 30 days, from FIRST.org.

**CWE reachability proxy** (weight 0.4) — structural classification of whether the vulnerability requires an exposed entry point:

| CWE | Type | Reachable |
|---|---|---|
| CWE-89 | SQL Injection | ✓ |
| CWE-79 | Cross-site Scripting | ✓ |
| CWE-502 | Deserialization | ✓ |
| CWE-22 | Path Traversal | ✓ |
| All others | — | ✗ |

---

## Reproducing the Experiment

### Prerequisites
```bash
pip install pandas requests statsmodels scipy
```
Install [OPA 1.18.2](https://www.openpolicyagent.org/docs/latest/#running-opa) and [Trivy 0.69](https://aquasecurity.github.io/trivy/).

### Steps

**1. Download CVEfixes v1.0.0**
```bash
# Download from Zenodo
wget https://zenodo.org/records/7029359/files/CVEfixes.db
```

**2. Extract the Python corpus**
```bash
python corpus/extract_corpus.py --db CVEfixes.db --output corpus/corpus.csv
```

**3. Fetch EPSS scores**
```bash
python corpus/fetch_epss.py --input corpus/corpus.csv --output corpus/corpus_epss.csv
```

**4. Run the experiment**
```bash
python corpus/run_experiment.py --input corpus/corpus_epss.csv --threshold 0.1
```

**5. Run the statistical test**
```bash
python results/statistical_test.py
```

**6. Run the sensitivity analysis**
```bash
python corpus/sensitivity_analysis.py
```

---

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/security-gate.yml`) runs both gates on every push to `main`. The pipeline:

1. Checks out the repository
2. Sets up Python environment
3. Installs Trivy and OPA
4. Runs Trivy vulnerability scan → produces JSON output
5. Evaluates both gate policies against the same JSON input
6. Reports gate decisions

---

## Sensitivity Analysis

| θ | Gate B Breaks | Break Rate | TP Retention | Safe? |
|---|---|---|---|---|
| 0.10 | 61 | 19.9% | 100% | ✅ |
| 0.15 | 61 | 19.9% | 100% | ✅ |
| 0.20 | 60 | 19.5% | 75% | ❌ |
| 0.25 | 60 | 19.5% | 75% | ❌ |
| 0.30 | 60 | 19.5% | 75% | ❌ |
| 0.40 | 59 | 19.2% | 50% | ❌ |
| 0.50 | 2 | 0.7% | 50% | ❌ |

**Operating point: θ = 0.1** — the highest threshold that maintains ≥ 90% true-positive retention.

---

## Research Context

- **Dataset:** [CVEfixes v1.0.0](https://zenodo.org/records/7029359) — 307 Python commits, 275 CVEs
- **Scanner:** [Trivy 0.69](https://aquasecurity.github.io/trivy/) — SCA on requirements.txt
- **Gate engine:** [Open Policy Agent 1.18.2](https://www.openpolicyagent.org/) — Rego v1 policies
- **EPSS:** [FIRST.org API](https://www.first.org/epss/api) — daily updated exploitation scores
- **Statistical test:** Two-proportion z-test, α = 0.05

---

## Citation

If you use this replication package in your research, please cite:

```bibtex
@{venkatesh2026riskweighted,
  author    = {Venkatesh, Ashok},
  title     = {Risk-Weighted Policy-as-Code Security Gates in CI/CD Pipelines},
  school    = {SRH University of Applied Sciences Leipzig},
  year      = {2026},
  url       = {https://github.com/ashokvenki/risk-weighted-gate}
}
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*M.Sc. Computer Science (Cyber Security) — SRH University of Applied Sciences Leipzig — 2026*
