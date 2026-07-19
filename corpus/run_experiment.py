import pandas as pd
import subprocess
import json

# Reachable CWEs - your scoring model
REACHABLE_CWES = {"CWE-89", "CWE-79", "CWE-502", "CWE-22"}

def reachability_flag(cwe_id):
    return 1.0 if cwe_id in REACHABLE_CWES else 0.0

def composite_score(epss, cwe_id):
    return (epss * 0.6) + (reachability_flag(cwe_id) * 0.4)

def fixed_threshold_decision(cvss_score, threshold=7.0):
    return cvss_score >= threshold

def risk_weighted_decision(epss, cwe_id, threshold=0.4):
    return composite_score(epss, cwe_id) >= threshold

# Load corpus
corpus = pd.read_csv("corpus/python_corpus_with_epss.csv")
print(f"Running experiment on {len(corpus)} commits...")

results = []

for _, row in corpus.iterrows():
    cve_id = row['cve_id']
    cvss = float(row['cvss_score'])
    epss = float(row['epss_score'])
    cwe = str(row['cwe_id'])

    fixed_blocked = fixed_threshold_decision(cvss)
    risk_blocked = risk_weighted_decision(epss, cwe)
    score = composite_score(epss, cwe)

    results.append({
        'cve_id': cve_id,
        'commit_hash': row['commit_hash'],
        'cvss_score': cvss,
        'epss_score': epss,
        'cwe_id': cwe,
        'composite_score': round(score, 4),
        'fixed_gate_blocked': fixed_blocked,
        'risk_gate_blocked': risk_blocked,
    })

df = pd.DataFrame(results)

# ── METRICS ──────────────────────────────────────────────
total = len(df)
fixed_breaks = df['fixed_gate_blocked'].sum()
risk_breaks = df['risk_gate_blocked'].sum()

fixed_break_rate = fixed_breaks / total * 100
risk_break_rate = risk_breaks / total * 100
reduction = fixed_breaks - risk_breaks
reduction_pct = (reduction / fixed_breaks * 100) if fixed_breaks > 0 else 0

print(f"\n{'='*60}")
print(f"EXPERIMENT RESULTS — {total} Python commits")
print(f"{'='*60}")
print(f"\nTotal commits:                    {total}")
print(f"\nGate A (Fixed Threshold CVSS≥7):")
print(f"  Breaks:                         {fixed_breaks}")
print(f"  Break rate:                     {fixed_break_rate:.1f}%")
print(f"\nGate B (Risk-Weighted):")
print(f"  Breaks:                         {risk_breaks}")
print(f"  Break rate:                     {risk_break_rate:.1f}%")
print(f"\nComparison:")
print(f"  Break reduction:                {reduction} commits")
print(f"  Break rate reduction:           {reduction_pct:.1f}%")

# ── NOT-KNOWN-EXPLOITED BREAK RATE ───────────────────────
# Using EPSS < 0.1 as proxy for not-known-exploited
# (In full experiment this uses CISA KEV catalogue)
not_exploited = df[df['epss_score'] < 0.1]
fixed_non_kev = df[df['fixed_gate_blocked'] & (df['epss_score'] < 0.1)]
risk_non_kev = df[df['risk_gate_blocked'] & (df['epss_score'] < 0.1)]

fixed_fp_rate = len(fixed_non_kev) / fixed_breaks * 100 if fixed_breaks > 0 else 0
risk_fp_rate = len(risk_non_kev) / risk_breaks * 100 if risk_breaks > 0 else 0

print(f"\nNot-Known-Exploited Break Rate (EPSS < 0.1 proxy):")
print(f"  Gate A:                         {fixed_fp_rate:.1f}%")
print(f"  Gate B:                         {risk_fp_rate:.1f}%")

# ── TRUE POSITIVE RETENTION ──────────────────────────────
high_epss = df[df['epss_score'] >= 0.1]
fixed_tp = df[df['fixed_gate_blocked'] & (df['epss_score'] >= 0.1)]
risk_tp = df[df['risk_gate_blocked'] & (df['epss_score'] >= 0.1)]

fixed_tp_rate = len(fixed_tp) / len(high_epss) * 100 if len(high_epss) > 0 else 0
risk_tp_rate = len(risk_tp) / len(high_epss) * 100 if len(high_epss) > 0 else 0

print(f"\nTrue-Positive Retention (EPSS >= 0.1):")
print(f"  High-EPSS findings in corpus:   {len(high_epss)}")
print(f"  Gate A retained:                {fixed_tp_rate:.1f}%")
print(f"  Gate B retained:                {risk_tp_rate:.1f}%")

# Save results
df.to_csv("results/experiment_results.csv", index=False)
print(f"\nFull results saved to results/experiment_results.csv")
