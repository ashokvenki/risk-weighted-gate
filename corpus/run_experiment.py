import pandas as pd
import json

REACHABLE_CWES = {"CWE-89", "CWE-79", "CWE-502", "CWE-22"}

def reachability_flag(cwe_id):
    return 1.0 if cwe_id in REACHABLE_CWES else 0.0

def composite_score(epss, cwe_id):
    return (epss * 0.6) + (reachability_flag(cwe_id) * 0.4)

def fixed_threshold_decision(cvss_score, threshold=7.0):
    return cvss_score >= threshold

def risk_weighted_decision(epss, cwe_id, threshold=0.1):
    return composite_score(epss, cwe_id) >= threshold

corpus = pd.read_csv("corpus/python_corpus_with_epss.csv")
print(f"Running experiment on {len(corpus)} commits...")

results = []
for _, row in corpus.iterrows():
    cve_id = row['cve_id']
    cvss = float(row['cvss_score'])
    epss = float(row['epss_score'])
    cwe = str(row['cwe_id'])
    score = composite_score(epss, cwe)

    results.append({
        'cve_id': cve_id,
        'commit_hash': row['commit_hash'],
        'cvss_score': cvss,
        'epss_score': epss,
        'cwe_id': cwe,
        'composite_score': round(score, 4),
        'fixed_gate_blocked': fixed_threshold_decision(cvss),
        'risk_gate_blocked': risk_weighted_decision(epss, cwe),
    })

df = pd.DataFrame(results)
df.to_csv("results/experiment_results.csv", index=False)
print("Results saved with threshold 0.1")
print(f"Fixed gate breaks: {df['fixed_gate_blocked'].sum()}")
print(f"Risk gate breaks:  {df['risk_gate_blocked'].sum()}")
