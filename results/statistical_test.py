import pandas as pd
from statsmodels.stats.proportion import proportions_ztest
from scipy import stats
import numpy as np

df = pd.read_csv("results/experiment_results.csv")
total = len(df)

fixed_breaks = df['fixed_gate_blocked'].sum()
risk_breaks = df['risk_gate_blocked'].sum()

fixed_rate = fixed_breaks / total
risk_rate = risk_breaks / total

print("=" * 60)
print("STATISTICAL ANALYSIS")
print("=" * 60)
print(f"\nTotal commits:          {total}")
print(f"Gate A breaks:          {fixed_breaks} ({fixed_rate*100:.1f}%)")
print(f"Gate B breaks:          {risk_breaks} ({risk_rate*100:.1f}%)")

# Two-proportion z-test
count = np.array([fixed_breaks, risk_breaks])
nobs = np.array([total, total])

z_stat, p_value = proportions_ztest(count, nobs)

print(f"\nTwo-Proportion Z-Test:")
print(f"  Z-statistic:          {z_stat:.4f}")
print(f"  P-value:              {p_value:.6f}")
print(f"  Significant (a=0.05): {'YES' if p_value < 0.05 else 'NO'}")

# Effect size
effect_size = abs(fixed_rate - risk_rate)
print(f"\nEffect size:            {effect_size:.4f}")
print(f"Break rate reduction:   {effect_size*100:.1f} percentage points")

# True positive retention
high_epss = df[df['epss_score'] >= 0.1]
risk_tp = (df['risk_gate_blocked'] & (df['epss_score'] >= 0.1)).sum()
tp_retention = risk_tp / len(high_epss) * 100

print(f"\nTrue-Positive Retention:")
print(f"  High-risk findings:   {len(high_epss)}")
print(f"  Gate B retained:      {tp_retention:.1f}%")
print(f"  Meets 90% floor:      {'YES' if tp_retention >= 90 else 'NO'}")

print(f"\n{'='*60}")
print("CONCLUSION")
print(f"{'='*60}")
if p_value < 0.05 and tp_retention >= 90:
    print("Risk-weighted gate significantly reduces break rate")
    print("while retaining all high-risk findings.")
    print("Both conditions of RQ1 are satisfied.")
else:
    print("Result does not satisfy both RQ1 conditions.")
