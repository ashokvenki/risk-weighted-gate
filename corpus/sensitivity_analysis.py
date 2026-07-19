import pandas as pd

df = pd.read_csv("results/experiment_results.csv")
total = len(df)
high_epss = df[df['epss_score'] >= 0.1]

print(f"{'Threshold':<12} {'Breaks':<10} {'Break Rate':<14} {'TP Retained':<14} {'Safe?'}")
print("-" * 60)

for threshold in [0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.5]:
    risk_blocked = df['composite_score'] >= threshold
    breaks = risk_blocked.sum()
    break_rate = breaks / total * 100
    tp = (risk_blocked & (df['epss_score'] >= 0.1)).sum()
    tp_rate = tp / len(high_epss) * 100 if len(high_epss) > 0 else 0
    safe = "✓ SAFE" if tp_rate >= 90 else "✗ UNSAFE"
    print(f"{threshold:<12} {breaks:<10} {break_rate:<14.1f} {tp_rate:<14.1f} {safe}")

