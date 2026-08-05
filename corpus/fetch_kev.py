import requests
import pandas as pd
import json

print("Fetching CISA KEV catalogue...")

url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
response = requests.get(url, timeout=30)
kev_data = response.json()

# Extract all CVE IDs from KEV
kev_cves = set()
for vuln in kev_data.get('vulnerabilities', []):
    kev_cves.add(vuln['cveID'])

print(f"Total CVEs in CISA KEV catalogue: {len(kev_cves)}")

# Load your corpus
corpus = pd.read_csv("corpus/python_corpus_with_epss.csv")
print(f"Total CVEs in your corpus: {corpus['cve_id'].nunique()}")

# Check which corpus CVEs are in KEV
corpus['kev_confirmed'] = corpus['cve_id'].isin(kev_cves)

kev_count = corpus['kev_confirmed'].sum()
print(f"\nKEV-confirmed findings in your corpus: {kev_count}")
print(f"Non-KEV findings: {len(corpus) - kev_count}")

if kev_count > 0:
    print("\nKEV-confirmed CVEs in your corpus:")
    kev_rows = corpus[corpus['kev_confirmed']][['cve_id', 'cvss_score', 'epss_score', 'cwe_id']]
    print(kev_rows.to_string(index=False))

# Save updated corpus
corpus.to_csv("corpus/python_corpus_with_epss.csv", index=False)
print("\nCorpus updated with KEV labels.")
