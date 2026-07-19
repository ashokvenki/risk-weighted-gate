import requests
import pandas as pd
import time

# Load corpus
corpus = pd.read_csv("corpus/python_corpus.csv")
cve_ids = corpus['cve_id'].unique().tolist()

print(f"Fetching EPSS scores for {len(cve_ids)} unique CVEs...")

epss_scores = {}
batch_size = 30

for i in range(0, len(cve_ids), batch_size):
    batch = cve_ids[i:i+batch_size]
    cve_param = ",".join(batch)
    
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_param}"
        response = requests.get(url, timeout=30)
        data = response.json()
        
        for item in data.get('data', []):
            epss_scores[item['cve']] = float(item['epss'])
        
        print(f"Fetched batch {i//batch_size + 1}/{(len(cve_ids)//batch_size) + 1}")
        time.sleep(1)
        
    except Exception as e:
        print(f"Error fetching batch {i}: {e}")
        continue

# Add EPSS scores to corpus
corpus['epss_score'] = corpus['cve_id'].map(epss_scores).fillna(0.001)

print(f"\nEPSS scores fetched: {len(epss_scores)}")
print(f"CVEs without EPSS score: {corpus['epss_score'].eq(0.001).sum()}")
print(f"\nEPSS score distribution:")
print(corpus['epss_score'].describe())

# Save updated corpus
corpus.to_csv("corpus/python_corpus_with_epss.csv", index=False)
print(f"\nSaved to corpus/python_corpus_with_epss.csv")
