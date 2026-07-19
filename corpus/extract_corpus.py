import sqlite3
import pandas as pd

DB_PATH = "corpus/CVEfixes_v1.0.0/Data/CVEfixes.db"
conn = sqlite3.connect(DB_PATH)

print("Extracting Python corpus from CVEfixes...")

corpus = pd.read_sql("""
    SELECT 
        f.cve_id,
        f.hash as commit_hash,
        r.repo_url,
        r.repo_name,
        COALESCE(c.cvss3_base_score, c.cvss2_base_score, '0') as cvss_score,
        cv.cwe_id,
        c.published_date,
        c.cvss3_base_severity
    FROM fixes f
    JOIN repository r ON f.repo_url = r.repo_url
    JOIN cve c ON f.cve_id = c.cve_id
    LEFT JOIN cwe_classification cv ON f.cve_id = cv.cve_id
    WHERE r.repo_language = 'Python'
    ORDER BY f.cve_id
""", conn)

# Clean up
corpus['cvss_score'] = pd.to_numeric(corpus['cvss_score'], errors='coerce').fillna(0.0)
corpus['cwe_id'] = corpus['cwe_id'].fillna('CWE-000')

# Remove duplicates
corpus = corpus.drop_duplicates(subset=['cve_id', 'commit_hash'])

print(f"Total Python commits extracted: {len(corpus)}")
print(f"Unique CVEs: {corpus['cve_id'].nunique()}")
print(f"\nCWE distribution:")
print(corpus['cwe_id'].value_counts().head(10))
print(f"\nCVSS score distribution:")
print(corpus['cvss_score'].describe())

# Save to CSV
corpus.to_csv("corpus/python_corpus.csv", index=False)
print(f"\nCorpus saved to corpus/python_corpus.csv")

conn.close()
