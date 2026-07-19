import sqlite3
import pandas as pd

DB_PATH = "corpus/CVEfixes_v1.0.0/Data/CVEfixes.db"
conn = sqlite3.connect(DB_PATH)

# Check what languages exist
print("=== LANGUAGES IN DATASET ===")
langs = pd.read_sql("""
    SELECT repo_language, COUNT(*) as count 
    FROM repository 
    GROUP BY repo_language 
    ORDER BY count DESC
    LIMIT 15
""", conn)
print(langs)

# Count Python commits
print("\n=== PYTHON COMMITS COUNT ===")
python_count = pd.read_sql("""
    SELECT COUNT(*) as count
    FROM fixes f
    JOIN repository r ON f.repo_url = r.repo_url
    WHERE r.repo_language = 'Python'
""", conn)
print(python_count)

# Sample Python commits with CVE and CWE data
print("\n=== SAMPLE PYTHON COMMITS ===")
sample = pd.read_sql("""
    SELECT 
        f.cve_id,
        f.hash,
        r.repo_name,
        c.cvss3_base_score,
        c.cvss2_base_score,
        cv.cwe_id
    FROM fixes f
    JOIN repository r ON f.repo_url = r.repo_url
    JOIN cve c ON f.cve_id = c.cve_id
    LEFT JOIN cwe_classification cv ON f.cve_id = cv.cve_id
    WHERE r.repo_language = 'Python'
    LIMIT 10
""", conn)
print(sample)

conn.close()
