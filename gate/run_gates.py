import json
import subprocess
import sys

# CWE mapping for common CVEs - in real experiment this comes from CVEfixes
CWE_MAP = {
    "CVE-2019-10906": "CWE-693",
    "CVE-2020-28493": "CWE-400",
    "CVE-2024-22195": "CWE-79",
    "CVE-2024-34064": "CWE-79",
    "CVE-2024-56326": "CWE-693",
    "CVE-2025-27516": "CWE-693",
    "CVE-2019-14322": "CWE-22",
    "CVE-2019-14806": "CWE-331",
    "CVE-2023-25577": "CWE-400",
    "CVE-2024-34069": "CWE-352",
    "CVE-2018-1000805": "CWE-287",
    "CVE-2017-18342": "CWE-502",
    "CVE-2020-14343": "CWE-502",
    "CVE-2023-0286": "CWE-119",
    "CVE-2023-50782": "CWE-208",
}

# EPSS scores - in real experiment fetched from FIRST.org API
EPSS_MAP = {
    "CVE-2019-10906": 0.002,
    "CVE-2020-28493": 0.004,
    "CVE-2024-22195": 0.001,
    "CVE-2024-34064": 0.001,
    "CVE-2024-56326": 0.001,
    "CVE-2025-27516": 0.002,
    "CVE-2019-14322": 0.003,
    "CVE-2019-14806": 0.002,
    "CVE-2023-25577": 0.004,
    "CVE-2024-34069": 0.001,
    "CVE-2018-1000805": 0.012,
    "CVE-2017-18342": 0.450,
    "CVE-2020-14343": 0.380,
    "CVE-2023-0286": 0.003,
    "CVE-2023-50782": 0.002,
}

def load_trivy_output(path):
    with open(path) as f:
        return json.load(f)

def convert_to_gate_input(trivy_data):
    findings = []
    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID", "UNKNOWN")
            cvss = vuln.get("CVSS", {})
            score = 0
            for source in cvss.values():
                score = max(score, source.get("V3Score", source.get("V2Score", 0)))
            findings.append({
                "cve_id": cve_id,
                "package": vuln.get("PkgName", "unknown"),
                "version": vuln.get("InstalledVersion", "unknown"),
                "cvss_score": score,
                "epss_score": EPSS_MAP.get(cve_id, 0.001),
                "cwe_id": CWE_MAP.get(cve_id, "CWE-000")
            })
    return {"findings": findings}

def run_opa(input_data, policy_path, query):
    input_json = json.dumps(input_data)
    result = subprocess.run(
        ["opa", "eval",
         "--input", "/dev/stdin",
         "--data", policy_path,
         query],
        input=input_json,
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)

def main():
    print("=" * 60)
    print("RISK-WEIGHTED GATE EXPERIMENT")
    print("=" * 60)

    # Load Trivy output
    trivy_data = load_trivy_output("results/trivy_output.json")
    gate_input = convert_to_gate_input(trivy_data)
    total = len(gate_input["findings"])
    print(f"\nTotal findings from Trivy: {total}")

    # Run fixed-threshold gate
    print("\n--- GATE A: Fixed Threshold (CVSS >= 7.0) ---")
    fixed_result = run_opa(
        gate_input,
        "gate/fixed/fixed_threshold.rego",
        "data.gate.fixed.violations"
    )
    fixed_violations = fixed_result["result"][0]["expressions"][0]["value"]
    print(f"Blocked: {len(fixed_violations)} findings")
    for v in fixed_violations:
        print(f"  {v}")

    # Run risk-weighted gate
    print("\n--- GATE B: Risk-Weighted (EPSS + CWE Reachability) ---")
    risk_result = run_opa(
        gate_input,
        "gate/risk_weighted/risk_weighted.rego",
        "data.gate.risk_weighted.violations"
    )
    risk_violations = risk_result["result"][0]["expressions"][0]["value"]
    print(f"Blocked: {len(risk_violations)} findings")
    for v in risk_violations:
        print(f"  {v}")

    # Summary
    print("\n--- COMPARISON SUMMARY ---")
    print(f"Total findings:              {total}")
    print(f"Fixed gate blocked:          {len(fixed_violations)}")
    print(f"Risk-weighted gate blocked:  {len(risk_violations)}")
    print(f"Reduction in breaks:         {len(fixed_violations) - len(risk_violations)}")
    if len(fixed_violations) > 0:
        reduction_pct = ((len(fixed_violations) - len(risk_violations)) / len(fixed_violations)) * 100
        print(f"Break rate reduction:        {reduction_pct:.1f}%")

if __name__ == "__main__":
    main()
