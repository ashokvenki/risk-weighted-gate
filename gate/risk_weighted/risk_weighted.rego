package gate.risk_weighted

import rego.v1

# Risk-weighted gate
# Composite score = (EPSS * 0.6) + (reachability * 0.4)
# Build breaks only if composite score >= 0.4

# CWE categories classified as reachable
# These sit at exposed entry points structurally
reachable_cwes := {
    "CWE-89",   # SQL Injection
    "CWE-79",   # Cross-site Scripting
    "CWE-502",  # Deserialization
    "CWE-22"    # Path Traversal
}

default allow := false
default deny_reasons := []

# Reachability flag — 1.0 if reachable CWE, 0.0 if not
reachability_flag(cwe) := 1.0 if {
    cwe in reachable_cwes
}

reachability_flag(cwe) := 0.0 if {
    not cwe in reachable_cwes
}

# Composite risk score
composite_score(finding) := score if {
    score := (finding.epss_score * 0.6) + (reachability_flag(finding.cwe_id) * 0.4)
}

# Violations — only block if composite score >= 0.4
violations contains msg if {
    some finding in input.findings
    score := composite_score(finding)
    score >= 0.4
    msg := sprintf("BLOCKED: %s (CVE: %s, EPSS: %v, CWE: %s, Score: %v)", [
        finding.package,
        finding.cve_id,
        finding.epss_score,
        finding.cwe_id,
        score
    ])
}

allow if {
    count(violations) == 0
}

deny_reasons := [msg | some msg in violations]
