package gate.fixed

import rego.v1

# Gate breaks the build if any finding has CVSS >= 7.0
# This is the control gate - no context, no scoring

default allow := false
default deny_reasons := []

allow if {
    count(violations) == 0
}

violations contains msg if {
    some finding in input.findings
    finding.cvss_score >= 7.0
    msg := sprintf("BLOCKED: %s (CVE: %s, CVSS: %v)", [
        finding.package,
        finding.cve_id,
        finding.cvss_score
    ])
}

deny_reasons := [msg | some msg in violations]
