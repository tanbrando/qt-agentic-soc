# 🛡️ Security Incident Investigation Report: Security Incident: SSH Authentication Brute Force on edge-gateway-01

## Executive Summary
- **Case ID**: `c707b3b1-0444-4d3f-a7f7-7d93acd6f187`
- **Assigned Verdict**: **True Positive**
- **Confidence Level**: **95.0%**
- **Incident Severity**: **HIGH**
- **Target Host**: `edge-gateway-01`

### Summary
High-confidence True Positive confirmed. Attacker telemetry matches malicious threat intelligence reputation score (100.0/100) and repeated authentication failures.

---

## 🔍 Root Cause Analysis
External credential brute-force campaign targeting authentication daemon on public-facing endpoint.

---

## 🌐 Threat Intelligence & Enriched Artifacts
- **Observable 185.220.101.5** (IP): Score 100.0/100 | Vendor: AbuseIPDB

---

## 📋 Investigation Findings & Evidence
- **Total Correlated Alerts**: 1
- **Evidence Raw Log Count**: 5
- **Impacted Hostname**: `edge-gateway-01`
- **Correlated Attacker Observables**: 185.220.101.5

---

## 🛠️ Recommended Remediation Proposals (Human-in-the-Loop)
> **Note**: Automated containment is withheld. The following actions are recommended for human approval:
1. Block offending IP address(es) 185.220.101.5 on perimeter firewall.
2. Enforce SSH key-only authentication and disable password-based login for privileged users.
3. Review auth.log for any successful logins immediately succeeding failed brute-force clusters.