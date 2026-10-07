# Runbook: [Alert/Technique Name]

**Detection Rule:** SOC-XXX  
**ATT&CK Technique:** TXXXX.XXX — [Name]  
**Severity:** [Critical / High / Medium / Low]  
**SLA:** Acknowledge within ___ minutes, triage within ___ minutes

---

## Overview

[2-3 sentence description of what this alert detects, why it matters, and what the attacker's goal typically is.]

---

## Step 1 — Initial Triage

### 1.1 Verify the Alert

[How to verify the alert is real. KQL/EQL query to run in Kibana. Key fields to check.]

Key questions:
- [ ] [Question 1]
- [ ] [Question 2]
- [ ] [Question 3]

### 1.2 Scope Assessment

[How to determine how widespread the activity is. Are other hosts affected?]

---

## Step 2 — Containment

[Immediate actions to stop the threat from spreading. Be specific — include exact commands.]

---

## Step 3 — Investigation

[Deeper analysis steps. Timeline reconstruction, enrichment, pivoting.]

---

## Step 4 — Remediation

[Steps to fix the root cause and harden against recurrence.]

---

## Step 5 — Post-Incident Actions

### Case Closure Checklist
- [ ] Verdict documented (TP/FP/Benign)
- [ ] Root cause identified
- [ ] Impact assessed
- [ ] IoCs added to MISP
- [ ] Detection gaps documented as GitHub issues
- [ ] Lessons learned recorded

---

## Escalation Criteria

[Specific conditions that warrant escalating severity or engaging additional teams.]

---

## Related Resources

- [Detection Rule SOC-XXX](../../detections/sigma/)
- [MITRE ATT&CK](https://attack.mitre.org/techniques/TXXXX/)
