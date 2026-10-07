# ADR-002: Use TheHive for Case Management

**Date:** 2025-01-01  
**Status:** Accepted

---

## Context

The lab needs a case management system to simulate a real SOC workflow: when an alert fires, analysts need to open a case, document their investigation, run enrichments, and close with a verdict and lessons learned.

Candidates:
1. **TheHive** (open source, SOC-focused, integrates with Cortex and MISP)
2. **JIRA** (generic, overkill, not security-specific)
3. **Manual tracking in GitHub Issues** (simple but doesn't demonstrate SOAR)
4. **Shuffle** (SOAR-focused, good complement but not case management)

---

## Decision

Use **TheHive 5** with **Cortex** for automated observable enrichment.

---

## Rationale

TheHive is purpose-built for security incident management. Its native integrations with Cortex (automated analysis) and MISP (threat intelligence) allow the lab to demonstrate an end-to-end alert → case → enrich → close → report workflow. This is directly transferable to enterprise environments that use commercial equivalents (Splunk SOAR, Palo Alto XSOAR).

Cortex provides "one-click" enrichment of observables (IP reputation, file hash lookups, domain analysis) which demonstrates automation skills valued in Security Engineering roles.

---

## Consequences

- TheHive and Cortex add ~4GB RAM requirement to the SIEM server
- Wazuh alerts will be forwarded to TheHive via a Python integration script
- Case templates will be created for each major detection category
