# ADR-001: Use Wazuh as the HIDS and Agent Framework

**Date:** 2025-01-01  
**Status:** Accepted

---

## Context

The lab needs a host-based intrusion detection system (HIDS) capable of:
- Collecting and normalising logs from both Windows and Linux endpoints
- Running custom detection rules against host telemetry
- Providing file integrity monitoring (FIM)
- Performing vulnerability scanning

The main candidates evaluated were:
1. **Wazuh** (fork of OSSEC, actively maintained, free)
2. **Pure OSSEC** (original project, slower release cadence)
3. **Velociraptor** (excellent for forensics/EDR, different use case)
4. **Elastic Agent + Security** (requires Elastic licence for many features)

---

## Decision

Use **Wazuh** as the primary HIDS and agent management framework.

---

## Rationale

| Criterion | Wazuh | OSSEC | Velociraptor | Elastic Security |
|-----------|-------|-------|--------------|------------------|
| Active development | ✅ | ⚠️ | ✅ | ✅ |
| Free & open source | ✅ | ✅ | ✅ | ⚠️ (partial) |
| Windows + Linux agents | ✅ | ✅ | ✅ | ✅ |
| Native ELK integration | ✅ | ❌ | ❌ | ✅ |
| FIM | ✅ | ✅ | ⚠️ | ⚠️ |
| Vuln detection | ✅ | ❌ | ❌ | ⚠️ |
| Industry prevalence | ✅ | ⚠️ | ⚠️ | ✅ |
| Learning value | High | Medium | High | High |

Wazuh is used in production by real SOCs, ships with native Elasticsearch integration, and has active community support. It adds resume value that OSSEC alone does not.

---

## Consequences

- The project will follow Wazuh's XML rule format for host-based rules, with Sigma as the canonical portable format
- Wazuh major version upgrades may require agent updates across all VMs
- The ELK stack version must be compatible with the Wazuh version installed (see setup docs)
