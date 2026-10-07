# ADR-003: Sigma as the Canonical Detection Rule Format

**Date:** 2025-01-01  
**Status:** Accepted

---

## Context

Detection rules need to be stored and maintained. The lab uses multiple backends (Wazuh XML, Elasticsearch EQL/KQL, Suricata) which each have their own rule syntax. Rules written natively for one tool are not portable.

---

## Decision

**Sigma** is the canonical format. Every detection rule is written as a Sigma rule first, then converted to the target backend format using `sigma-cli`.

Native-format rules (Wazuh XML, Suricata `.rules`) are generated outputs, not the source of truth.

---

## Rationale

- Sigma rules are backend-agnostic — the same rule can target Elasticsearch, Splunk, QRadar, Microsoft Sentinel
- This is an industry-recognised skill: writing Sigma rules is explicitly listed in many Security Engineer job descriptions
- The `sigma-cli` workflow enforces rule quality (mandatory fields, valid syntax)
- GitHub CI can validate all Sigma rules automatically on every PR

---

## Consequences

- All detection development starts with a Sigma rule in `detections/sigma/<tactic>/`
- Converted output rules live in `detections/wazuh/`, `detections/elastic/`, `detections/suricata/`
- Rule IDs must be UUIDs generated at creation time and never changed
- The CI pipeline runs `sigma check` on all `.yml` files in `detections/sigma/`

## Status note

Today the Sigma rules in `detections/sigma/` are validated in CI, but the Wazuh XML and Suricata rules in this repository are
hand-written, not generated from Sigma. Suricata network rules cannot be expressed in Sigma at all. Generating Wazuh rules from
Sigma remains a goal, not a fact.
