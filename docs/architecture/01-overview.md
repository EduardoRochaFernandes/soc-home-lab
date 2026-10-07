# Architecture Overview

## Goals

This lab is designed to simulate a small-to-medium enterprise Security Operations Center with:

- **Centralised log collection** from Windows, Linux, and network devices
- **Host-based intrusion detection** via Wazuh agents
- **Network intrusion detection** via Suricata on a dedicated sensor
- **Threat intelligence** enrichment via MISP
- **Case management** and semi-automated response via TheHive + Cortex

---

## Design Principles

1. **Visibility over complexity** — every component should produce observable, queryable data
2. **Defence in depth** — multiple detection layers (host + network + application)
3. **Reproducibility** — all configurations are version-controlled and can rebuild from scratch
4. **ATT&CK alignment** — every detection rule references a technique; coverage gaps are explicit

---

## Component Roles

| Component | Layer | Role |
|-----------|-------|------|
| Wazuh Manager | Management | Receives agent data, runs host-based rules, FIM, vuln scanning |
| Wazuh Agents | Host | Collect OS events, auditd, Sysmon, forward to manager |
| Elasticsearch | Storage | Backend index for all log data |
| Logstash | Pipeline | Enrichment, parsing, routing before indexing |
| Kibana | Visualisation | Dashboards, alert review, KQL/EQL queries |
| Suricata | Network | NIDS running in IDS mode on the virtual switch |
| Zeek | Network | Metadata extraction (DNS, HTTP, SSL, conn logs) |
| Filebeat | Agent | Ships Linux and nginx logs to Logstash |
| Winlogbeat | Agent | Ships Windows Event Logs to Logstash |
| TheHive | IR | Case management, alert aggregation, task tracking |
| Cortex | IR | Automated observable analysis (IP reputation, file hash, etc.) |
| MISP | Threat Intel | IoC management, feed consumption, ATT&CK mapping |

---

## Network Topology

```
Host-only Network: 192.168.56.0/24

  .10  SIEM Server    (Ubuntu 22.04 — Wazuh + ELK + TheHive + MISP)
  .20  Windows Victim (Windows 10 — Sysmon + Wazuh Agent + Winlogbeat)
  .30  Linux Victim   (Ubuntu 22.04 — auditd + Wazuh Agent + Filebeat + Suricata)
  .40  Kali Attacker  (Kali Linux — Atomic Red Team + Caldera + manual tools)
```

All VMs are on a **host-only** network with no internet access except the SIEM server, which has a second NAT adapter for package installation.

---

## Data Flow

```
Windows Victim                    SIEM Server
┌──────────────┐                 ┌──────────────────────────────────┐
│ Sysmon       ├─ Winlogbeat ───►│ Logstash :5044                   │
│ Event Logs   │                 │   ↓ (parse + enrich)             │
│ Wazuh Agent  ├──────────────►  │ Elasticsearch                    │
└──────────────┘  (1514/UDP)     │   ↓                              │
                                 │ Kibana (dashboards)              │
Linux Victim                     │   ↓                              │
┌──────────────┐                 │ Wazuh Manager (alerts)           │
│ auditd       ├─ Filebeat ────► │   ↓                              │
│ syslog/auth  │                 │ TheHive (cases)                  │
│ nginx logs   │                 │   ↓                              │
│ Suricata EVE ├─ Filebeat ────► │ Cortex (enrichment)              │
│ Wazuh Agent  ├──────────────►  │   ↓                              │
└──────────────┘                 │ MISP (threat intel)              │
                                 └──────────────────────────────────┘
```

---

## Hardware Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 24 GB | 32+ GB |
| CPU | 6 cores | 8+ cores |
| Storage | 200 GB SSD | 500 GB SSD |

### VM Allocation

| VM | RAM | vCPU | Disk |
|----|-----|------|------|
| SIEM Server | 12 GB | 4 | 100 GB |
| Windows Victim | 4 GB | 2 | 60 GB |
| Linux Victim | 2 GB | 2 | 40 GB |
| Kali Attacker | 4 GB | 2 | 60 GB |

---

## Security Considerations

- All inter-VM traffic stays on host-only network
- Wazuh agent communication is encrypted (TLS)
- Elasticsearch is not exposed outside the SIEM VM
- Kibana and TheHive are accessible only from host machine via port forwarding
- No credentials are stored in this repository (see `.gitignore`)

---

## Related Documents

- [Network Diagram](02-network-diagram.md)
- [Data Flow Detail](03-data-flow.md)
- [ADR-001: Why Wazuh over pure OSSEC](adr/ADR-001-wazuh-over-ossec.md)
- [ADR-002: Why TheHive for case management](adr/ADR-002-thehive-case-management.md)
- [ADR-003: Sigma as canonical rule format](adr/ADR-003-sigma-canonical-format.md)
