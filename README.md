# 🛡️ SOC Home Lab — Open-Source SIEM & Detection Engineering Platform

<div align="center">

![Status](https://img.shields.io/badge/status-active-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![Stack](https://img.shields.io/badge/stack-Wazuh%20%7C%20ELK%20%7C%20Suricata%20%7C%20TheHive%20%7C%20MISP-blueviolet)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)

**A fully documented, production-grade Security Operations Center built from scratch.**  
Detection engineering · Incident response · Threat intelligence · SOAR automation

[Architecture](#architecture) · [Setup Guide](docs/setup/) · [Detection Rules](detections/) · [Runbooks](docs/runbooks/) · [Milestones](#roadmap)

</div>

---

## 📖 Overview

This project is a complete, open-source SOC home lab built on commodity hardware using industry-standard tools. It was designed to mirror real-world Security Operations Center environments and serve as a hands-on learning platform for detection engineering, incident response, and threat intelligence operations.

**What makes this different from tutorials:**
- Every detection rule is mapped to MITRE ATT&CK and validated against real attack simulations
- Full incident response pipeline from alert → triage → case → post-mortem
- Architecture decisions are documented in [ADRs](docs/architecture/adr/)
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/) — the project history is readable
- All attack simulations are documented with expected detections, so you can reproduce results

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Proxmox / VirtualBox Host                        │
│                                                                       │
│  ┌─────────────────────┐   ┌──────────────┐   ┌──────────────────┐ │
│  │    SIEM Server       │   │ Windows 10   │   │  Ubuntu 22.04    │ │
│  │                      │   │  (Victim)    │   │  (Victim)        │ │
│  │  • Wazuh Manager     │   │              │   │                  │ │
│  │  • Elasticsearch     │◄──│• Sysmon      │   │• auditd          │ │
│  │  • Kibana            │   │• Winlogbeat  │   │• Filebeat        │ │
│  │  • Logstash          │◄──│• Wazuh Agent │◄──│• Wazuh Agent     │ │
│  │  • TheHive           │   │              │   │• Suricata (NIDS) │ │
│  │  • Cortex            │   └──────────────┘   │• nginx           │ │
│  │  • MISP              │                       └──────────────────┘ │
│  └─────────────────────┘                                             │
│                                                                       │
│  ┌─────────────────────┐                                             │
│  │  Kali Linux          │                                            │
│  │  (Attack Platform)   │                                            │
│  │  • Atomic Red Team   │                                            │
│  │  • Caldera           │                                            │
│  └─────────────────────┘                                             │
└─────────────────────────────────────────────────────────────────────┘
```

See [Architecture Overview](docs/architecture/01-overview.md) for full details, network topology, and data flow.

---

## 🧱 Stack

| Component | Role | Version |
|-----------|------|---------|
| [Wazuh](https://wazuh.com/) | HIDS, FIM, Vulnerability Detection, Agent Management | 4.7.x |
| [Elasticsearch](https://www.elastic.co/) | Log storage and search backend | 8.x |
| [Kibana](https://www.elastic.co/kibana) | Dashboards and visualisation | 8.x |
| [Logstash](https://www.elastic.co/logstash) | Log ingestion and enrichment pipelines | 8.x |
| [Suricata](https://suricata.io/) | Network Intrusion Detection System (NIDS) | 7.x |
| [Zeek](https://zeek.org/) | Network traffic analysis and metadata | 6.x |
| [TheHive](https://thehive-project.org/) | Case management and incident response | 5.x |
| [Cortex](https://github.com/TheHive-Project/Cortex) | Automated observable analysis | 3.x |
| [MISP](https://www.misp-project.org/) | Threat intelligence platform and IoC sharing | 2.4.x |
| [Winlogbeat](https://www.elastic.co/beats/winlogbeat) | Windows event log shipper | 8.x |
| [Filebeat](https://www.elastic.co/beats/filebeat) | Linux log shipper | 8.x |
| [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Enhanced Windows telemetry | Latest |

---

## 🗺️ Roadmap

| Milestone | Scope | Status |
|-----------|-------|--------|
| [M1 — Foundation](../../milestone/1) | Repo setup, architecture docs, lab networking | 🔄 In Progress |
| [M2 — Core SIEM](../../milestone/2) | Wazuh + ELK operational, first logs flowing | ⏳ Planned |
| [M3 — Log Sources](../../milestone/3) | Windows, Linux, Suricata, nginx agents | ⏳ Planned |
| [M4 — Detection Engineering](../../milestone/4) | 30+ Sigma rules, ATT&CK coverage, dashboards | ⏳ Planned |
| [M5 — Attack Simulations](../../milestone/5) | Atomic Red Team validation of all detections | ⏳ Planned |
| [M6 — SOAR & Threat Intel](../../milestone/6) | TheHive + Cortex + MISP integration | ⏳ Planned |
| [M7 — Documentation & Polish](../../milestone/7) | Runbooks, reports, demo video | ⏳ Planned |

---

## 🚀 Quick Start

> **Prerequisites:** 32GB RAM minimum, 500GB storage, VirtualBox or Proxmox installed.

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/soc-home-lab.git
cd soc-home-lab

# 2. Follow the setup guide in order
# Start here:
cat docs/setup/01-proxmox-setup.md
```

Full setup walkthrough → [docs/setup/](docs/setup/)

---

## 📂 Repository Structure

```
soc-home-lab/
├── .github/                  # Issue templates, CI workflows, PR template
├── docs/
│   ├── architecture/         # Design docs, network diagrams, ADRs
│   ├── setup/                # Step-by-step installation guides
│   ├── detections/           # Detection catalog, rule writing guide
│   ├── runbooks/             # Incident response playbooks
│   └── reports/              # Attack simulation reports & post-mortems
├── infrastructure/
│   ├── ansible/              # Automated agent provisioning
│   └── scripts/              # Utility shell scripts
├── detections/
│   ├── sigma/                # Portable Sigma rules (mapped to ATT&CK)
│   ├── wazuh/                # Wazuh custom rules (XML)
│   ├── suricata/             # Suricata network signatures
│   └── elastic/              # EQL / KQL saved queries
├── dashboards/               # Kibana dashboard exports (NDJSON)
├── simulations/              # Attack playbooks and Atomic Red Team mappings
├── threat-intel/             # MISP feed configs, IoC enrichment tools
└── tools/                    # Python utilities (log generator, triage helper)
```

---

## 🎯 Detection Coverage

Current ATT&CK coverage is tracked in the [Detection Catalog](docs/detections/catalog.md).

| Tactic | Rules | Validated |
|--------|-------|-----------|
| Initial Access | 0 | 0 |
| Execution | 0 | 0 |
| Persistence | 0 | 0 |
| Privilege Escalation | 0 | 0 |
| Defense Evasion | 0 | 0 |
| Credential Access | 0 | 0 |
| Discovery | 0 | 0 |
| Lateral Movement | 0 | 0 |
| Collection | 0 | 0 |
| Exfiltration | 0 | 0 |

*Table auto-updated as rules are added in [Milestone 4](../../milestone/4)*

---

## 📋 Contributing

This is a learning project built in public. Contributions, suggestions and issue reports are welcome.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## ⚠️ Legal Disclaimer

All attack simulations in this project are performed in an **isolated, private lab environment** with no connection to production networks. Tools and techniques documented here are for **educational and defensive purposes only**. The author does not condone unauthorized access to computer systems.

---

## 📄 License

MIT — see [LICENSE](LICENSE)
