# Detection Catalog

This catalog tracks all detection rules in the project, their ATT&CK mapping, log sources, severity, and validation status.

**Rule format:** All rules are authored in [Sigma](https://github.com/SigmaHQ/sigma) and converted to target backends. See [Rule Writing Guide](rule-writing-guide.md).

---

## Coverage Summary

| Tactic | Total Rules | Validated | Coverage |
|--------|-------------|-----------|----------|
| Initial Access | 2 | 0 | 🔴 Low |
| Execution | 4 | 0 | 🔴 Low |
| Persistence | 3 | 0 | 🔴 Low |
| Privilege Escalation | 2 | 0 | 🔴 Low |
| Defense Evasion | 3 | 0 | 🔴 Low |
| Credential Access | 3 | 0 | 🔴 Low |
| Discovery | 2 | 0 | 🔴 Low |
| Lateral Movement | 2 | 0 | 🔴 Low |
| Collection | 1 | 0 | 🔴 Low |
| Exfiltration | 1 | 0 | 🔴 Low |
| **Total** | **23** | **0** | |

*Rules are added progressively through Milestone 4. Validated = simulation confirmed alert fires.*

---

## Rule Index

### Initial Access

| Rule ID | Title | Technique | Log Source | Severity | Validated |
|---------|-------|-----------|------------|----------|-----------|
| [SOC-001](../../detections/sigma/initial-access/SOC-001-web-shell-upload.yml) | Web Shell Upload via nginx | T1505.003 | nginx | High | ❌ |
| [SOC-002](../../detections/sigma/initial-access/SOC-002-exploit-public-facing.yml) | Suspicious HTTP Error Spike | T1190 | Suricata | Medium | ❌ |

### Execution

| Rule ID | Title | Technique | Log Source | Severity | Validated |
|---------|-------|-----------|------------|----------|-----------|
| [SOC-010](../../detections/sigma/execution/SOC-010-powershell-encoded.yml) | PowerShell Encoded Command | T1059.001 | Sysmon (EID 1) | High | ❌ |
| [SOC-011](../../detections/sigma/execution/SOC-011-powershell-scriptblock.yml) | PowerShell Script Block Logging — Suspicious Keywords | T1059.001 | PowerShell/Operational | High | ❌ |
| [SOC-012](../../detections/sigma/execution/SOC-012-linux-bash-reverse-shell.yml) | Bash Reverse Shell Patterns | T1059.004 | auditd | High | ❌ |
| [SOC-013](../../detections/sigma/execution/SOC-013-wmi-execution.yml) | WMI Process Execution | T1047 | Sysmon (EID 1) | Medium | ❌ |

### Persistence

| Rule ID | Title | Technique | Log Source | Severity | Validated |
|---------|-------|-----------|------------|----------|-----------|
| [SOC-020](../../detections/sigma/persistence/SOC-020-crontab-modification.yml) | Crontab Modification | T1053.003 | auditd | Medium | ❌ |
| [SOC-021](../../detections/sigma/persistence/SOC-021-new-service-created.yml) | New Windows Service Created | T1543.003 | Sysmon (EID 13) | High | ❌ |
| [SOC-022](../../detections/sigma/persistence/SOC-022-ssh-authorized-keys.yml) | SSH Authorized Keys Modified | T1098.004 | auditd | High | ❌ |

### Privilege Escalation

| Rule ID | Title | Technique | Log Source | Severity | Validated |
|---------|-------|-----------|------------|----------|-----------|
| [SOC-030](../../detections/sigma/privilege-escalation/SOC-030-sudo-abuse.yml) | Unusual sudo Usage | T1548.003 | auth.log | Medium | ❌ |
| [SOC-031](../../detections/sigma/privilege-escalation/SOC-031-suid-execution.yml) | SUID Binary Execution | T1548.001 | auditd | High | ❌ |

### Defense Evasion

| Rule ID | Title | Technique | Log Source | Severity | Validated |
|---------|-------|-----------|------------|----------|-----------|
| [SOC-040](../../detections/sigma/defense-evasion/SOC-040-log-clearing-windows.yml) | Windows Event Log Cleared | T1070.001 | Security (EID 1102) | Critical | ❌ |
| [SOC-041](../../detections/sigma/defense-evasion/SOC-041-auditd-tamper.yml) | auditd Service Stopped | T1562.012 | syslog | High | ❌ |
| [SOC-042](../../detections/sigma/defense-evasion/SOC-042-timestomp.yml) | File Timestamp Modification (Timestomping) | T1070.006 | auditd | Medium | ❌ |

### Credential Access

| Rule ID | Title | Technique | Log Source | Severity | Validated |
|---------|-------|-----------|------------|----------|-----------|
| [SOC-050](../../detections/sigma/credential-access/SOC-050-ssh-bruteforce.yml) | SSH Brute Force Attack | T1110.001 | auth.log / Suricata | High | ❌ |
| [SOC-051](../../detections/sigma/credential-access/SOC-051-mimikatz-indicators.yml) | Mimikatz In-Memory Indicators | T1003.001 | Sysmon (EID 10) | Critical | ❌ |
| [SOC-052](../../detections/sigma/credential-access/SOC-052-passwd-shadow-access.yml) | /etc/shadow or /etc/passwd Read | T1003.008 | auditd | High | ❌ |

### Discovery

| Rule ID | Title | Technique | Log Source | Severity | Validated |
|---------|-------|-----------|------------|----------|-----------|
| [SOC-060](../../detections/sigma/discovery/SOC-060-network-scan.yml) | Network Port Scan Detected | T1046 | Suricata | Medium | ❌ |
| [SOC-061](../../detections/sigma/discovery/SOC-061-ad-enumeration.yml) | Active Directory Enumeration | T1087.002 | Security Event Logs | Medium | ❌ |

### Lateral Movement

| Rule ID | Title | Technique | Log Source | Severity | Validated |
|---------|-------|-----------|------------|----------|-----------|
| [SOC-070](../../detections/sigma/lateral-movement/SOC-070-psexec.yml) | PsExec / Remote Execution | T1021.002 | Sysmon (EID 1, 17) | High | ❌ |
| [SOC-071](../../detections/sigma/lateral-movement/SOC-071-rdp-brute.yml) | RDP Brute Force | T1110.001 | Security (EID 4625) | High | ❌ |

### Collection & Exfiltration

| Rule ID | Title | Technique | Log Source | Severity | Validated |
|---------|-------|-----------|------------|----------|-----------|
| [SOC-080](../../detections/sigma/collection/SOC-080-data-staging.yml) | Large Archive Creation | T1074 | auditd / Sysmon | Medium | ❌ |
| [SOC-090](../../detections/sigma/exfiltration/SOC-090-dns-tunneling.yml) | DNS Tunneling Indicators | T1048.003 | Suricata / Zeek | High | ❌ |

---

## Coverage Heatmap (ATT&CK Navigator)

An ATT&CK Navigator layer file is maintained at [`docs/reports/attck-coverage.json`](../reports/attck-coverage.json). Import it at https://mitre-attack.github.io/attack-navigator/ to visualise coverage.

---

## Adding New Rules

See [Rule Writing Guide](rule-writing-guide.md) and open a [Detection Rule Issue](../../issues/new?template=detection-rule.yml).
