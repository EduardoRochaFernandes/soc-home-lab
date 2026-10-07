# Detection Rule Writing Guide

A reference for authoring, validating, and deploying detection rules in this project.

---

## Rule Lifecycle

```
Research → Sigma Draft → Peer Review → Lab Validation → Deploy → Monitor FP Rate
```

1. **Research** — understand the technique via ATT&CK, blog posts, malware samples
2. **Draft** — write Sigma rule (see template below)
3. **Review** — open a PR; CI validates syntax
4. **Validate** — run the simulation, confirm the alert fires
5. **Deploy** — convert to target backends via `sigma-cli`
6. **Monitor** — watch for false positives over 48h baseline period

---

## Sigma Rule Template

```yaml
title: <Descriptive title — what does it detect, not how>
id: <uuid4 — generate with: python3 -c "import uuid; print(uuid.uuid4())">
status: experimental       # experimental | test | stable
description: |
  Detects <behaviour> which may indicate <technique>.
  Attackers use this technique to <goal>.
  
  References:
  - https://attack.mitre.org/techniques/T1xxx/xxx/
  - <blog post or research link>
references:
  - https://attack.mitre.org/techniques/T1xxx/xxx/
author: <your name>
date: YYYY/MM/DD
modified: YYYY/MM/DD
tags:
  - attack.<tactic_name>         # e.g. attack.credential-access
  - attack.t<id>                 # e.g. attack.t1110.001
logsource:
  product: <windows|linux|network>
  service: <sysmon|security|auditd|suricata|auth|nginx>
  # For Sysmon rules, add:
  # definition: 'Requirements: Sysmon installed with SwiftOnSecurity config'
detection:
  selection:
    <FieldName>: <Value>
    # Use lists for OR conditions:
    # <FieldName>:
    #   - value1
    #   - value2
  filter_legitimate:
    # Explicitly exclude known false positives
    <FieldName>: <LegitimateValue>
  condition: selection and not filter_legitimate
falsepositives:
  - <Known legitimate activity that could match>
  - <Another known FP>
level: <critical|high|medium|low|informational>
```

---

## Field Names by Log Source

### Sysmon (Windows)

| Event ID | Key Fields |
|----------|-----------|
| 1 (Process Create) | `Image`, `CommandLine`, `ParentImage`, `User`, `IntegrityLevel` |
| 3 (Network Connect) | `DestinationIp`, `DestinationPort`, `Image`, `Protocol` |
| 7 (Image Load) | `ImageLoaded`, `Image`, `Signed`, `SignatureStatus` |
| 10 (ProcessAccess) | `TargetImage`, `GrantedAccess`, `SourceImage` |
| 13 (Registry) | `TargetObject`, `Details` |
| 22 (DNS Query) | `QueryName`, `Image` |

### Windows Security Events

| Event ID | Description | Key Fields |
|----------|-------------|-----------|
| 4624 | Successful logon | `LogonType`, `SubjectUserName`, `IpAddress` |
| 4625 | Failed logon | `TargetUserName`, `IpAddress`, `LogonType` |
| 4648 | Explicit credentials logon | `TargetUserName`, `SubjectUserName` |
| 4688 | Process creation | `CommandLine`, `NewProcessName`, `ParentProcessName` |
| 4698 | Scheduled task created | `TaskName`, `TaskContent` |
| 4720 | User account created | `TargetUserName`, `SubjectUserName` |
| 4728/4732 | Group membership change | `MemberName`, `GroupName` |
| 1102 | Audit log cleared | `SubjectUserName` |

### Linux auditd

| Key | Description |
|-----|-------------|
| `type` | SYSCALL, EXECVE, PATH, etc. |
| `syscall` | Syscall name or number |
| `exe` | Executable path |
| `key` | Audit rule key (e.g. `identity`, `execution`) |
| `uid`, `gid` | User/group IDs |
| `auid` | Audit UID (login user) |
| `comm` | Command name |
| `a0`, `a1` | Syscall arguments |

### Suricata EVE

| Field | Description |
|-------|-------------|
| `event_type` | `alert`, `dns`, `http`, `tls`, `flow` |
| `alert.signature` | Rule name that triggered |
| `alert.category` | ET category |
| `alert.severity` | 1 (high) to 3 (low) |
| `src_ip`, `dest_ip` | Source/destination |
| `proto` | Protocol |
| `http.url` | URL (for HTTP events) |

---

## Worked Example — SSH Brute Force

The real file is [`SOC-050-ssh-bruteforce.yml`](../../detections/sigma/credential-access/SOC-050-ssh-bruteforce.yml). It is two
YAML documents in one file: a base rule that matches a single failed login, and a Sigma *correlation* rule that counts them.

```yaml
# Document 1: the event
title: SSH Failed Password Attempt
name: ssh_failed_password
logsource:
  product: linux
  service: auth
detection:
  selection:
    program: sshd
    message|contains: 'Failed password'
  condition: selection
# ... (id, tags, level, etc. omitted here)
---
# Document 2: more than 5 events from one source IP in 60 seconds
title: SSH Brute Force Attack
correlation:
  type: event_count
  rules:
    - ssh_failed_password
  group-by:
    - src_ip
  timespan: 60s
  condition:
    gt: 5
```

The older `selection | count() by src_ip > 5` pipe syntax is deprecated and rejected by current pySigma, which is why the
correlation form is used.

Check and convert (the Elasticsearch backend does not convert correlation rules, so convert the Windows rules instead):

```bash
sigma check -x attacktag detections/sigma
sigma plugin install elasticsearch
sigma convert -t lucene -p ecs_windows detections/sigma/execution detections/sigma/defense-evasion
```

`make sigma` runs these two steps.

---

## Detection Quality Checklist

Before submitting a rule in a PR:

- [ ] **Specificity**: Does the rule have enough conditions to avoid massive FP rates?
- [ ] **Sensitivity**: Would this miss variants of the technique (e.g. encoded commands)?
- [ ] **False positives**: Is the `falsepositives` field honest and complete?
- [ ] **Filters**: Are known legitimate cases filtered with `filter_*` conditions?
- [ ] **ATT&CK**: Is the `tags` section correct and complete?
- [ ] **Severity**: Is the level appropriate? (Critical = confirmed breach, not just suspicious)
- [ ] **Validated**: Did the rule fire against a simulation? (Required for `status: stable`)
- [ ] **UUID**: Does the rule have a unique, permanent ID?

---

## Severity Guidelines

| Level | When to use | Example |
|-------|-------------|---------|
| `critical` | High-confidence active exploitation | Mimikatz LSASS access, log clearing during incident |
| `high` | Strong indicator, low FP in normal environments | PowerShell encoded command, SSH brute force success |
| `medium` | Suspicious, requires analyst investigation | Unusual cron modification, SUID binary execution |
| `low` | Informational, high FP in some environments | Port scan from internal IP, unusual DNS query |
| `informational` | Baseline telemetry, not actionable alone | All process creations (use for hunting, not alerting) |

---

## Converting Rules to Backend Formats

```bash
# Install sigma-cli
pip install sigma-cli
sigma plugin install elasticsearch
sigma plugin install splunk
sigma plugin install qradar

# Convert to Elasticsearch EQL
sigma convert -t elasticsearch-eql -p ecs_windows detections/sigma/execution/SOC-010-powershell-encoded.yml

# Convert to Kibana NDJSON (importable)
sigma convert -t kibana-ndjson detections/sigma/execution/SOC-010-powershell-encoded.yml

# Convert all rules in a tactic folder
sigma convert -t elasticsearch-eql detections/sigma/credential-access/*.yml

# Validate syntax only
sigma check detections/sigma/credential-access/SOC-050-ssh-bruteforce.yml
```

Converted output goes in:
- `detections/elastic/` — EQL/KQL queries
- `detections/wazuh/` — Wazuh XML rules
- `detections/suricata/` — Suricata `.rules` files
