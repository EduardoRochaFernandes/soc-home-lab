# Elastic Detection Queries (EQL / KQL)
#
# These queries are the Elasticsearch-converted versions of the Sigma rules.
# Import them into Kibana under Security → Detection Rules or use as saved searches.
#
# Generated from Sigma rules using:
#   sigma convert -t elasticsearch-eql -p ecs_windows detections/sigma/<rule>.yml

---

## SOC-010 — PowerShell Encoded Command (EQL)

```eql
process where event.type == "start"
  and process.name : ("powershell.exe", "pwsh.exe")
  and process.command_line : ("* -EncodedCommand *", "* -enc *", "* -EC *")
```

**Kibana Rule Settings:**
- Name: `SOC-010 PowerShell Encoded Command`
- Type: EQL
- Index: `winlogbeat-*`
- Severity: High
- Risk Score: 73
- MITRE ATT&CK: T1059.001

---

## SOC-040 — Windows Event Log Cleared (EQL)

```eql
sequence with maxspan=30s
  [any where event.code : ("1102", "104")
    and event.provider : ("Microsoft-Windows-Eventlog")]
```

**Simple KQL version:**
```kql
event.code: "1102" OR (event.code: "104" AND winlog.provider_name: "Microsoft-Windows-Eventlog")
```

**Kibana Rule Settings:**
- Name: `SOC-040 Windows Event Log Cleared`
- Severity: Critical
- Risk Score: 99
- MITRE ATT&CK: T1070.001

---

## SOC-050 — SSH Brute Force (EQL with threshold)

```eql
authentication where
  event.outcome == "failure"
  and process.name == "sshd"
```

**With threshold in Kibana:**
- Type: Threshold
- Threshold field: `source.ip`
- Threshold value: 5
- Time window: 60s

**KQL for hunting:**
```kql
process.name: "sshd" AND "Failed password" AND event.outcome: "failure"
```

---

## SOC-051 — Mimikatz LSASS Access (EQL)

```eql
process where event.type == "start"
  and event.code == "10"
  and winlog.event_data.TargetImage : "*\\lsass.exe"
  and winlog.event_data.GrantedAccess : ("0x1010", "0x1410", "0x1438", "0x143a", "0x1418")
  and not process.executable : (
    "*\\MsMpEng.exe",
    "*\\svchost.exe",
    "*\\csrss.exe",
    "*\\werfault.exe"
  )
```

**Kibana Rule Settings:**
- Name: `SOC-051 Mimikatz LSASS Memory Access`
- Severity: Critical
- Risk Score: 99
- MITRE ATT&CK: T1003.001

---

## SOC-052 — /etc/shadow Access (KQL)

```kql
tags: "audit" AND auditd.data.key: "identity"
  AND file.path: ("/etc/shadow" OR "/etc/passwd" OR "/etc/gshadow")
```

---

## SOC-060 — Network Scan Detected (Suricata KQL)

```kql
event_type: "alert"
  AND alert.category: "Network Scan"
  AND NOT src_ip: "192.168.56.10"
```

---

## Threat Hunting Queries

These are not detection rules but useful for proactive hunting:

### Hunt: Unusual Parent-Child Process Relationships
```eql
process where event.type == "start"
  and process.parent.name : ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")
  and process.name : ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
```

### Hunt: Encoded PowerShell in Scheduled Tasks
```kql
winlog.event_id: "4698" AND winlog.event_data.TaskContent: "*EncodedCommand*"
```

### Hunt: New Local Admin Account Created
```eql
sequence with maxspan=1m
  [iam where event.code == "4720"]
  [iam where event.code == "4732" and winlog.event_data.GroupName == "Administrators"]
```

### Hunt: Outbound Connection to Rare External IP
```eql
network where event.type == "connection"
  and network.direction == "outbound"
  and not destination.ip : ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  and process.name : ("powershell.exe", "cmd.exe", "mshta.exe")
```

### Hunt: Mass File Access (Ransomware Indicator)
```eql
file where event.type in ("creation", "change")
  and file.extension in ("locked", "encrypted", "ransom", "crypt")
```

### Hunt: SSH Key Added by Non-Root User
```kql
tags: "audit" AND auditd.data.key: "ssh_keys"
  AND user.name: (NOT "root")
```

---

## Importing Rules into Kibana

1. Go to **Security → Detect → Rules**
2. Click **Import rules**
3. Upload the NDJSON exports from `dashboards/kibana/`

Or create manually:
1. **Create new rule**
2. Select rule type (EQL / KQL / Threshold)
3. Paste the query from above
4. Configure severity, risk score, and MITRE tags
5. Set schedule (e.g. every 5 minutes)
