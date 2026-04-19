# Runbook: Suspicious PowerShell Execution

**Detection Rule:** SOC-010  
**ATT&CK Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell  
**Severity:** High  
**SLA:** Acknowledge within 15 minutes, triage within 30 minutes

---

## Overview

PowerShell with encoded commands (`-EncodedCommand`, `-enc`) is one of the most common techniques used in real-world attacks — from ransomware droppers to post-exploitation frameworks like Empire and Cobalt Strike. This runbook covers triage from a Sysmon Event ID 1 alert where PowerShell was launched with suspicious flags.

---

## Step 1 — Initial Triage

### 1.1 Decode the Command

```powershell
# On the analyst machine — decode the base64 payload
$encoded = "<PASTE_BASE64_FROM_ALERT>"
[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
```

Or in Python (on your analyst machine):
```python
import base64
encoded = "<PASTE_BASE64_FROM_ALERT>"
print(base64.b64decode(encoded).decode('utf-16'))
```

Key questions:
- [ ] What does the decoded command actually do?
- [ ] Does it download anything? (look for `IWR`, `Invoke-WebRequest`, `DownloadString`, `DownloadFile`)
- [ ] Does it reference external IPs or domains?
- [ ] Is it reading or writing to disk?
- [ ] Does it attempt to disable AV or logging?

### 1.2 Examine Process Tree in Kibana

```kql
winlog.channel: "Microsoft-Windows-Sysmon/Operational"
  AND winlog.event_id: "1"
  AND (process.parent.pid: "<PARENT_PID>" OR process.pid: "<POWERSHELL_PID>")
```

Look for:
- **Parent process** — Was this launched by Word, Excel, a browser, or another suspicious parent?
- **Child processes** — Did PowerShell launch anything after running?

### 1.3 Check for Network Connections from Same Process

```kql
winlog.channel: "Microsoft-Windows-Sysmon/Operational"
  AND winlog.event_id: "3"
  AND process.pid: "<POWERSHELL_PID>"
```

Any outbound connections to external IPs → escalate severity immediately.

### 1.4 Check Script Block Log

```kql
winlog.channel: "Microsoft-Windows-PowerShell/Operational"
  AND winlog.event_id: "4104"
  AND "@timestamp": [<ALERT_TIME_MINUS_5min> TO <ALERT_TIME_PLUS_5min>]
```

Script Block Logging captures the decoded command — use this to see exactly what ran.

---

## Step 2 — Containment

### 2.1 If Active Threat — Isolate the Host

Via Wazuh (active response):
```bash
# On SIEM — trigger active response to block an IP or isolate
sudo /var/ossec/bin/agent_control -b <AGENT_IP> -f netsh-win-2016 -a "<ATTACKER_IP>"
```

Manual (on Windows Victim if accessible):
```powershell
# Block all outbound except to SIEM (for Wazuh agent to stay connected)
New-NetFirewallRule -DisplayName "SOC-ISOLATE-BLOCK-OUT" `
  -Direction Outbound -Action Block -Profile Any
New-NetFirewallRule -DisplayName "SOC-ISOLATE-ALLOW-SIEM" `
  -Direction Outbound -RemoteAddress 192.168.56.10 -Action Allow
```

### 2.2 Kill the Process (if still running)

```powershell
# On Windows Victim
Stop-Process -Id <PID> -Force
```

---

## Step 3 — Investigation

### 3.1 Timeline Reconstruction

```kql
# All Sysmon events from the affected host in ±30 min window
winlog.computer_name: "<HOSTNAME>"
  AND "@timestamp": [<T-30min> TO <T+30min>]
  AND winlog.channel: "Microsoft-Windows-Sysmon/Operational"
| sort @timestamp asc
```

### 3.2 Hunt for Persistence Mechanisms

```kql
# Registry run keys modified after the execution
winlog.event_id: ("12" OR "13" OR "14")
  AND winlog.event_data.TargetObject: ("*\\Run\\*" OR "*\\RunOnce\\*" OR "*\\Services\\*")
```

```kql
# Scheduled task created
winlog.event_id: "4698"
```

### 3.3 Hunt for Lateral Movement Indicators

```kql
# Network connections to other lab hosts after the alert
winlog.event_id: "3"
  AND destination.ip: ("192.168.56.20" OR "192.168.56.30")
  AND NOT source.ip: "192.168.56.10"
  AND "@timestamp": [<ALERT_TIME> TO NOW]
```

### 3.4 Enrich External IPs/Domains in TheHive

Add any IPs or domains from the decoded command as observables in the TheHive case and run Cortex analyzers:
- `AbuseIPDB_1_0`
- `VirusTotal_GetReport_3_0`
- `Shodan_DNSResolve_1_0`

---

## Step 4 — Remediation

### 4.1 If False Positive (Legitimate Tool)

Add the parent process and/or command pattern to the Sigma rule filter:

```yaml
# In SOC-010 — add to filter_legitimate section
filter_legitimate:
  ParentImage|endswith:
    - '\YourLegitTool.exe'
  CommandLine|contains:
    - 'KnownGoodPattern'
```

Open a PR to update the rule.

### 4.2 If True Positive

1. Preserve forensic evidence (export relevant Kibana queries to CSV)
2. Take VM snapshot before any remediation
3. Remove persistence mechanisms found in Step 3.2
4. Check for additional compromised credentials (any successful logons?)
5. Reset passwords for any accounts that ran PowerShell
6. If malware executed: consider full reimaging from clean snapshot

---

## Step 5 — Post-Incident Actions

### Case Closure in TheHive

| Field | Value |
|-------|-------|
| Verdict | True Positive — Malicious PowerShell / False Positive — [Tool Name] |
| Root Cause | |
| Impact | |
| Containment | |
| Remediation | |

### Follow-up Issues

- Detection gap in rule? → [New Detection Issue](../../issues/new?template=detection-rule.yml)
- False positive to filter? → Open PR against SOC-010 Sigma rule

---

## Related Resources

- [Detection Rule SOC-010](../../detections/sigma/execution/SOC-010-powershell-encoded.yml)
- [Simulation Scenario](../../simulations/manual/02-powershell-encoded.md)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Hunting PowerShell — RTC blog](https://redcanary.com/threat-detection-report/techniques/powershell/)
