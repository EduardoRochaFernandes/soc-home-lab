# Simulation: PowerShell Encoded Command Execution

**ATT&CK Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell  
**Detection Rule:** SOC-010  
**Expected Severity:** High  
**Estimated Duration:** 5 minutes  
**Platform:** Windows Victim (192.168.56.20)

---

## Objective

Simulate an attacker using PowerShell with encoded commands to execute a payload, bypassing simple string-based detection. Validate that SOC-010 fires on Sysmon Event ID 1.

---

## Prerequisites

- [ ] Windows Victim VM running
- [ ] Sysmon installed with SwiftOnSecurity config
- [ ] Winlogbeat shipping to Logstash
- [ ] Kibana open on `winlogbeat-*` index

---

## Execution

### Test 1 — Basic Encoded Command

On the Windows Victim, open PowerShell as Administrator:

```powershell
# Encode a simple (harmless) command
$command = "Write-Host 'SOC Lab Simulation - T1059.001'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)

# Execute the encoded command (this is what attackers do)
powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand $encoded
```

### Test 2 — Bypass Execution Policy (Common Attacker Technique)

```powershell
# This pattern appears in many real-world attacks
powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive `
  -EncodedCommand "V3JpdGUtSG9zdCAnU09DIExhYiBTaW11bGF0aW9uJw=="
```

### Test 3 — Atomic Red Team (Preferred)

If Atomic Red Team is installed:

```powershell
# Install Atomic Red Team if not present
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics -Force

# Execute T1059.001 atomics
Invoke-AtomicTest T1059.001
```

---

## Expected Detection Results

| Detection | Expected? | Fired? | Time to Alert |
|-----------|-----------|--------|---------------|
| Sysmon Event ID 1 (Process Create) | Yes | ❓ | |
| SOC-010 Kibana EQL rule | Yes | ❓ | |
| Wazuh Sysmon rule (if configured) | Yes | ❓ | |
| PowerShell Script Block Log (Event 4104) | Yes | ❓ | |

---

## KQL to Verify in Kibana

```kql
winlog.channel: "Microsoft-Windows-Sysmon/Operational"
  AND winlog.event_id: "1"
  AND process.command_line: *EncodedCommand*
```

Also check PowerShell Script Block logs:
```kql
winlog.channel: "Microsoft-Windows-PowerShell/Operational"
  AND winlog.event_id: "4104"
```

---

## Cleanup

```powershell
# No cleanup needed — simulated commands were harmless
# Remove Atomic Red Team artifacts if installed
Remove-Item -Path "$env:TEMP\AtomicRedTeam" -Recurse -Force -ErrorAction SilentlyContinue
```

---

## Findings

*Complete after running simulation.*

**Date run:**  
**Analyst:**  
**Result:** Pass / Fail / Partial

**What fired:**

**What was missed:**

**Time from execution to alert:**

**Detection gaps identified:**

**Follow-up issues:**
- [ ] #
