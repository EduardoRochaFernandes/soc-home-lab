# 07 — Windows Agent Setup (Sysmon + Winlogbeat + Wazuh)

## Overview

The Windows Victim (`192.168.56.20`) ships enhanced telemetry to the SIEM using three complementary tools:

| Tool | What it collects |
|------|-----------------|
| Sysmon | Process creation, network connections, file creates, registry, WMI |
| Winlogbeat | Windows Event Logs (Security, System, Application, PowerShell) |
| Wazuh Agent | FIM, vulnerability scanning, Wazuh rule processing on-host |

---

## 1. Install Sysmon

### Download

Download from Microsoft Sysinternals: https://docs.microsoft.com/sysinternals/downloads/sysmon

Or from PowerShell:
```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"
```

### Use SwiftOnSecurity Config (gold standard)

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
  -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"
```

### Install

```powershell
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i .\sysmonconfig.xml
```

Verify:
```powershell
Get-Service Sysmon64
# Status should be: Running
```

Check events:
```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
  Format-List TimeCreated, Id, Message
```

---

## 2. Enable Critical Windows Event Logs

Run in PowerShell as Administrator:

```powershell
# Enable PowerShell Script Block Logging
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $path -Force
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1

# Enable PowerShell Module Logging
$path2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $path2 -Force
Set-ItemProperty -Path $path2 -Name "EnableModuleLogging" -Value 1

# Enable Command Line Auditing in Process Creation events
$path3 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $path3 -Force
Set-ItemProperty -Path $path3 -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1

# Enable Audit Policy — Security events
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Account Management" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Process Tracking" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable

Write-Host "Audit policies configured."
```

---

## 3. Install Winlogbeat

### Download and Extract

```powershell
$version = "8.12.0"
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-$version-windows-x86_64.zip" `
  -OutFile "$env:TEMP\winlogbeat.zip"
Expand-Archive "$env:TEMP\winlogbeat.zip" -DestinationPath "C:\Program Files\Winlogbeat"
Rename-Item "C:\Program Files\Winlogbeat\winlogbeat-$version-windows-x86_64" "C:\Program Files\Winlogbeat\winlogbeat"
```

### Configure Winlogbeat

Create `C:\Program Files\Winlogbeat\winlogbeat\winlogbeat.yml`:

```yaml
winlogbeat.event_logs:
  - name: Application
    ignore_older: 72h
  - name: System
    ignore_older: 72h
  - name: Security
    ignore_older: 72h
  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 72h
  - name: Microsoft-Windows-PowerShell/Operational
    ignore_older: 72h
  - name: Windows PowerShell
    ignore_older: 72h
  - name: Microsoft-Windows-WMI-Activity/Operational
    ignore_older: 72h
  - name: Microsoft-Windows-TaskScheduler/Operational
    ignore_older: 72h

output.logstash:
  hosts: ["192.168.56.10:5044"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded

logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\Logs
logging.level: info
```

### Install as Service

```powershell
cd "C:\Program Files\Winlogbeat\winlogbeat"

# Test config
.\winlogbeat.exe test config -c .\winlogbeat.yml

# Test output connectivity
.\winlogbeat.exe test output -c .\winlogbeat.yml

# Install service
PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
Start-Service winlogbeat
Set-Service winlogbeat -StartupType Automatic

Get-Service winlogbeat
```

---

## 4. Install Wazuh Agent

### Download

```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi" `
  -OutFile "$env:TEMP\wazuh-agent.msi"
```

### Install with Manager IP

```powershell
msiexec.exe /i "$env:TEMP\wazuh-agent.msi" `
  WAZUH_MANAGER="192.168.56.10" `
  WAZUH_AGENT_GROUP="windows" `
  WAZUH_REGISTRATION_SERVER="192.168.56.10" `
  /qn
```

### Start Service

```powershell
NET START WazuhSvc
Set-Service WazuhSvc -StartupType Automatic
```

Verify agent registered on SIEM:

```bash
# On SIEM server
sudo /var/ossec/bin/agent_control -l
```

---

## 5. Firewall Rules (Windows)

```powershell
# Allow Wazuh agent communication
New-NetFirewallRule -DisplayName "Wazuh Agent Outbound" `
  -Direction Outbound -Protocol TCP `
  -RemoteAddress 192.168.56.10 -RemotePort 1514,1515 `
  -Action Allow

# Allow Winlogbeat/Logstash
New-NetFirewallRule -DisplayName "Winlogbeat Outbound" `
  -Direction Outbound -Protocol TCP `
  -RemoteAddress 192.168.56.10 -RemotePort 5044 `
  -Action Allow
```

---

## Validation Checklist

- [ ] Sysmon service running, events appearing in Event Viewer under `Microsoft-Windows-Sysmon/Operational`
- [ ] PowerShell Script Block Logging enabled (check registry)
- [ ] Winlogbeat service running, shipping events
- [ ] Wazuh agent registered on manager (`sudo /var/ossec/bin/agent_control -l`)
- [ ] `winlogbeat-*` index appearing in Kibana with Sysmon Event IDs
- [ ] Event ID 1 (Process Create) visible in Kibana

---

## Key Sysmon Event IDs Reference

| Event ID | Description | ATT&CK Relevance |
|----------|-------------|-----------------|
| 1 | Process Create | T1059 Execution |
| 3 | Network Connection | T1071 C2 |
| 7 | Image Loaded (DLL) | T1055 Process Injection |
| 8 | CreateRemoteThread | T1055 Process Injection |
| 10 | ProcessAccess | T1003 Credential Dumping |
| 11 | FileCreate | T1105 Ingress Tool Transfer |
| 12/13 | Registry Events | T1547 Boot Persistence |
| 17/18 | Pipe Events | T1021 Lateral Movement |
| 22 | DNS Query | T1071 C2/DNS |
| 25 | ProcessTampering | T1562 Defense Evasion |

---

## Next Step

→ [08 — Linux Agent Setup (auditd + Filebeat)](08-agents-linux.md)
