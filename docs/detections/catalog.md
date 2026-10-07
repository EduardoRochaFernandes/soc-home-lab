# Detection Catalog

This catalog lists what actually exists in `detections/` and what is still only planned.

**Nothing here has been validated against a live attack yet.** The simulation playbooks in
[`simulations/manual/`](../../simulations/manual/) describe how to do it; the results have not been recorded in this repository.

**What CI checks:** Sigma rules parse and pass `sigma check` (ATT&CK tag validation excluded, see the workflow comment),
the Wazuh XML is well-formed with unique rule IDs, and the Suricata local rules are syntax-checked by a real Suricata binary.
That proves the files are valid, not that the detections fire.

**Rule format:** rules are authored in [Sigma](https://github.com/SigmaHQ/sigma) where the log source allows it. See the
[Rule Writing Guide](rule-writing-guide.md) and [ADR-003](../architecture/adr/ADR-003-sigma-canonical-format.md).

---

## Implemented

### Sigma rules (`detections/sigma/`)

| Rule ID | Title | Technique | Log source | Level | Validated on a live lab |
|---------|-------|-----------|------------|-------|-------------------------|
| [SOC-010](../../detections/sigma/execution/SOC-010-powershell-encoded.yml) | PowerShell Encoded Command Execution | T1059.001 | Windows process creation (Sysmon EID 1) | High | No |
| [SOC-040](../../detections/sigma/defense-evasion/SOC-040-log-clearing-windows.yml) | Windows Security Event Log Cleared | T1070.001 | Windows Security / System | Critical | No |
| [SOC-050](../../detections/sigma/credential-access/SOC-050-ssh-bruteforce.yml) | SSH Brute Force (event-count correlation) | T1110.001 | Linux auth.log | High | No |
| [SOC-051](../../detections/sigma/credential-access/SOC-051-mimikatz-indicators.yml) | Mimikatz LSASS Memory Access | T1003.001 | Sysmon process access (EID 10) | Critical | No |

### Wazuh rules (`detections/wazuh/local_rules.xml`)

Hand-written Wazuh XML. The rule IDs are in the local range 100000-199999. Not loaded into a Wazuh manager by CI.

| Wazuh ID(s) | Catalog ID | What it matches | Technique |
|-------------|------------|-----------------|-----------|
| 100050, 100051 | SOC-050 | Repeated SSH failures / invalid users from one IP | T1110.001, T1110.003 |
| 100040, 100041 | SOC-041 | auditd stopped or reconfigured | T1562.012 |
| 100020 | SOC-020 | Cron modification (auditd key `cron`) | T1053.003 |
| 100022 | SOC-022 | `authorized_keys` changed (syscheck) | T1098.004 |
| 100052 | SOC-052 | Access to `/etc/shadow`, `/etc/passwd` | T1003.008 |
| 100030 | SOC-030 | sudo used to spawn a shell or interpreter | T1548.003 |
| 100012 | SOC-012 | Reverse-shell patterns in audited commands | T1059.004 |
| 100080 | SOC-080 | Archive utility execution (data staging hint) | T1074 |
| 100060 | SOC-060 | Network scanning tool executed on a host | T1046 |
| 100100 | - | Kernel module load/unload | T1547.006 |
| 100200, 100201 | - | File-integrity changes to critical files and system binaries | T1543 (100201) |

### Suricata rules (`detections/suricata/local.rules`)

SIDs 9000001-9099999. SSH and RDP brute force, Nmap SYN/version scans, outbound connections to common C2 ports, DNS tunnelling
heuristics, SQL injection / XSS / directory traversal in HTTP URIs, a `python-requests` user-agent heuristic and HTTP on
non-standard ports.

---

## Planned (not written yet)

These IDs were reserved when the project was scaffolded. There is no rule file for any of them.

| Rule ID | Idea | Technique |
|---------|------|-----------|
| SOC-001 | Web shell upload via nginx | T1505.003 |
| SOC-002 | HTTP error spike on a public-facing app | T1190 |
| SOC-011 | PowerShell script block logging, suspicious keywords | T1059.001 |
| SOC-013 | WMI process execution | T1047 |
| SOC-021 | New Windows service created | T1543.003 |
| SOC-031 | SUID binary execution | T1548.001 |
| SOC-042 | File timestamp modification (timestomping) | T1070.006 |
| SOC-061 | Active Directory enumeration | T1087.002 |
| SOC-070 | PsExec / remote execution | T1021.002 |
| SOC-071 | RDP brute force (Windows side) | T1110.001 |
| SOC-090 | DNS tunnelling (needs Zeek or Suricata DNS logs) | T1048.003 |

Sigma versions of the Wazuh-only rules above (SOC-012, 020, 022, 030, 041, 052, 060, 080) are also still to do.

---

## Notes on ATT&CK tags

Sigma tactic tags use hyphens (`attack.credential-access`). The ATT&CK knowledge base keeps evolving; recent versions
reorganised "Defense Evasion", so `sigma check`'s tag validator (which downloads the latest ATT&CK data) rejects tags that were
valid when the rules were written. CI therefore excludes that one validator rather than failing on upstream taxonomy changes.

## Adding new rules

See the [Rule Writing Guide](rule-writing-guide.md) and open a
[Detection Rule issue](https://github.com/EduardoRochaFernandes/soc-home-lab/issues/new?template=detection-rule.yml).
