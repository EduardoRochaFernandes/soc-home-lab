# Runbook: SSH Brute Force Attack

**Detection Rule:** SOC-050  
**ATT&CK Technique:** T1110.001 — Brute Force: Password Spraying  
**Severity:** High  
**SLA:** Acknowledge within 15 minutes, initial triage within 30 minutes

---

## Overview

SSH brute force attacks involve repeated authentication attempts against an SSH service using a list of credentials. The attacker's goal is typically initial access or lateral movement.

**This runbook covers:**
1. Initial triage and scoping
2. Containment
3. Investigation
4. Remediation
5. Post-incident actions

---

## Step 1 — Initial Triage

### 1.1 Verify the Alert

Open the Wazuh alert or TheHive case. Confirm:

```kql
# In Kibana — search for the source IP
program: sshd AND "Failed password" AND src_ip: <ATTACKER_IP>
```

Key questions:
- [ ] How many failed attempts? (>100 = likely automated)
- [ ] How many unique usernames attempted?
- [ ] Is the source IP internal or external?
- [ ] Is the target host a critical asset?
- [ ] Any **successful** logons from the same IP?

### 1.2 Check for Successful Authentication

```kql
# In Kibana — look for "Accepted" from same IP
program: sshd AND "Accepted" AND src_ip: <ATTACKER_IP>
```

```bash
# On the target host — check auth.log directly
sudo grep "Accepted" /var/log/auth.log | grep <ATTACKER_IP>
```

> ⚠️ **If any successful logon found:** Escalate severity to CRITICAL. Continue with this runbook AND open a new Lateral Movement case.

### 1.3 Identify the Scope

```bash
# On SIEM — check if other hosts are being targeted
sudo grep "Failed password" /var/ossec/logs/alerts/alerts.log | \
  grep <ATTACKER_IP> | awk '{print $NF}' | sort | uniq -c | sort -rn
```

---

## Step 2 — Containment

### 2.1 Block the Source IP at Host Level

```bash
# On the target Linux host
sudo ufw insert 1 deny from <ATTACKER_IP> to any
sudo ufw status numbered
```

### 2.2 Block at Network Level (if Suricata is in IPS mode)

```bash
# Create a local Suricata rule to drop traffic
sudo tee -a /etc/suricata/rules/local.rules <<EOF
drop tcp <ATTACKER_IP> any -> \$HOME_NET 22 (msg:"SOC-LAB: Blocked SSH brute force source"; sid:9000001; rev:1;)
EOF

sudo kill -USR2 $(pidof suricata)
```

### 2.3 Document Containment Action

Update the TheHive case with:
- Action taken
- Timestamp
- Analyst name
- IP blocked

---

## Step 3 — Investigation

### 3.1 Enrich the Source IP

Run in TheHive → Cortex:
- `AbuseIPDB_1_0` — check IP reputation
- `MaxMind_GeoIP_3_0` — geolocation
- `Shodan_DNSResolve_1_0` — reverse DNS

### 3.2 Analyse the Username List

What usernames were attempted?

```bash
sudo grep "Failed password" /var/log/auth.log | \
  grep <ATTACKER_IP> | \
  grep -oP "for \K\S+" | \
  sort | uniq -c | sort -rn | head -20
```

- Common usernames (`admin`, `root`, `ubuntu`) → script kiddie / automated scanner
- Specific internal usernames → targeted attack, possible insider knowledge

### 3.3 Timeline Reconstruction

```bash
# First and last attempt
sudo grep <ATTACKER_IP> /var/log/auth.log | head -1
sudo grep <ATTACKER_IP> /var/log/auth.log | tail -1

# Attempt rate (per minute)
sudo grep "Failed password" /var/log/auth.log | grep <ATTACKER_IP> | \
  awk '{print $1, $2, $3}' | uniq -c
```

### 3.4 Check Other Protocols from Same Source

```kql
# In Kibana — all Suricata events from attacker IP
src_ip: <ATTACKER_IP> AND event_type: *
```

Is the attacker also scanning other ports or attempting other services (RDP, FTP)?

---

## Step 4 — Remediation

### 4.1 Harden SSH Configuration

```bash
sudo nano /etc/ssh/sshd_config
```

Recommended settings:
```conf
# Disable password authentication (use keys only)
PasswordAuthentication no

# Disable root login
PermitRootLogin no

# Limit authentication attempts
MaxAuthTries 3

# Disconnect after 60s if not authenticated
LoginGraceTime 60

# Restrict to specific users (if applicable)
AllowUsers <your_username>
```

```bash
sudo systemctl restart sshd
```

### 4.2 Install fail2ban (if not present)

```bash
sudo apt install -y fail2ban

sudo tee /etc/fail2ban/jail.local <<EOF
[sshd]
enabled = true
maxretry = 5
findtime = 300
bantime = 3600
EOF

sudo systemctl enable fail2ban
sudo systemctl restart fail2ban
```

### 4.3 Rotate SSH Keys (if compromise suspected)

```bash
# Generate new key pair on admin machine
ssh-keygen -t ed25519 -C "admin-key-$(date +%Y%m%d)" -f ~/.ssh/soc_lab_key

# Install new public key
ssh-copy-id -i ~/.ssh/soc_lab_key.pub user@192.168.56.30

# Remove old keys from authorized_keys if present
```

---

## Step 5 — Post-Incident Actions

### 5.1 Close the TheHive Case

Record:
- **Verdict:** True Positive — External SSH Brute Force
- **Root cause:** SSH service exposed to lab network with password auth enabled
- **Impact:** No successful authentication (or document if there was)
- **Containment:** Source IP blocked via ufw
- **Remediation:** Password auth disabled, fail2ban installed

### 5.2 Open Follow-up Issues

If gaps were found during investigation, create GitHub issues:
- Detection gap: [Open Detection Issue](../../issues/new?template=detection-rule.yml)
- Infrastructure hardening: [Open Feature Request](../../issues/new?template=feature-request.yml)

### 5.3 Document IoCs

Add to MISP:
- Source IP as `ip-src` indicator
- Tag with `tlp:white` if safe to share

### 5.4 Lessons Learned

| Question | Answer |
|----------|--------|
| How long from start of attack to alert? | |
| How long from alert to containment? | |
| Were there missed detections? | |
| What would have prevented this? | |
| What runbook updates are needed? | |

---

## Escalation Criteria

Escalate to **Critical Incident** if:
- Any successful SSH logon from the brute-force source IP
- Internal source IP (potential compromised host doing lateral movement)
- Service account or privileged username successfully authenticated
- Attack continues after IP block (multiple source IPs — botnet)

---

## Related Resources

- [Detection Rule SOC-050](../../detections/sigma/credential-access/SOC-050-ssh-bruteforce.yml)
- [Wazuh SSH Brute Force Rules](../../detections/wazuh/)
- [Simulation Scenario](../../simulations/manual/01-ssh-bruteforce.md)
- [MITRE ATT&CK T1110.001](https://attack.mitre.org/techniques/T1110/001/)
