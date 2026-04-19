# 05 — Suricata NIDS Setup

## Overview

Suricata runs on the **Linux Victim VM** (`192.168.56.30`) in IDS mode, monitoring all traffic on the lab network interface. Alerts are written to EVE JSON format and shipped to the SIEM via Filebeat.

Architecture:
```
Network traffic → Suricata (Linux Victim) → EVE JSON log → Filebeat → Logstash → Elasticsearch
```

---

## Installation (on Linux Victim — 192.168.56.30)

### 1. Add Suricata PPA and Install

```bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install -y suricata suricata-update
```

### 2. Update Rules

```bash
sudo suricata-update

# List available rule sources
sudo suricata-update list-sources

# Enable Emerging Threats Open ruleset (free, high quality)
sudo suricata-update enable-source et/open
sudo suricata-update
```

---

## Configuration

### 3. Configure Suricata

Find your network interface name:
```bash
ip a  # note the interface on 192.168.56.0/24 — typically enp0s3 or eth0
```

Edit the main config:

```bash
sudo nano /etc/suricata/suricata.yaml
```

Key settings to change:

```yaml
# Line ~12 — set your HOME_NET
vars:
  address-groups:
    HOME_NET: "[192.168.56.0/24]"
    EXTERNAL_NET: "!$HOME_NET"

# Line ~75 — set the interface
af-packet:
  - interface: enp0s3    # <-- your interface name

# Line ~55 — EVE JSON output (ensure enabled)
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
            metadata: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: yes
        - ssh
        - flow
        - netflow
```

### 4. Enable Community ID (for correlation across tools)

```yaml
# In outputs → eve-log section:
community-id: true
```

Community ID generates a consistent hash for a network flow, allowing correlation between Suricata, Zeek, and other tools on the same traffic.

### 5. Performance Tuning for Lab

```yaml
# Reduce CPU usage in lab environment
threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
  detect-thread-ratio: 1.0
```

---

## Start and Enable Suricata

```bash
sudo systemctl enable suricata
sudo systemctl start suricata

# Verify it's running and loading rules
sudo tail -f /var/log/suricata/suricata.log
```

Look for:
```
<Notice> - rule reload complete
<Notice> - all 20000+ signatures loaded
```

---

## Test Suricata is Detecting

```bash
# From Kali, run a simple curl to trigger ET rules
curl http://192.168.56.30/

# From Linux Victim, check for alerts
sudo tail -f /var/log/suricata/eve.json | python3 -m json.tool | grep -A5 '"event_type":"alert"'
```

---

## Install Filebeat to Ship EVE Logs

```bash
# Add Elastic repo (same as SIEM server)
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update && sudo apt install -y filebeat
```

Configure Filebeat for Suricata:

```bash
sudo tee /etc/filebeat/filebeat.yml <<EOF
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/suricata/eve.json
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    event.module: suricata
    event.dataset: suricata.eve
  fields_under_root: true

output.logstash:
  hosts: ["192.168.56.10:5044"]

processors:
  - add_host_metadata: ~
  - add_cloud_metadata: ~
EOF
```

```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat

# Verify shipping
sudo filebeat test output
```

---

## Custom Suricata Rules

Local rules go in `/etc/suricata/rules/local.rules`. These are tracked in this repo at `detections/suricata/`.

```bash
# Symlink repo rules to Suricata rules directory (after repo is cloned)
sudo ln -sf /opt/soc-home-lab/detections/suricata/local.rules /etc/suricata/rules/local.rules

# Add to suricata.yaml rule-files section:
rule-files:
  - suricata.rules
  - local.rules
```

Reload rules without restart:
```bash
sudo kill -USR2 $(pidof suricata)
```

---

## Validation Checklist

- [ ] Suricata running on Linux Victim
- [ ] EVE JSON alerts writing to `/var/log/suricata/eve.json`
- [ ] Community ID enabled
- [ ] ET/Open ruleset loaded (check rule count in log)
- [ ] Filebeat shipping EVE logs to Logstash on SIEM
- [ ] `suricata-*` index appearing in Kibana

---

## Next Step

→ [06 — TheHive & MISP Setup](06-thehive-misp.md)
