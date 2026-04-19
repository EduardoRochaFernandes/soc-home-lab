# 06 — TheHive 5 & MISP Integration

## Overview

TheHive is our case management platform. When Wazuh generates a high-severity alert, a Python integration script creates a case in TheHive automatically. Cortex provides automated enrichment of observables (IPs, hashes, domains). MISP provides threat intelligence feeds.

```
Wazuh Alert → Python Integration → TheHive Case → Cortex Analysis → MISP IoC Lookup
```

---

## Part A — TheHive Installation

### 1. Install Dependencies

```bash
# On SIEM server
sudo apt install -y wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl

# Java 11+
sudo apt install -y openjdk-17-jre-headless
```

### 2. Install Cassandra (TheHive database)

```bash
wget -qO - https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor -o /usr/share/keyrings/cassandra-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/cassandra-keyring.gpg] https://debian.cassandra.apache.org 41x main" | \
  sudo tee /etc/apt/sources.list.d/cassandra.sources.list

sudo apt update && sudo apt install -y cassandra
```

Configure Cassandra for single-node:

```bash
sudo nano /etc/cassandra/cassandra.yaml
```

Change:
```yaml
cluster_name: 'soc-lab'
listen_address: localhost
rpc_address: localhost
seeds: "127.0.0.1:7000"
```

```bash
sudo systemctl enable cassandra
sudo systemctl start cassandra

# Verify (takes ~30s)
nodetool status
```

Expected: `UN  127.0.0.1` (Up/Normal)

### 3. Install TheHive

```bash
wget -qO - https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY | \
  sudo gpg --dearmor -o /usr/share/keyrings/thehive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/thehive-keyring.gpg] https://deb.thehive-project.org release main" | \
  sudo tee /etc/apt/sources.list.d/thehive.list

sudo apt update && sudo apt install -y thehive
```

### 4. Configure TheHive

```bash
sudo tee /etc/thehive/application.conf <<EOF
# Database
db.janusgraph {
  storage {
    backend: cql
    hostname: ["127.0.0.1"]
    cql.cluster-name: soc-lab
    cql.keyspace: thehive
  }
}

# File storage
storage {
  provider: localfs
  localfs.location: /opt/thp/thehive/files
}

# Application
play.http.secret.key: "$(openssl rand -base64 32)"
play.modules.enabled += org.thp.thehive.connector.cortex.CortexConnector

# Cortex connection
cortex {
  servers: [
    {
      name: local
      url: "http://127.0.0.1:9001"
      auth {
        type: bearer
        key: "CORTEX_API_KEY_HERE"  # Update after Cortex install
      }
      wsConfig {}
    }
  ]
}

# MISP connection
misp {
  servers: [
    {
      name: local
      url: "https://127.0.0.1"
      auth {
        type: key
        key: "MISP_API_KEY_HERE"  # Update after MISP install
      }
      wsConfig.ssl.loose.acceptAnyCertificate: true
    }
  ]
}
EOF
```

```bash
sudo mkdir -p /opt/thp/thehive/files
sudo chown -R thehive:thehive /opt/thp/thehive

sudo systemctl enable thehive
sudo systemctl start thehive

# Monitor startup (takes 1-2 minutes)
sudo journalctl -u thehive -f
```

Access TheHive at: `http://192.168.56.10:9000`

Default credentials: `admin@thehive.local` / `secret` — **change immediately**

---

## Part B — Cortex Installation

### 5. Install Cortex

```bash
echo "deb [signed-by=/usr/share/keyrings/thehive-keyring.gpg] https://deb.thehive-project.org release main" | \
  sudo tee /etc/apt/sources.list.d/cortex.list  # same repo

sudo apt update && sudo apt install -y cortex
```

```bash
sudo tee /etc/cortex/application.conf <<EOF
play.http.secret.key: "$(openssl rand -base64 32)"
search.host: ["127.0.0.1:9201"]
analyzer.urls: ["/opt/cortex/analyzers"]
responder.urls: ["/opt/cortex/responders"]
EOF
```

```bash
sudo systemctl enable cortex
sudo systemctl start cortex
```

Access Cortex at: `http://192.168.56.10:9001`

### 6. Install Cortex Analyzers

```bash
sudo pip3 install cortexutils
git clone https://github.com/TheHive-Project/Cortex-Analyzers /opt/cortex/analyzers
cd /opt/cortex/analyzers
sudo pip3 install -r requirements.txt 2>/dev/null || true

# Install per-analyzer requirements
find . -name "requirements.txt" -exec pip3 install -r {} \; 2>/dev/null
```

Enable useful free analyzers in Cortex UI:
- `AbuseIPDB_1_0` — IP reputation
- `Shodan_DNSResolve_1_0` — domain info
- `VirusTotal_GetReport_3_0` — file hash lookup
- `MaxMind_GeoIP_3_0` — IP geolocation
- `Urlscan_io_Search_0_1_0` — URL analysis

---

## Part C — Wazuh → TheHive Integration

### 7. Install Integration Script

```bash
sudo pip3 install requests
```

```bash
sudo tee /var/ossec/integrations/custom-thehive.py <<'SCRIPT'
#!/usr/bin/env python3
"""
Wazuh → TheHive integration
Creates a TheHive alert for every Wazuh alert with level >= 10
"""

import sys
import json
import requests
import datetime

THEHIVE_URL = "http://127.0.0.1:9000"
THEHIVE_API_KEY = "YOUR_THEHIVE_API_KEY"  # Generate in TheHive UI
MIN_LEVEL = 10

def send_to_thehive(alert_data):
    alert = alert_data.get("data", {})
    rule = alert_data.get("rule", {})
    level = rule.get("level", 0)

    if level < MIN_LEVEL:
        return

    title = f"[Wazuh] {rule.get('description', 'Unknown Alert')}"
    description = f"""
## Wazuh Alert

**Rule ID:** {rule.get('id', 'N/A')}
**Level:** {level}
**Agent:** {alert_data.get('agent', {}).get('name', 'N/A')} ({alert_data.get('agent', {}).get('ip', 'N/A')})
**Timestamp:** {alert_data.get('timestamp', 'N/A')}

### Raw Alert
```json
{json.dumps(alert_data, indent=2)}
```
"""

    severity_map = {range(10, 12): 2, range(12, 14): 3, range(14, 20): 4}
    severity = next((v for k, v in severity_map.items() if level in k), 2)

    payload = {
        "title": title,
        "description": description,
        "type": "external",
        "source": "Wazuh",
        "sourceRef": str(alert_data.get("id", "0")),
        "severity": severity,
        "tags": ["wazuh", f"level-{level}", rule.get("groups", [""])[0]],
        "tlp": 2,
        "status": "New"
    }

    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        r = requests.post(f"{THEHIVE_URL}/api/v1/alert", json=payload, headers=headers, timeout=10)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"TheHive integration error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        alert_data = json.load(f)
    send_to_thehive(alert_data)
SCRIPT

sudo chmod +x /var/ossec/integrations/custom-thehive.py
sudo chown root:wazuh /var/ossec/integrations/custom-thehive.py
```

### 8. Configure Wazuh to Use Integration

Add to `/var/ossec/etc/ossec.conf` inside the `<ossec_config>` block:

```xml
<integration>
  <name>custom-thehive</name>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

```bash
sudo systemctl restart wazuh-manager
```

---

## Part D — MISP (abbreviated)

MISP has a complex installer. Use the official script:

```bash
cd /opt
sudo git clone https://github.com/MISP/MISP.git
cd MISP
sudo git checkout tags/$(git tag | tail -1)  # latest stable tag

# Follow official installer for Ubuntu 22.04:
# https://misp.github.io/MISP/
```

After MISP is up, configure feeds in `Administration → Feeds`:
- CIRCL OSINT Feed
- Abuse.ch URLhaus
- Emerging Threats
- PhishTank

---

## Validation Checklist

- [ ] Cassandra running and `nodetool status` shows `UN`
- [ ] TheHive accessible at `http://192.168.56.10:9000`
- [ ] Cortex accessible at `http://192.168.56.10:9001`
- [ ] At least 3 Cortex analyzers enabled and working
- [ ] Wazuh integration script sending alerts to TheHive
- [ ] MISP feeds enabled and syncing

---

## Next Step

→ [07 — Windows Agent Setup (Sysmon + Winlogbeat)](07-agents-windows.md)
