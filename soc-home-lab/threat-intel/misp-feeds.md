# Threat Intelligence Feeds — MISP Configuration

This document lists all threat intelligence feeds configured in MISP and their purpose.

---

## Feed Inventory

| Feed Name | URL | Format | Update Freq | Category | Cost |
|-----------|-----|--------|-------------|----------|------|
| CIRCL OSINT | https://www.circl.lu/doc/misp/feed-osint/ | MISP | Daily | General | Free |
| Abuse.ch URLhaus | https://urlhaus.abuse.ch/downloads/misp/ | MISP | Hourly | Malware URLs | Free |
| Abuse.ch MalwareBazaar | https://bazaar.abuse.ch/export/misp/ | MISP | Daily | File Hashes | Free |
| Emerging Threats | https://rules.emergingthreats.net/blockrules/compromised-ips.txt | CSV | Daily | Compromised IPs | Free |
| PhishTank | http://data.phishtank.com/data/online-valid.csv | CSV | Daily | Phishing | Free |
| AlienVault OTX | https://otx.alienvault.com/ | MISP | Real-time | General | Free |

---

## Adding Feeds in MISP

1. Log into MISP at `https://192.168.56.10`
2. Navigate to **Sync Actions → Feeds**
3. Click **Add Feed** or use the feeds list to **Enable** default feeds
4. Set **Input Source** to `Network`
5. Configure the URL and format from the table above
6. Enable **Auto-fetch** with desired frequency

---

## Correlating Feed IoCs with Alerts

When an alert fires in Wazuh/Kibana, extract observables and check against MISP:

### Via TheHive + Cortex
Create a case in TheHive, add the observable, and run the `MISP_2_0` analyzer in Cortex. This queries your local MISP instance automatically.

### Via MISP UI
1. Go to **Event Actions → Search for value**
2. Paste the IP/hash/domain
3. MISP will return any matching events from your feeds

### Via API (Python)

```python
import requests

MISP_URL = "https://192.168.56.10"
MISP_KEY = "YOUR_API_KEY"

def search_misp(value):
    headers = {
        "Authorization": MISP_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payload = {
        "returnFormat": "json",
        "value": value,
        "limit": 10
    }
    r = requests.post(
        f"{MISP_URL}/attributes/restSearch",
        json=payload,
        headers=headers,
        verify=False  # Self-signed cert in lab
    )
    return r.json()

result = search_misp("1.2.3.4")
print(result)
```

---

## IoC Tagging Convention

When creating IoCs from lab simulations, use these tags:

| Tag | When |
|-----|------|
| `tlp:white` | Safe to share publicly |
| `tlp:green` | Share within community |
| `tlp:amber` | Internal use, limited sharing |
| `lab:simulation` | Generated during a lab simulation (not real threat) |
| `lab:validated` | Confirmed malicious in our lab environment |
| `source:wazuh` | Originated from a Wazuh alert |
| `source:suricata` | Originated from a Suricata alert |

---

## Feed Health Monitoring

Check MISP feed sync status weekly:

1. **Sync Actions → Feeds** — verify `Last pulled` dates are current
2. **Event count** should grow over time
3. If a feed stops updating, check the URL is still valid

---

## ATT&CK Mapping of Feed Coverage

| Feed | Primary ATT&CK Categories |
|------|--------------------------|
| URLhaus | T1105 Ingress Transfer, T1071 C2 |
| MalwareBazaar | T1204 User Execution (malicious files) |
| Emerging Threats | T1046 Network Scanning, T1110 Brute Force |
| PhishTank | T1566 Phishing, T1192 Spearphishing |
| OTX | Broad coverage, all tactics |
