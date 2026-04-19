# 04 — Elasticsearch & Kibana (Standalone ELK)

## Overview

Wazuh ships its own Indexer (an Elasticsearch fork) and Dashboard (a Kibana fork). This guide installs a **separate standalone ELK stack** alongside Wazuh to:

- Ingest logs from Filebeat, Winlogbeat, and Suricata independently of Wazuh
- Build custom Kibana dashboards over raw log data
- Run EQL/KQL threat hunting queries on the full log corpus

Both stacks share the same server. Ports are separated to avoid conflict.

| Component | Port |
|-----------|------|
| Wazuh Indexer | 9200 (internal) |
| Standalone Elasticsearch | 9201 |
| Wazuh Dashboard | 443 |
| Standalone Kibana | 5601 |
| Logstash Beats input | 5044 |

---

## 1. Add Elastic Repository

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update
```

---

## 2. Install Elasticsearch

```bash
sudo apt install -y elasticsearch
```

### Configure Elasticsearch

```bash
sudo tee /etc/elasticsearch/elasticsearch.yml <<EOF
cluster.name: soc-lab
node.name: siem-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 192.168.56.10
http.port: 9201
transport.port: 9301
discovery.type: single-node
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
EOF
```

> We disable xpack security for the lab (Wazuh Indexer handles secure agent comms). In production, always enable it.

```bash
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

# Verify
curl http://192.168.56.10:9201
```

Expected response:
```json
{
  "name" : "siem-node-1",
  "cluster_name" : "soc-lab",
  "version" : { ... },
  "tagline" : "You Know, for Search"
}
```

---

## 3. Install Logstash

```bash
sudo apt install -y logstash
```

### Create Beats Input Pipeline

```bash
sudo tee /etc/logstash/conf.d/01-beats-input.conf <<EOF
input {
  beats {
    port => 5044
  }
}
EOF
```

### Create Output Pipeline

```bash
sudo tee /etc/logstash/conf.d/99-output.conf <<EOF
output {
  if [@metadata][pipeline] {
    elasticsearch {
      hosts => ["http://192.168.56.10:9201"]
      manage_template => false
      index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
      pipeline => "%{[@metadata][pipeline]}"
    }
  } else {
    elasticsearch {
      hosts => ["http://192.168.56.10:9201"]
      manage_template => false
      index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
    }
  }
}
EOF
```

### Create Suricata Enrichment Pipeline

```bash
sudo tee /etc/logstash/conf.d/10-suricata.conf <<EOF
filter {
  if [agent][type] == "filebeat" and [event][module] == "suricata" {
    if [event][dataset] == "suricata.eve" {
      mutate {
        add_field => { "[@metadata][pipeline]" => "filebeat-suricata-eve-pipeline" }
      }
    }
  }
}
EOF
```

```bash
sudo systemctl enable logstash
sudo systemctl start logstash

# Check for pipeline errors (takes ~60s to start)
sudo journalctl -u logstash -f
```

---

## 4. Install Kibana

```bash
sudo apt install -y kibana
```

### Configure Kibana

```bash
sudo tee /etc/kibana/kibana.yml <<EOF
server.port: 5601
server.host: "192.168.56.10"
server.name: "soc-lab-kibana"
elasticsearch.hosts: ["http://192.168.56.10:9201"]
logging.appenders.file.type: file
logging.appenders.file.fileName: /var/log/kibana/kibana.log
logging.appenders.file.layout.type: json
logging.root.appenders: [default, file]
EOF
```

```bash
sudo mkdir -p /var/log/kibana
sudo chown kibana:kibana /var/log/kibana

sudo systemctl enable kibana
sudo systemctl start kibana
```

Kibana takes ~2 minutes to start. Check progress:

```bash
sudo journalctl -u kibana -f
```

Once started, access at: `http://192.168.56.10:5601`

---

## 5. Create Index Patterns in Kibana

Navigate to **Stack Management → Index Patterns** and create:

| Pattern | Time Field |
|---------|-----------|
| `filebeat-*` | `@timestamp` |
| `winlogbeat-*` | `@timestamp` |
| `suricata-*` | `@timestamp` |

---

## 6. Install Index Lifecycle Policies

To prevent disk exhaustion, set a 30-day retention policy:

Go to **Stack Management → Index Lifecycle Policies → Create Policy**:

```json
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "10gb",
            "max_age": "1d"
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

---

## Validation Checklist

- [ ] Elasticsearch responding at `http://192.168.56.10:9201`
- [ ] Logstash running with no pipeline errors
- [ ] Kibana accessible at `http://192.168.56.10:5601`
- [ ] Index patterns created in Kibana
- [ ] ILM policy applied

---

## Next Step

→ [05 — Suricata NIDS Setup](05-suricata-install.md)
