# 02 — SIEM Server Preparation

## Prerequisites

- SIEM VM running Ubuntu 22.04 LTS Server
- Static IP set to `192.168.56.10`
- Internet access via NAT adapter (for package installation)

---

## 1. System Updates

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git vim net-tools htop unzip gnupg2 ca-certificates lsb-release apt-transport-https
```

---

## 2. Set Hostname

```bash
sudo hostnamectl set-hostname siem-server
```

Add entries to `/etc/hosts`:

```bash
sudo tee -a /etc/hosts <<EOF

# SOC Lab
192.168.56.10  siem-server
192.168.56.20  windows-victim
192.168.56.30  linux-victim
192.168.56.40  kali-attacker
EOF
```

---

## 3. Firewall Configuration

```bash
sudo apt install -y ufw

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# SSH from host only
sudo ufw allow from 192.168.56.0/24 to any port 22

# Wazuh agent communication
sudo ufw allow 1514/udp
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp   # Agent enrollment

# Elasticsearch (internal only)
sudo ufw allow from 192.168.56.0/24 to any port 9200
sudo ufw allow from 192.168.56.0/24 to any port 9300

# Kibana
sudo ufw allow from 192.168.56.0/24 to any port 5601

# Logstash Beats input
sudo ufw allow 5044/tcp

# TheHive
sudo ufw allow from 192.168.56.0/24 to any port 9000

# MISP
sudo ufw allow from 192.168.56.0/24 to any port 443

sudo ufw --force enable
sudo ufw status verbose
```

---

## 4. Increase System Limits for Elasticsearch

```bash
# Set vm.max_map_count (required by Elasticsearch)
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Increase file descriptor limits
sudo tee -a /etc/security/limits.conf <<EOF
elasticsearch soft nofile 65536
elasticsearch hard nofile 65536
wazuh soft nofile 65536
wazuh hard nofile 65536
EOF
```

---

## 5. Create Service Users

```bash
# These will be used by install scripts — create them in advance
sudo useradd -r -s /bin/false elasticsearch 2>/dev/null || true
sudo useradd -r -s /bin/false wazuh 2>/dev/null || true
```

---

## 6. Install Java (required by some components)

```bash
sudo apt install -y openjdk-17-jre-headless
java -version
```

---

## 7. Snapshot

Take a snapshot before proceeding:

```
Snapshot name: "base-os-ready"
```

---

## Validation

```bash
# Confirm hostname
hostname  # should return: siem-server

# Confirm IP
ip a show | grep 192.168.56

# Confirm firewall
sudo ufw status

# Confirm sysctl
sysctl vm.max_map_count  # should return: 262144

# Confirm Java
java -version
```

---

## Next Step

→ [03 — Wazuh Installation](03-wazuh-install.md)
