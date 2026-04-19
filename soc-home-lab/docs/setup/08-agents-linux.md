# 08 — Linux Agent Setup (auditd + Filebeat + Wazuh)

## Overview

The Linux Victim (`192.168.56.30`) ships:

| Source | Ships via | Content |
|--------|-----------|---------|
| auditd | Wazuh Agent | Syscall auditing, file access, privilege use |
| syslog / auth.log | Filebeat | SSH, sudo, cron, system events |
| nginx access/error | Filebeat | Web application logs |
| Suricata EVE | Filebeat | Network IDS alerts (covered in guide 05) |
| Wazuh Agent | Direct | FIM, policy compliance |

---

## 1. Install and Configure auditd

```bash
sudo apt install -y auditd audispd-plugins
```

### Load Comprehensive Audit Rules

Use the **Linux Audit Framework** rules aligned to MITRE ATT&CK:

```bash
sudo apt install -y git
git clone https://github.com/bfuzzy1/auditd-attack /tmp/auditd-attack
sudo cp /tmp/auditd-attack/auditd-attack.rules /etc/audit/rules.d/audit.rules
```

Or manually create core rules:

```bash
sudo tee /etc/audit/rules.d/soc-lab.rules <<'EOF'
# Delete all existing rules
-D

# Increase buffer size
-b 8192

# Failure mode: 1=log, 2=panic
-f 1

# === Identity and Authentication ===
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# === Privileged Commands ===
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# === Network Configuration ===
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_modifications
-w /etc/hosts -p wa -k network_modifications
-w /etc/network/ -p wa -k network_modifications

# === Systemd / Cron (Persistence) ===
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd_persistence

# === SSH Keys (Persistence) ===
-w /root/.ssh/ -p wa -k ssh_keys
-a always,exit -F arch=b64 -S open -F dir=/home -F name=.ssh -k ssh_keys

# === Execution (T1059) ===
-a always,exit -F arch=b64 -S execve -k execution
-a always,exit -F arch=b32 -S execve -k execution

# === Process Injection / Memory (T1055) ===
-a always,exit -F arch=b64 -S ptrace -k process_injection
-a always,exit -F arch=b64 -S process_vm_writev -k process_injection

# === File Downloads (T1105) ===
-a always,exit -F arch=b64 -S open -F name=wget -k download_tools
-a always,exit -F arch=b64 -S open -F name=curl -k download_tools

# === Kernel Modules (T1547.006) ===
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_modules

# === Make audit config immutable (remove to allow changes without reboot)
# -e 2
EOF
```

```bash
sudo augenrules --load
sudo systemctl enable auditd
sudo systemctl restart auditd

# Verify rules loaded
sudo auditctl -l | head -20
```

---

## 2. Configure rsyslog for Structured Output

```bash
sudo tee /etc/rsyslog.d/50-soc-lab.conf <<EOF
# Forward auth logs to a dedicated file for Filebeat
auth,authpriv.*          /var/log/auth-soc.log
# Forward all logs to local file
*.*                      /var/log/syslog-soc.log
EOF

sudo systemctl restart rsyslog
```

---

## 3. Install and Configure nginx (Target Web App)

```bash
sudo apt install -y nginx

# Create a simple test application
sudo tee /var/www/html/index.html <<EOF
<html><body>
<h1>SOC Lab - Target Web App</h1>
<p>This is a deliberately exposed web application for detection testing.</p>
</body></html>
EOF

# Enable detailed access logging
sudo tee /etc/nginx/conf.d/soc-logging.conf <<EOF
log_format detailed '\$remote_addr - \$remote_user [\$time_local] '
                    '"\$request" \$status \$body_bytes_sent '
                    '"\$http_referer" "\$http_user_agent" '
                    '\$request_time \$upstream_response_time';

access_log /var/log/nginx/access-detailed.log detailed;
error_log /var/log/nginx/error.log warn;
EOF

sudo systemctl enable nginx
sudo systemctl restart nginx
```

---

## 4. Install Filebeat (Linux)

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update && sudo apt install -y filebeat
```

Configure Filebeat:

```bash
sudo tee /etc/filebeat/filebeat.yml <<'EOF'
filebeat.inputs:

# Auth / syslog
- type: log
  id: auth-logs
  enabled: true
  paths:
    - /var/log/auth.log
    - /var/log/auth-soc.log
  fields:
    log_type: auth
    source_host: linux-victim
  fields_under_root: true

# nginx access
- type: log
  id: nginx-access
  enabled: true
  paths:
    - /var/log/nginx/access*.log
  fields:
    log_type: nginx_access
    event.module: nginx
  fields_under_root: true

# nginx error
- type: log
  id: nginx-error
  enabled: true
  paths:
    - /var/log/nginx/error.log
  fields:
    log_type: nginx_error
  fields_under_root: true

# Suricata EVE (from guide 05)
- type: log
  id: suricata-eve
  enabled: true
  paths:
    - /var/log/suricata/eve.json
  json.keys_under_root: true
  json.add_error_key: true
  fields:
    event.module: suricata
  fields_under_root: true

output.logstash:
  hosts: ["192.168.56.10:5044"]

processors:
  - add_host_metadata: ~
  - add_fields:
      target: ''
      fields:
        agent.hostname: linux-victim
        observer.ip: 192.168.56.30

logging.to_files: true
logging.files:
  path: /var/log/filebeat
logging.level: info
EOF
```

```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat

# Test output
sudo filebeat test output
```

---

## 5. Install Wazuh Agent (Linux)

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update && sudo WAZUH_MANAGER="192.168.56.10" apt install -y wazuh-agent
```

### Configure Wazuh Agent for auditd

Edit `/var/ossec/etc/ossec.conf` and add inside `<ossec_config>`:

```xml
<!-- Monitor auditd logs -->
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>

<!-- Monitor auth logs -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>

<!-- File Integrity Monitoring — critical paths -->
<syscheck>
  <directories check_all="yes" report_changes="yes" realtime="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>
  <directories check_all="yes" report_changes="yes">/root/.ssh,/home</directories>
</syscheck>
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

---

## Validation Checklist

- [ ] auditd running, rules loaded (`sudo auditctl -l` shows rules)
- [ ] nginx running, test page accessible at `http://192.168.56.30`
- [ ] Filebeat running, shipping auth, nginx, and Suricata logs
- [ ] `filebeat-*` index in Kibana with nginx and auth events
- [ ] Wazuh agent registered and active on manager
- [ ] FIM events appearing in Wazuh dashboard when files under `/etc` are modified

---

## Next Step

Detection engineering begins! → [Detection Catalog](../detections/catalog.md)
