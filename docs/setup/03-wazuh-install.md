# 03 — Wazuh Manager Installation

## Prerequisites

- SIEM server prepared per [02 — SIEM Server Preparation](02-siem-server.md)
- Internet access active on SIEM VM

---

## 1. Install Wazuh Manager

Wazuh provides an assisted installer that handles the full stack. We install only the **manager** component here; Elasticsearch and Kibana are covered in the next guide.

```bash
# Download the Wazuh install script
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml
```

Edit `config.yml` before running:

```yaml
nodes:
  indexer:
    - name: node-1
      ip: 192.168.56.10

  server:
    - name: wazuh-1
      ip: 192.168.56.10

  dashboard:
    - name: dashboard
      ip: 192.168.56.10
```

```bash
# Generate certificates and install all-in-one
sudo bash wazuh-install.sh -a
```

> This installs Wazuh Manager, Wazuh Indexer (Elasticsearch fork), and Wazuh Dashboard. Installation takes 5–15 minutes.

Save the credentials printed at the end:

```
INFO: --- Summary ---
INFO: You can access the web interface https://192.168.56.10
INFO:    User: admin
INFO:    Password: <GENERATED_PASSWORD>
```

Store credentials in your password manager — **never commit them.**

---

## 2. Verify Services

```bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

All three should be `active (running)`.

```bash
# Check manager log for errors
sudo tail -f /var/ossec/logs/ossec.log
```

---

## 3. Enable Services on Boot

```bash
sudo systemctl enable wazuh-manager wazuh-indexer wazuh-dashboard
```

---

## 4. Access the Dashboard

From your host machine browser, navigate to:

```
https://192.168.56.10
```

Accept the self-signed certificate warning and log in with the credentials saved above.

---

## 5. Custom Rule Configuration

Wazuh custom rules live at `/var/ossec/etc/rules/local_rules.xml`. We will add rules incrementally as detections are developed. For now, verify the file exists:

```bash
cat /var/ossec/etc/rules/local_rules.xml
```

Custom rules should use IDs **100000–199999** to avoid conflicts with built-in rules.

---

## 6. Configure Log Rotation

```bash
sudo tee /etc/logrotate.d/wazuh <<EOF
/var/ossec/logs/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    sharedscripts
    postrotate
        /bin/kill -HUP \$(cat /var/ossec/var/run/wazuh-logcollector.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
EOF
```

---

## 7. Snapshot

```
Snapshot name: "wazuh-installed"
```

---

## Validation Checklist

- [ ] `wazuh-manager` service is active and running
- [ ] `wazuh-indexer` service is active and running
- [ ] `wazuh-dashboard` service is active and running
- [ ] Web dashboard accessible at `https://192.168.56.10`
- [ ] No errors in `/var/ossec/logs/ossec.log`
- [ ] `local_rules.xml` exists at `/var/ossec/etc/rules/`

---

## Next Step

→ [04 — Elasticsearch & Kibana Setup](04-elk-install.md)
