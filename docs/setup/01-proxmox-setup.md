# 01 — Lab Environment Setup (Proxmox / VirtualBox)

## Prerequisites

- Host machine with 32 GB RAM, 500 GB SSD, 8-core CPU
- Proxmox VE 8.x installed **or** VirtualBox 7.x installed on Windows/Linux/macOS
- ISO images downloaded (links below)

### ISO Downloads

| VM | ISO | Source |
|----|-----|--------|
| SIEM Server | Ubuntu 22.04 LTS Server | [ubuntu.com](https://ubuntu.com/download/server) |
| Linux Victim | Ubuntu 22.04 LTS Desktop | [ubuntu.com](https://ubuntu.com/download/desktop) |
| Windows Victim | Windows 10 Enterprise Evaluation | [microsoft.com](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise) |
| Attacker | Kali Linux | [kali.org](https://www.kali.org/get-kali/) |

---

## Network Design

All VMs communicate on a **host-only network** — no internet access, fully isolated.

```
Network:   192.168.56.0/24
Gateway:   192.168.56.1 (host)

SIEM:      192.168.56.10
Windows:   192.168.56.20
Linux:     192.168.56.30
Kali:      192.168.56.40
```

The SIEM server gets a **second NAT adapter** for internet access during installation only. Disable or disconnect it after setup is complete.

---

## Option A: VirtualBox Setup

### 1. Create the Host-Only Network

1. Open VirtualBox → **File → Host Network Manager**
2. Click **Create**
3. Set IPv4 Address: `192.168.56.1`
4. Set IPv4 Network Mask: `255.255.255.0`
5. **Disable DHCP server** (static IPs only)

### 2. Create Each VM

Repeat for each VM with these specs:

#### SIEM Server
```
Name:       soc-siem
Type:       Linux / Ubuntu 22.04 LTS (64-bit)
RAM:        12288 MB (12 GB)
CPUs:       4
Disk:       100 GB (dynamically allocated)
Network 1:  Host-only Adapter → vboxnet0
Network 2:  NAT (for installation only)
```

#### Windows Victim
```
Name:       soc-windows
Type:       Windows 10 (64-bit)
RAM:        4096 MB
CPUs:       2
Disk:       60 GB
Network:    Host-only Adapter → vboxnet0
```

#### Linux Victim
```
Name:       soc-linux
Type:       Linux / Ubuntu 22.04 LTS (64-bit)
RAM:        2048 MB
CPUs:       2
Disk:       40 GB
Network:    Host-only Adapter → vboxnet0
```

#### Kali Attacker
```
Name:       soc-kali
Type:       Linux / Debian (64-bit)
RAM:        4096 MB
CPUs:       2
Disk:       60 GB
Network:    Host-only Adapter → vboxnet0
```

### 3. Configure Static IPs (Ubuntu VMs)

After installing Ubuntu on the SIEM and Linux Victim, set static IPs:

```bash
# Edit Netplan config
sudo nano /etc/netplan/00-installer-config.yaml
```

**SIEM Server (`192.168.56.10`):**
```yaml
network:
  version: 2
  ethernets:
    enp0s3:                      # Host-only adapter
      dhcp4: false
      addresses:
        - 192.168.56.10/24
    enp0s8:                      # NAT adapter (install only)
      dhcp4: true
```

```bash
sudo netplan apply
```

**Linux Victim (`192.168.56.30`):**
```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
      addresses:
        - 192.168.56.30/24
      gateway4: 192.168.56.1
```

### 4. Configure Static IP (Windows Victim)

1. Control Panel → Network and Internet → Network Connections
2. Right-click the adapter → Properties → IPv4
3. Set:
   - IP: `192.168.56.20`
   - Subnet: `255.255.255.0`
   - Gateway: `192.168.56.1`
   - DNS: `192.168.56.10` (SIEM will serve as DNS later if needed)

---

## Option B: Proxmox Setup

### 1. Create Linux Bridge for Lab Network

In Proxmox shell:

```bash
# Add to /etc/network/interfaces
auto vmbr1
iface vmbr1 inet static
    address 192.168.56.1/24
    bridge-ports none
    bridge-stp off
    bridge-fd 0
```

```bash
systemctl restart networking
```

### 2. Upload ISOs

Go to: **Datacenter → local → ISO Images → Upload**

Upload all four ISOs.

### 3. Create VMs

For each VM in Proxmox:
- **OS:** Select uploaded ISO
- **System:** Default (SeaBIOS, q35)
- **Network:** Bridge → `vmbr1` (lab network)
- RAM, CPU, disk as per the table in Option A

For the SIEM, add a **second network device** on `vmbr0` (internet bridge) for installation.

---

## Validation

After all VMs are booted and IPs configured:

```bash
# From SIEM server, ping all VMs
ping -c 2 192.168.56.20   # Windows Victim
ping -c 2 192.168.56.30   # Linux Victim
ping -c 2 192.168.56.40   # Kali

# From Kali, ping SIEM
ping -c 2 192.168.56.10
```

All pings should succeed. If any fail, check:
1. VM is powered on
2. Correct adapter is selected (host-only / vmbr1)
3. Static IP is correctly set
4. Firewall on Windows is not blocking ICMP

---

## Snapshots — Do This Now

Before installing any software, take a snapshot of each VM:

**VirtualBox:**
```
Machine → Take Snapshot → Name: "Fresh Install"
```

**Proxmox:**
```
VM → Snapshots → Take Snapshot → Name: fresh-install
```

This allows you to roll back cleanly if something breaks during installation.

---

## Next Step

→ [02 — SIEM Server Preparation](02-siem-server.md)
