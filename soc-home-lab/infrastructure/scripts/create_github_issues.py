#!/usr/bin/env python3
"""
create_github_issues.py — SOC Home Lab
========================================
Helper script to bulk-create all project issues and milestones on GitHub
using the GitHub CLI (gh) or REST API.

Run this ONCE after creating your GitHub repository to populate it with
the full issue backlog, milestones, and project board.

Prerequisites:
    pip install PyGithub python-dotenv
    gh auth login  (or set GITHUB_TOKEN in .env)

Usage:
    python3 scripts/create_github_issues.py --repo YOUR_USERNAME/soc-home-lab
    python3 scripts/create_github_issues.py --repo YOUR_USERNAME/soc-home-lab --dry-run
"""

import argparse
import os
import sys
import time

try:
    from github import Github, GithubException
    from dotenv import load_dotenv
except ImportError:
    print("Run: pip install PyGithub python-dotenv")
    sys.exit(1)

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# ─────────────────────────────────────────────
# MILESTONES
# ─────────────────────────────────────────────

MILESTONES = [
    {"title": "M1 — Foundation",           "description": "Repository scaffold, architecture docs, lab networking, VM setup"},
    {"title": "M2 — Core SIEM",            "description": "Wazuh + ELK operational, first logs flowing end-to-end"},
    {"title": "M3 — Log Sources",          "description": "Windows (Sysmon + Winlogbeat), Linux (auditd + Filebeat), Suricata, nginx agents"},
    {"title": "M4 — Detection Engineering","description": "30+ Sigma rules, ATT&CK coverage map, Kibana dashboards"},
    {"title": "M5 — Attack Simulations",   "description": "Atomic Red Team validation of all detections, simulation reports"},
    {"title": "M6 — SOAR & Threat Intel",  "description": "TheHive + Cortex + MISP integration, automated triage workflow"},
    {"title": "M7 — Documentation & Polish","description": "Runbooks, post-mortem reports, demo video, README polish"},
]

# ─────────────────────────────────────────────
# LABELS
# ─────────────────────────────────────────────

LABELS = [
    {"name": "detection",       "color": "e11d48", "description": "Detection rule — new or update"},
    {"name": "infrastructure",  "color": "0ea5e9", "description": "Lab setup, tooling, VM configuration"},
    {"name": "documentation",   "color": "8b5cf6", "description": "Documentation improvement"},
    {"name": "simulation",      "color": "f59e0b", "description": "Attack simulation scenario"},
    {"name": "threat-intel",    "color": "10b981", "description": "MISP / IoC / threat intelligence"},
    {"name": "bug",             "color": "ef4444", "description": "Something is broken"},
    {"name": "enhancement",     "color": "6366f1", "description": "New feature or improvement"},
    {"name": "good first issue","color": "22c55e", "description": "Good entry point for contributors"},
    {"name": "wazuh",           "color": "0891b2", "description": "Wazuh-related"},
    {"name": "elastic",         "color": "fbbf24", "description": "Elasticsearch / Kibana / Logstash"},
    {"name": "suricata",        "color": "a855f7", "description": "Suricata NIDS"},
    {"name": "thehive",         "color": "f97316", "description": "TheHive case management"},
    {"name": "sigma",           "color": "14b8a6", "description": "Sigma detection rules"},
    {"name": "windows",         "color": "3b82f6", "description": "Windows-specific"},
    {"name": "linux",           "color": "84cc16", "description": "Linux-specific"},
    {"name": "mitre-attck",     "color": "dc2626", "description": "MITRE ATT&CK aligned"},
    {"name": "priority:high",   "color": "b91c1c", "description": "High priority"},
    {"name": "priority:medium", "color": "d97706", "description": "Medium priority"},
    {"name": "priority:low",    "color": "65a30d", "description": "Low priority"},
]

# ─────────────────────────────────────────────
# ISSUES
# ─────────────────────────────────────────────

ISSUES = [
    # ── MILESTONE 1: Foundation ──────────────────────────────────────────
    {
        "title": "feat: initialise repository structure and scaffold",
        "body": """## Summary
Create the complete directory structure, base configuration files, and repository metadata.

## Tasks
- [ ] Create all directories per `docs/architecture/01-overview.md`
- [ ] Add `.gitignore`, `LICENSE`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`
- [ ] Add GitHub issue templates (detection-rule, bug, feature, incident)
- [ ] Add PR template
- [ ] Add CI workflows (sigma-validate, markdown-lint, yaml-lint)
- [ ] Pin initial milestones to this issue

## Acceptance Criteria
- All directories exist
- CI pipeline passes on `main`
- README renders correctly on GitHub
""",
        "labels": ["infrastructure", "documentation", "priority:high"],
        "milestone": "M1 — Foundation",
    },
    {
        "title": "docs: write architecture overview and network diagram",
        "body": """## Summary
Document the full lab architecture, network topology, and component roles before any installation begins.

## Tasks
- [ ] Complete `docs/architecture/01-overview.md`
- [ ] Create `docs/architecture/02-network-diagram.md` with ASCII/Mermaid diagram
- [ ] Create `docs/architecture/03-data-flow.md` — log pipeline from source to dashboard
- [ ] Write ADR-001 (Wazuh choice)
- [ ] Write ADR-002 (TheHive choice)
- [ ] Write ADR-003 (Sigma as canonical format)

## Acceptance Criteria
- Architecture doc covers all components, ports, and data flows
- All three ADRs written with context, decision, and consequences
""",
        "labels": ["documentation", "priority:high"],
        "milestone": "M1 — Foundation",
    },
    {
        "title": "infra: provision lab VMs (VirtualBox / Proxmox)",
        "body": """## Summary
Set up all four virtual machines per the architecture spec.

## Tasks
- [ ] Create host-only network (192.168.56.0/24)
- [ ] Provision SIEM Server VM (Ubuntu 22.04, 12GB RAM, 100GB)
- [ ] Provision Windows Victim VM (Windows 10, 4GB RAM, 60GB)
- [ ] Provision Linux Victim VM (Ubuntu 22.04, 2GB RAM, 40GB)
- [ ] Provision Kali Attacker VM (Kali, 4GB RAM, 60GB)
- [ ] Configure static IPs on all VMs
- [ ] Verify network connectivity (ping matrix)
- [ ] Take baseline snapshots of all VMs

## Acceptance Criteria
- All VMs pingable from each other on 192.168.56.0/24
- Snapshots taken named `fresh-install`
""",
        "labels": ["infrastructure", "priority:high"],
        "milestone": "M1 — Foundation",
    },

    # ── MILESTONE 2: Core SIEM ───────────────────────────────────────────
    {
        "title": "feat: install and configure Wazuh Manager",
        "body": """## Summary
Install Wazuh Manager, Wazuh Indexer, and Wazuh Dashboard on the SIEM server.

## Tasks
- [ ] Prepare SIEM server (updates, firewall, sysctl tuning)
- [ ] Run Wazuh all-in-one installer
- [ ] Verify all three services running
- [ ] Access dashboard at https://192.168.56.10
- [ ] Configure log rotation
- [ ] Set up custom rule file (`local_rules.xml`)
- [ ] Deploy `detections/wazuh/local_rules.xml` to manager
- [ ] Take snapshot `wazuh-installed`

Refs: `docs/setup/02-siem-server.md`, `docs/setup/03-wazuh-install.md`
""",
        "labels": ["infrastructure", "wazuh", "priority:high"],
        "milestone": "M2 — Core SIEM",
    },
    {
        "title": "feat: install Elasticsearch, Logstash, and Kibana",
        "body": """## Summary
Install the standalone ELK stack alongside Wazuh for custom log ingestion and dashboards.

## Tasks
- [ ] Add Elastic apt repository
- [ ] Install Elasticsearch on port 9201
- [ ] Install and configure Logstash with Beats input pipeline
- [ ] Install Kibana on port 5601
- [ ] Create index patterns in Kibana
- [ ] Configure ILM policy (30-day retention)
- [ ] Test pipeline with a sample log

Refs: `docs/setup/04-elk-install.md`
""",
        "labels": ["infrastructure", "elastic", "priority:high"],
        "milestone": "M2 — Core SIEM",
    },

    # ── MILESTONE 3: Log Sources ─────────────────────────────────────────
    {
        "title": "feat: deploy Suricata NIDS on Linux Victim",
        "body": """## Summary
Install and configure Suricata on the Linux Victim VM to detect network-level threats.

## Tasks
- [ ] Install Suricata from OISF PPA
- [ ] Run `suricata-update` and enable ET/Open ruleset
- [ ] Configure `HOME_NET`, interface, EVE JSON output
- [ ] Enable Community ID
- [ ] Deploy `detections/suricata/local.rules`
- [ ] Install Filebeat to ship EVE JSON to SIEM
- [ ] Verify `suricata-*` index in Kibana
- [ ] Run test scan from Kali and confirm alert fires

Refs: `docs/setup/05-suricata-install.md`
""",
        "labels": ["infrastructure", "suricata", "priority:high"],
        "milestone": "M3 — Log Sources",
    },
    {
        "title": "feat: configure Windows agent (Sysmon + Winlogbeat + Wazuh)",
        "body": """## Summary
Deploy full telemetry stack on the Windows Victim VM.

## Tasks
- [ ] Install Sysmon with SwiftOnSecurity config
- [ ] Enable PowerShell Script Block Logging (Group Policy / Registry)
- [ ] Enable advanced audit policy (logon, process, object access)
- [ ] Install and configure Winlogbeat
- [ ] Install Wazuh Agent for Windows
- [ ] Verify agent registered on Wazuh Manager
- [ ] Verify `winlogbeat-*` index in Kibana with Sysmon Event IDs
- [ ] Confirm Event ID 1 (Process Create) visible in Kibana

Refs: `docs/setup/07-agents-windows.md`
""",
        "labels": ["infrastructure", "windows", "wazuh", "priority:high"],
        "milestone": "M3 — Log Sources",
    },
    {
        "title": "feat: configure Linux agent (auditd + Filebeat + Wazuh)",
        "body": """## Summary
Deploy full telemetry stack on the Linux Victim VM.

## Tasks
- [ ] Install auditd with ATT&CK-aligned rules (`soc-lab.rules`)
- [ ] Install and configure nginx as a target web app
- [ ] Install Filebeat (auth, nginx, Suricata inputs)
- [ ] Install and configure Wazuh Agent (auditd + FIM)
- [ ] Verify `filebeat-*` index in Kibana with auth and nginx logs
- [ ] Verify Wazuh agent registered and FIM working
- [ ] Test: modify `/etc/hosts` and confirm FIM alert

Refs: `docs/setup/08-agents-linux.md`
""",
        "labels": ["infrastructure", "linux", "wazuh", "priority:high"],
        "milestone": "M3 — Log Sources",
    },

    # ── MILESTONE 4: Detection Engineering ───────────────────────────────
    {
        "title": "[Detection] T1110.001 — SSH Brute Force",
        "body": """## ATT&CK
- **Tactic:** Credential Access
- **Technique:** T1110.001 — Password Spraying (SSH)
- **Rule ID:** SOC-050

## Tasks
- [ ] Review and finalise Sigma rule in `detections/sigma/credential-access/SOC-050-ssh-bruteforce.yml`
- [ ] Add Wazuh XML rule in `detections/wazuh/local_rules.xml` (rule ID 100050)
- [ ] Add Suricata rule in `detections/suricata/local.rules` (SID 9000001)
- [ ] Add EQL query in `detections/elastic/detection-queries.md`
- [ ] Create Kibana threshold rule (5 failures / 60s per source IP)
- [ ] Run simulation: `simulations/manual/01-ssh-bruteforce.md`
- [ ] Update detection catalog

## Acceptance Criteria
- Rule fires within 60 seconds of simulation start
- Alert appears in both Wazuh and Kibana
- TheHive case created automatically
""",
        "labels": ["detection", "sigma", "linux", "mitre-attck", "priority:high"],
        "milestone": "M4 — Detection Engineering",
    },
    {
        "title": "[Detection] T1059.001 — PowerShell Encoded Command",
        "body": """## ATT&CK
- **Tactic:** Execution
- **Technique:** T1059.001 — PowerShell
- **Rule ID:** SOC-010

## Tasks
- [ ] Finalise Sigma rule `detections/sigma/execution/SOC-010-powershell-encoded.yml`
- [ ] Add Kibana EQL rule
- [ ] Add false positive filters (SCCM, Ansible WinRM)
- [ ] Run simulation: `simulations/manual/02-powershell-encoded.md`
- [ ] Update detection catalog
""",
        "labels": ["detection", "sigma", "windows", "mitre-attck", "priority:high"],
        "milestone": "M4 — Detection Engineering",
    },
    {
        "title": "[Detection] T1070.001 — Windows Event Log Cleared",
        "body": """## ATT&CK
- **Tactic:** Defense Evasion
- **Technique:** T1070.001 — Clear Windows Event Logs
- **Rule ID:** SOC-040

## Tasks
- [ ] Finalise Sigma rule `detections/sigma/defense-evasion/SOC-040-log-clearing-windows.yml`
- [ ] Add Kibana EQL rule for Event ID 1102 and 104
- [ ] Test: run `wevtutil cl Security` on Windows Victim and confirm alert fires
- [ ] Update detection catalog
""",
        "labels": ["detection", "sigma", "windows", "mitre-attck", "priority:high"],
        "milestone": "M4 — Detection Engineering",
    },
    {
        "title": "[Detection] T1003.001 — Mimikatz LSASS Memory Access",
        "body": """## ATT&CK
- **Tactic:** Credential Access
- **Technique:** T1003.001 — LSASS Memory
- **Rule ID:** SOC-051

## Tasks
- [ ] Finalise Sigma rule `detections/sigma/credential-access/SOC-051-mimikatz-indicators.yml`
- [ ] Add Kibana EQL rule targeting Sysmon Event ID 10
- [ ] Test with: `Invoke-AtomicTest T1003.001` on Windows Victim
- [ ] Document false positive filters (AV/EDR products)
- [ ] Update detection catalog
""",
        "labels": ["detection", "sigma", "windows", "mitre-attck", "priority:high"],
        "milestone": "M4 — Detection Engineering",
    },
    {
        "title": "feat: build Kibana dashboards for SOC overview",
        "body": """## Summary
Create Kibana dashboards for daily SOC operations.

## Dashboard Panels Required

### 1. SOC Overview Dashboard
- [ ] Alert count by severity (last 24h)
- [ ] Top 10 triggered rules
- [ ] Alert timeline (bar chart, by hour)
- [ ] Top source IPs generating alerts
- [ ] Map of source geolocations

### 2. Windows Endpoint Dashboard  
- [ ] Top processes by count (Sysmon EID 1)
- [ ] PowerShell execution timeline
- [ ] Network connections by destination port
- [ ] Failed logon timeline and heatmap

### 3. Linux Endpoint Dashboard
- [ ] SSH failure rate over time
- [ ] Sudo usage by user
- [ ] nginx 4xx/5xx error rate
- [ ] auditd events by key

### 4. Network / Suricata Dashboard
- [ ] Alert count by Suricata category
- [ ] Top talking pairs (src/dst)
- [ ] Protocol distribution
- [ ] DNS query volume over time

## Acceptance Criteria
- All 4 dashboards created and exportable
- Dashboard NDJSON saved to `dashboards/kibana/`
- Screenshots in `dashboards/screenshots/`
""",
        "labels": ["elastic", "documentation", "priority:medium"],
        "milestone": "M4 — Detection Engineering",
    },

    # ── MILESTONE 5: Attack Simulations ─────────────────────────────────
    {
        "title": "test: run and document SSH brute force simulation",
        "body": "Execute and document simulation per `simulations/manual/01-ssh-bruteforce.md`. Record results, detection gaps, and update catalog.",
        "labels": ["simulation", "linux", "priority:high"],
        "milestone": "M5 — Attack Simulations",
    },
    {
        "title": "test: run and document PowerShell encoded command simulation",
        "body": "Execute and document simulation per `simulations/manual/02-powershell-encoded.md`. Record results using Atomic Red Team T1059.001.",
        "labels": ["simulation", "windows", "priority:high"],
        "milestone": "M5 — Attack Simulations",
    },
    {
        "title": "test: simulate web application attacks (SQLi, XSS, directory traversal)",
        "body": """## Summary
Use tools from Kali to attack the nginx web app on the Linux Victim and validate web-focused detections.

## Tools
- `sqlmap` — automated SQL injection
- `nikto` — web vulnerability scanner
- Manual `curl` requests for path traversal

## Expected Detections
- Suricata local rules: SOC web attack signatures
- nginx error log anomalies in Kibana

Create simulation doc at `simulations/manual/03-web-attacks.md`
""",
        "labels": ["simulation", "suricata", "linux", "priority:medium"],
        "milestone": "M5 — Attack Simulations",
    },

    # ── MILESTONE 6: SOAR & Threat Intel ────────────────────────────────
    {
        "title": "feat: install TheHive 5 and Cortex with analyzers",
        "body": """## Summary
Deploy TheHive case management and Cortex automated enrichment.

## Tasks
- [ ] Install Cassandra
- [ ] Install TheHive 5
- [ ] Install Cortex
- [ ] Install Cortex analyzers (AbuseIPDB, VirusTotal, MaxMind, Shodan)
- [ ] Configure API keys in `.env` (never in repo)
- [ ] Deploy Wazuh → TheHive Python integration script
- [ ] Test: trigger a level 10+ Wazuh alert and confirm TheHive case created

Refs: `docs/setup/06-thehive-misp.md`
""",
        "labels": ["infrastructure", "thehive", "priority:high"],
        "milestone": "M6 — SOAR & Threat Intel",
    },
    {
        "title": "feat: configure MISP with threat intelligence feeds",
        "body": """## Summary
Deploy MISP and configure free threat intelligence feeds.

## Tasks
- [ ] Install MISP (follow official Ubuntu 22.04 installer)
- [ ] Configure feeds: CIRCL OSINT, URLhaus, MalwareBazaar, ET, PhishTank
- [ ] Connect MISP to TheHive
- [ ] Connect MISP to Cortex (MISP_2_0 analyzer)
- [ ] Document feed configuration in `threat-intel/misp-feeds.md`
- [ ] Test: search for a known malicious IP from abuse.ch and confirm hit

Refs: `threat-intel/misp-feeds.md`
""",
        "labels": ["infrastructure", "threat-intel", "priority:high"],
        "milestone": "M6 — SOAR & Threat Intel",
    },

    # ── MILESTONE 7: Documentation & Polish ─────────────────────────────
    {
        "title": "docs: write runbooks for top 5 alert types",
        "body": """## Summary
Write complete incident response runbooks for the five highest-priority detection rules.

## Runbooks Required
- [x] `docs/runbooks/brute-force-ssh.md` — SOC-050 (done)
- [ ] `docs/runbooks/powershell-encoded.md` — SOC-010
- [ ] `docs/runbooks/log-clearing.md` — SOC-040
- [ ] `docs/runbooks/lsass-access.md` — SOC-051
- [ ] `docs/runbooks/web-attack.md` — SOC web detections

Use `docs/runbooks/_template.md` as base.
""",
        "labels": ["documentation", "priority:medium"],
        "milestone": "M7 — Documentation & Polish",
    },
    {
        "title": "docs: generate ATT&CK Navigator coverage layer",
        "body": """## Summary
Create an ATT&CK Navigator layer file showing current detection coverage.

## Tasks
- [ ] Audit all Sigma rules for technique IDs
- [ ] Generate `docs/reports/attck-coverage.json` (Navigator format)
- [ ] Screenshot the coverage heatmap
- [ ] Add to README and detection catalog
- [ ] Target: coverage in at least 5 tactics by M4 completion
""",
        "labels": ["documentation", "mitre-attck", "priority:medium"],
        "milestone": "M7 — Documentation & Polish",
    },
    {
        "title": "docs: write project post-mortem and lessons learned",
        "body": """## Summary
Document the complete project journey: what worked, what didn't, key learnings.

## Sections
- [ ] Lab design decisions (ADR retrospective)
- [ ] Detection engineering challenges
- [ ] False positive management experience
- [ ] Tool integration pain points
- [ ] What I would do differently
- [ ] Skills gained and evidence

Save as `docs/reports/project-retrospective.md`
""",
        "labels": ["documentation", "priority:low"],
        "milestone": "M7 — Documentation & Polish",
    },
]


def create_milestones(repo, dry_run=False):
    milestone_map = {}
    print("\n📍 Creating milestones...")
    for ms in MILESTONES:
        if dry_run:
            print(f"  [DRY RUN] Would create: {ms['title']}")
            milestone_map[ms["title"]] = None
            continue
        try:
            m = repo.create_milestone(title=ms["title"], description=ms["description"])
            milestone_map[ms["title"]] = m
            print(f"  ✅ Created: {ms['title']}")
            time.sleep(0.5)
        except GithubException as e:
            print(f"  ⚠️  Failed: {ms['title']} — {e.data.get('message', e)}")
    return milestone_map


def create_labels(repo, dry_run=False):
    print("\n🏷️  Creating labels...")
    for label in LABELS:
        if dry_run:
            print(f"  [DRY RUN] Would create: {label['name']}")
            continue
        try:
            repo.create_label(name=label["name"], color=label["color"], description=label["description"])
            print(f"  ✅ Created: {label['name']}")
            time.sleep(0.3)
        except GithubException as e:
            if "already_exists" in str(e.data):
                print(f"  ⏭️  Exists: {label['name']}")
            else:
                print(f"  ⚠️  Failed: {label['name']} — {e}")


def create_issues(repo, milestone_map, dry_run=False):
    print(f"\n📋 Creating {len(ISSUES)} issues...")
    for issue_data in ISSUES:
        title = issue_data["title"]
        if dry_run:
            print(f"  [DRY RUN] Would create: {title}")
            continue

        milestone_title = issue_data.get("milestone")
        milestone = milestone_map.get(milestone_title) if milestone_title else None

        label_names = issue_data.get("labels", [])
        labels = []
        for name in label_names:
            try:
                labels.append(repo.get_label(name))
            except GithubException:
                pass

        try:
            issue = repo.create_issue(
                title=title,
                body=issue_data.get("body", ""),
                labels=labels,
                milestone=milestone,
            )
            print(f"  ✅ #{issue.number}: {title}")
            time.sleep(0.8)
        except GithubException as e:
            print(f"  ❌ Failed: {title} — {e}")


def main():
    parser = argparse.ArgumentParser(description="Create SOC Home Lab GitHub issues")
    parser.add_argument("--repo", required=True, help="GitHub repo (e.g. username/soc-home-lab)")
    parser.add_argument("--dry-run", action="store_true", help="Preview without creating")
    args = parser.parse_args()

    if not GITHUB_TOKEN:
        print("Error: Set GITHUB_TOKEN in .env or environment")
        sys.exit(1)

    g = Github(GITHUB_TOKEN)

    try:
        repo = g.get_repo(args.repo)
        print(f"✅ Connected to: {repo.full_name}")
    except GithubException as e:
        print(f"❌ Cannot access repo '{args.repo}': {e}")
        sys.exit(1)

    if args.dry_run:
        print("\n⚠️  DRY RUN MODE — nothing will be created\n")

    milestone_map = create_milestones(repo, args.dry_run)
    create_labels(repo, args.dry_run)
    create_issues(repo, milestone_map, args.dry_run)

    print(f"\n{'='*50}")
    print(f"{'[DRY RUN] Preview complete' if args.dry_run else 'Done!'}")
    print(f"  Milestones: {len(MILESTONES)}")
    print(f"  Labels:     {len(LABELS)}")
    print(f"  Issues:     {len(ISSUES)}")
    if not args.dry_run:
        print(f"\n  View at: https://github.com/{args.repo}/issues")


if __name__ == "__main__":
    main()
