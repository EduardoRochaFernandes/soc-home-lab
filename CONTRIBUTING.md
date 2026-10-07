# Contributing to SOC Home Lab

Thank you for your interest in contributing! This document describes the conventions used throughout this project. Following them keeps the commit history readable and the project professionally structured.

---

## 📋 Table of Contents

- [Commit Messages](#commit-messages)
- [Branch Strategy](#branch-strategy)
- [Pull Request Process](#pull-request-process)
- [Issue Conventions](#issue-conventions)
- [Detection Rule Standards](#detection-rule-standards)
- [Documentation Standards](#documentation-standards)

---

## Commit Messages

This project follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

### Format

```
<type>(<scope>): <short description>

[optional body]

[optional footer: Refs #issue, Closes #issue]
```

### Types

| Type | When to use |
|------|-------------|
| `feat` | A new feature, detection rule, or capability |
| `fix` | A bug fix or correction to an existing rule/config |
| `docs` | Documentation only changes |
| `chore` | Build process, tooling, repo maintenance |
| `test` | Adding or updating simulation/test scenarios |
| `refactor` | Code or config restructuring without behaviour change |
| `ci` | CI/CD pipeline changes |
| `detection` | New or updated detection rule (custom type for this project) |
| `infra` | Infrastructure changes (Ansible, scripts, VM configs) |

### Scopes

`wazuh` · `elastic` · `suricata` · `thehive` · `misp` · `sigma` · `ansible` · `kibana` · `docs` · `ci` · `windows` · `linux`

### Examples

```bash
feat(wazuh): add custom rules for SSH brute force detection

detection(sigma): add T1110.001 - password spraying via failed logons

docs(runbooks): add SSH brute force incident response playbook

fix(suricata): correct threshold in web scan detection rule

infra(ansible): add Wazuh agent role for Ubuntu targets

test(simulations): document Atomic Red Team T1059.001 results

Refs #12
```

---

## Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable, documented, reviewed code only |
| `develop` | Integration branch — PRs merge here first |
| `feature/<name>` | New capability or infrastructure |
| `detection/<attack-id>-<short-name>` | New detection rule |
| `docs/<topic>` | Documentation updates |
| `fix/<issue-number>-<short-name>` | Bug fixes |
| `infra/<component>` | Infrastructure/automation changes |

### Examples

```bash
git checkout -b detection/t1110-001-ssh-bruteforce
git checkout -b feature/thehive-misp-integration
git checkout -b docs/runbook-lateral-movement
git checkout -b infra/ansible-wazuh-agent-role
```

---

## Pull Request Process

1. **Open an issue first** (unless it's a trivial docs fix) — link it in your PR
2. **Use the PR template** — fill in all sections
3. **Keep PRs focused** — one feature or detection per PR
4. **Update documentation** in the same PR that changes behaviour
5. **Add screenshots** for Kibana dashboard changes or new detections firing
6. **Reference ATT&CK** if the PR adds or modifies a detection

### PR Checklist

- [ ] Branch name follows the convention above
- [ ] Commits follow Conventional Commits
- [ ] Relevant documentation updated
- [ ] Detection rules validated against simulation (if applicable)
- [ ] ATT&CK technique ID referenced (if applicable)
- [ ] No secrets or credentials committed

---

## Issue Conventions

Use the provided issue templates:

| Template | When |
|----------|------|
| `detection-rule.yml` | Proposing a new detection rule |
| `bug-report.yml` | Reporting a broken config, rule, or script |
| `feature-request.yml` | Proposing a new capability or integration |
| `incident-report.yml` | Documenting a simulated incident |

### Labels

| Label | Meaning |
|-------|---------|
| `detection` | Related to a detection rule |
| `infrastructure` | Lab setup or tooling |
| `documentation` | Docs improvement |
| `simulation` | Attack simulation scenario |
| `threat-intel` | MISP / IoC related |
| `bug` | Something is broken |
| `good first issue` | Approachable for newcomers |
| `milestone/1` ... `milestone/7` | Milestone tracking |

---

## Detection Rule Standards

All detection rules must:

1. **Map to MITRE ATT&CK** — include Technique ID (e.g., `T1110.001`)
2. **Have a Sigma version** — even if also written in Wazuh XML or Suricata format
3. **Include test case** — documented in `simulations/` showing the rule fires
4. **Include false positive analysis** — what legitimate behaviour could trigger this
5. **Follow the severity scale:**

| Severity | When |
|----------|------|
| `critical` | Active exploitation, confirmed intrusion |
| `high` | Strong indicator of malicious activity |
| `medium` | Suspicious, requires investigation |
| `low` | Informational, context-dependent |
| `informational` | Baseline / telemetry only |

### Sigma Rule Template

```yaml
title: <Descriptive Title>
id: <uuid4>
status: experimental
description: <What this detects and why it matters>
references:
  - <URL to technique or source>
author: <Your name>
date: YYYY/MM/DD
tags:
  - attack.<tactic>
  - attack.t<id>
logsource:
  product: <windows|linux|network>
  service: <sysmon|auditd|suricata|...>
detection:
  selection:
    <field>: <value>
  condition: selection
falsepositives:
  - <List known false positives>
level: <critical|high|medium|low|informational>
```

---

## Documentation Standards

- Write in **plain English**, no unnecessary jargon
- Use **present tense** ("Adds support for..." not "Added support for...")
- Every setup doc should have a **Prerequisites** section and a **Validation** step at the end
- Screenshots should be placed in `docs/screenshots/` and referenced with relative paths
- Runbooks follow the template in `docs/runbooks/_template.md`

---

*Questions? Open a [Discussion](../../discussions) or an issue.*
