# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added
- Mermaid architecture and data-flow diagrams, ports table and a "known gaps" section in the architecture overview
- `ioc_enricher.py --demo`: offline mode with bundled synthetic sample data
- Offline test-suite (`tests/`), `Makefile`, dev container, `.env.example`, `.editorconfig`
- Single `ci.yml`: yamllint, ruff, pytest, Sigma check/convert, real Suricata config test, Ansible syntax check

### Changed
- Project moved from a nested `soc-home-lab/` folder to the repository root (workflows were not being picked up)
- README and detection catalog rewritten to describe only what exists; planned rules are listed separately
- ADR-002 and ADR-003 split into their own files (links from the overview were broken)
- T1110.001 is now labelled "Password Guessing" (it was mislabelled "Password Spraying", which is T1110.003)

### Fixed
- Sigma SOC-050: deprecated `count() by` pipe syntax replaced by a correlation rule
- Sigma SOC-010: invalid `2 of selection_*` condition, unused selection and ignored filter; generic `process_creation` log source
- Sigma SOC-051: generic `process_access` log source; tactic tags use the hyphenated form
- Suricata `local.rules`: multi-line rules now use `\` continuation (they could not be parsed otherwise)
- Ansible playbook referenced a non-existent `ossec.conf.j2` template; the task and its handler were removed
- `ioc_enricher.py` crashed on consoles that cannot print non-ASCII verdict icons


### Initial scaffold
- Initial repository scaffold
- Architecture documentation
- Issue templates and GitHub workflows
- CONTRIBUTING guidelines with Conventional Commits spec
- Setup guides for Proxmox, Wazuh, ELK, Suricata, TheHive, MISP

---

*Older entries will appear here as milestones are completed.*
