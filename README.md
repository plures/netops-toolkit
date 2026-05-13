# netops-toolkit

[![Version](https://img.shields.io/badge/version-0.30.3-blue.svg)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: BSL-1.1](https://img.shields.io/badge/License-BSL--1.1-blue.svg)](LICENSE) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![CI](https://github.com/plures/netops-toolkit/actions/workflows/release.yml/badge.svg)](https://github.com/plures/netops-toolkit/actions)
[![interrogate](https://img.shields.io/badge/interrogate-100%25-brightgreen.svg)](https://interrogate.readthedocs.io)
[![docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://plures.github.io/netops-toolkit/)

Modular network automation utilities for telco operations.

A collection of small, composable Python tools for common network engineering tasks.
Each utility does one thing well and can be combined with others to build workflows.
Designed for telco NOC/engineering teams moving from manual CLI work to automation.

---

## Table of Contents

- [Features](#features)
- [Supported Equipment](#supported-equipment)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Inventory Scan](#inventory-scan)
  - [Config Collection](#config-collection)
  - [Health Checks](#health-checks)
  - [BGP Monitor](#bgp-monitor)
  - [VLAN Audit](#vlan-audit)
  - [Config Diff](#config-diff)
  - [Safe Config Push](#safe-config-push)
  - [Credential Vault](#credential-vault)
  - [Ansible Integration](#ansible-integration)
- [Inventory File Format](#inventory-file-format)
- [Project Structure](#project-structure)
- [Design Principles](#design-principles)
- [Testing](#testing)
- [Contributing](#contributing)
- [Documentation](#documentation)
- [Changelog](#changelog)
- [License](#license)

---

## Features

| Area | Capability |
|------|------------|
| **Discovery** | Ping sweep + SNMP fingerprint → auto-populated inventory |
| **Config backup** | Bulk collection with timestamped snapshots |
| **Health checks** | CPU, memory, interface errors, log analysis across vendors |
| **BGP monitor** | Peer up/down, prefix deviation, flap detection |
| **VLAN audit** | Trunk/access consistency, orphan VLAN detection |
| **Config diff** | Semantic-aware diff (unified / tree / JSON) with security highlighting |
| **Safe push** | Dry-run by default, pre/post health validation, automatic rollback |
| **Change planning** | Risk assessment, step ordering, dry-run simulation |
| **Credential vault** | AES-256-GCM encrypted credential store with env override |
| **Reporting** | HTML/PDF health reports, email scheduling |
| **Ansible bridge** | Dynamic inventory, `netops_facts` module, playbook generator |

---

## Supported Equipment

| Vendor | Platforms | Status |
|--------|-----------|--------|
| Cisco | IOS, IOS-XE, IOS-XR, NX-OS | ✅ Core |
| Nokia | SR OS (SROS), SRL | ✅ Core |
| Brocade | FastIron/ICX (`brocade_fastiron`), Network OS/VDX (`brocade_nos`) | ✅ Core |
| Palo Alto | PAN-OS | ✅ Core |
| Juniper | Junos | ✅ Core |
| Arista | EOS | ✅ Core |
| Generic | Any CLI-based device | ✅ Via raw transport |

### Supported Transport

| Method | Library | Notes |
|--------|---------|-------|
| SSH | Netmiko / Paramiko | Default, recommended |
| SSH2 | Paramiko | Legacy SSH implementations |
| Telnet | Netmiko | Legacy devices, last resort |

---

## Requirements

- Python 3.10 or newer
- Network access to your devices (SSH or Telnet)
- Device credentials (username / password)

Core dependencies (installed automatically):

| Package | Purpose |
|---------|---------|
| `netmiko >= 4.3` | SSH/Telnet device transport |
| `paramiko >= 3.4` | SSH low-level library |
| `pyyaml >= 6.0` | YAML inventory and config parsing |
| `cryptography >= 46` | Credential vault encryption |

---

## Installation

```bash
# Stable install (editable/development)
pip install -e .

# With SNMP support (for inventory auto-discovery)
pip install -e ".[snmp]"

# With Ansible modules
pip install -e ".[ansible]"

# With HTML report generation
pip install -e ".[report]"

# With HTML + PDF report generation
pip install -e ".[report-pdf]"

# All optional extras
pip install -e ".[snmp,ansible,report-pdf]"

# Development (includes pytest, ruff)
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# 1. Create your inventory file
cp examples/inventory.yaml my-inventory.yaml
#    Edit my-inventory.yaml with your device IPs and credentials

# 2. Scan a subnet to discover devices automatically
python -m netops.inventory.scan --subnet 10.0.0.0/24

# 3. Run health checks against your inventory
python -m netops.check.health --inventory my-inventory.yaml

# 4. Back up all device configurations
python -m netops.collect.backup --inventory my-inventory.yaml --output-dir ./backups

# 5. Check interface status
python -m netops.check.interfaces --inventory my-inventory.yaml --down-only
```

---

## Usage

All commands are invoked as Python modules (`python -m <module>`). See
[docs/guides/cli-reference.md](docs/guides/cli-reference.md) for the full
flag reference.

### Inventory Scan

Auto-discover devices on a subnet using ping sweep and SNMP fingerprinting.

```bash
# Scan a /24 and write discovered devices to inventory.yaml
python -m netops.inventory.scan --subnet 10.0.0.0/24 --output inventory.yaml

# SNMP v2c community string (required for vendor detection)
python -m netops.inventory.scan --subnet 10.0.0.0/24 --community public

# Output as JSON for further processing
python -m netops.inventory.scan --subnet 10.0.0.0/24 --json
```

### Config Collection

Back up device running configurations to timestamped files.

```bash
# Collect config from a single device
python -m netops.collect.config --host 10.0.0.1 --vendor cisco_ios \
    --user admin --password secret

# Bulk backup from inventory
python -m netops.collect.backup --inventory inventory.yaml \
    --output-dir ./backups
```

### Health Checks

Run CPU, memory, interface-error, and log checks across your fleet.

```bash
# Check all devices in inventory
python -m netops.check.health --inventory inventory.yaml

# Check a single device
python -m netops.check.health --host 10.0.0.1 --vendor cisco_ios

# JSON output (suitable for monitoring systems)
python -m netops.check.health --inventory inventory.yaml --json

# Exit non-zero if any check fails (for CI / alerting pipelines)
python -m netops.check.health --inventory inventory.yaml --fail-on-alert

# Gather only specific categories
python -m netops.check.health --inventory inventory.yaml --gather cpu,memory
```

Sample output:

```
✅ core-rtr-01 (10.0.0.1) [cisco_ios]
   CPU:    12% (ok)
   Memory: 38% (ok)
   Errors: 0 interface error counters
   Logs:   0 critical messages in last 24h

⚠️  dist-sw-01 (10.0.1.1) [cisco_ios]
   CPU:    91% ← HIGH
   Memory: 45% (ok)
```

### BGP Monitor

Monitor BGP peer state, prefix counts, and flap detection.

```bash
# Monitor all BGP peers in inventory
python -m netops.check.bgp --inventory inventory.yaml

# Specify expected prefix counts per peer
python -m netops.check.bgp --inventory inventory.yaml \
    --expected-prefixes 10.0.0.2=100,10.0.0.3=200

# Alert when prefix count deviates more than 10% from expected
python -m netops.check.bgp --inventory inventory.yaml \
    --prefix-deviation 10 --fail-on-alert
```

### VLAN Audit

Audit VLAN consistency across your switching infrastructure.

```bash
# Audit VLANs on all switches in inventory
python -m netops.check.vlan --inventory inventory.yaml

# Report orphan VLANs (defined but not used on any trunk)
python -m netops.check.vlan --inventory inventory.yaml --orphans

# JSON report
python -m netops.check.vlan --inventory inventory.yaml --json
```

### Config Diff

Compare device configuration snapshots with semantic awareness.

```bash
# Semantic diff (default) — understands config hierarchy
python -m netops.change.diff --before before.txt --after after.txt

# Unified diff (patch-compatible)
python -m netops.change.diff --before before.txt --after after.txt \
    --format unified

# JSON output for CI pipelines
python -m netops.change.diff --before before.txt --after after.txt \
    --format json

# Fail CI if security-sensitive changes are detected
python -m netops.change.diff --before before.txt --after after.txt \
    --fail-on-security
```

### Safe Config Push

Push configuration changes with pre/post health validation and automatic
rollback on failure.

```bash
# Dry run first (default — nothing is changed)
python -m netops.change.push --host 10.0.0.1 --vendor cisco_ios \
    --config changes.txt

# Apply changes (requires explicit --commit flag)
python -m netops.change.push --host 10.0.0.1 --vendor cisco_ios \
    --config changes.txt --commit

# Auto-rollback if post-push health check fails
python -m netops.change.push --host 10.0.0.1 --vendor cisco_ios \
    --config changes.txt --commit --rollback-on-failure
```

### Credential Vault

Store and retrieve device credentials encrypted at rest (AES-256-GCM).

```bash
# Store credentials for a device
python -m netops.core.vault store --host 10.0.0.1 \
    --username admin --password secret

# Retrieve credentials (decrypted to stdout)
python -m netops.core.vault get --host 10.0.0.1

# Override via environment variables (useful in CI)
export NETOPS_CRED_10_0_0_1_USERNAME=admin
export NETOPS_CRED_10_0_0_1_PASSWORD=secret
```

### Ansible Integration

Use netops-toolkit as an Ansible dynamic inventory source or as a collection
of custom modules.

```bash
# Dynamic inventory (use directly with ansible-playbook)
ansible-playbook -i netops/ansible/dynamic_inventory.py site.yml

# Generate remediation playbooks from a health report
python -m netops.playbooks.generator --report health-report.json \
    --output remediation.yml
```

See [docs/guides/auto-inventory.md](docs/guides/auto-inventory.md) for the
full Ansible integration guide.

---

## Inventory File Format

All commands that take `--inventory` accept a YAML file in this format:

```yaml
defaults:
  username: admin          # Default username for all devices
  transport: ssh           # ssh (default) or telnet

devices:
  core-rtr-01:
    host: 10.0.0.1
    vendor: cisco_ios      # See vendor list in Supported Equipment above
    role: core             # core | distribution | access | edge
    site: dc1
    groups: [routers, core, dc1]
    tags:
      environment: production

  dist-sw-01:
    host: 10.0.1.1
    vendor: cisco_ios
    role: distribution
    site: dc1
    transport: telnet      # Per-device override
    port: 23

  paloalto-fw-01:
    host: 10.0.4.1
    vendor: paloalto_panos
    role: edge
    site: dc1
```

Copy [examples/inventory.yaml](examples/inventory.yaml) as a starting point.

---

## Project Structure

```
netops/
  core/           # Connection management, credential vault, base classes
  inventory/      # Device discovery and inventory management
  collect/        # Data collection (configs, state, logs)
  check/          # Health checks, BGP/VLAN/interface validation
  change/         # Safe config changes (diff, push, plan, rollback)
  report/         # HTML/PDF reports, email scheduling, health dashboard
  parsers/        # Vendor-specific CLI output parsers
  templates/      # Vendor-specific command templates
  playbooks/      # Composable multi-step workflows and Ansible integration
  ansible/        # Ansible dynamic inventory and custom modules
```

---

## Design Principles

1. **One script, one job** — each utility is independently useful
2. **Composable** — pipe outputs, chain scripts, build workflows
3. **Safe by default** — read-only unless explicitly told to change
4. **Vendor-agnostic core** — vendor specifics in templates, not logic
5. **Ansible-ready** — structured JSON output that Ansible can consume directly
6. **No magic** — clear, readable Python that a network engineer can modify

---

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run the full test suite
pytest

# Run with coverage report
pytest --cov=netops --cov-report=term-missing

# Run a specific test module
pytest tests/test_health.py -v

# Lint (ruff)
ruff check netops/ tests/
```

Tests live under `tests/` and are colocated by feature area. All tests use
mocks — no real devices are required.

---

## Contributing

1. Fork the repository and create a feature branch.
2. Install dev dependencies: `pip install -e ".[dev]"`
3. Make your changes. Add or update tests under `tests/`.
4. Run `ruff check netops/ tests/` and `pytest` — both must pass.
5. Open a pull request. Include a description of what changed and why.

**Commit style:** Use [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `chore:`, etc.).

Adding a new vendor? See an existing vendor implementation (e.g.
[docs/guides/brocade.md](docs/guides/brocade.md)) for the pattern:
`templates/` → `parsers/` → `check/` → tests.

---

## Documentation

Full guides are in [docs/guides/](docs/guides/):

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/guides/getting-started.md) | Install and run your first command |
| [CLI Reference](docs/guides/cli-reference.md) | Complete flag reference for all commands |
| [Config Collector](docs/guides/config-collector.md) | Bulk configuration backup |
| [Interface Checker](docs/guides/interface-checker.md) | Interface status and error checking |
| [Inventory Management](docs/guides/inventory-management.md) | Build and manage device inventories |
| [Auto-Inventory Pipeline](docs/guides/auto-inventory.md) | Scan → inventory → Ansible bridge |
| [Network Scanner](docs/guides/scan.md) | Subnet scanning and vendor detection |
| [Config Diff Engine](docs/guides/config-diff.md) | Semantic configuration diffing |
| [Brocade Support](docs/guides/brocade.md) | Brocade FastIron/ICX and NOS guide |
| [Palo Alto Support](docs/guides/paloalto.md) | PAN-OS security policy audit guide |
| [Juniper Support](docs/guides/juniper.md) | JunOS health checks guide |

The full **[API Reference](docs/api/README.md)** covers every public class, function, and parameter. A quick summary lives in [`docs/API.md`](docs/API.md).

| Module | Description |
|--------|-------------|
| [Core](docs/api/core.md) | Connection management, inventory, credential vault |
| [Check](docs/api/check.md) | Health, BGP, interface, VLAN, and vendor-specific checks |
| [Change](docs/api/change.md) | Diff engine, change planning, safe push, rollback |
| [Collect](docs/api/collect.md) | Configuration collection and bulk backup |
| [Parsers](docs/api/parsers.md) | Vendor CLI and eAPI output parsers |
| [Playbooks](docs/api/playbooks.md) | Ansible remediation playbook generation |
| [Report](docs/api/report.md) | HTML/PDF reports, health dashboard, email, scheduling |
| [Ansible](docs/api/ansible.md) | Dynamic inventory and Ansible modules |
| [Inventory](docs/api/inventory.md) | Subnet scanner and device discovery |

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a full history of changes.

---

## License


Dual-licensed under [BSL-1.1](LICENSE) and [MIT](LICENSE-MIT). You may choose either license at your option.

