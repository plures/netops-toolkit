# netops-toolkit

Modular network automation utilities for telco operations.

## What This Is

A collection of small, composable Python scripts for common network engineering tasks. Each utility does one thing well and can be combined with others to build workflows.

**Target environment:** Telco NOC/engineering teams moving from manual CLI work to automation.

## Supported Equipment

| Vendor | Platforms | Status |
|--------|-----------|--------|
| Cisco | IOS, IOS-XE, IOS-XR, NX-OS | ✅ Core |
| Nokia | SR OS (SROS), SRL | ✅ Core |
| Brocade | FastIron/ICX (`brocade_fastiron`), Network OS/VDX (`brocade_nos`) | ✅ Core |
| Palo Alto | PAN-OS | ✅ Core |
| Juniper | Junos | 🔜 Planned |
| Arista | EOS | 🔜 Planned |
| Generic | Any CLI-based device | ✅ Via raw transport |

## Supported Auth / Transport

| Method | Library | Notes |
|--------|---------|-------|
| SSH | Netmiko / Paramiko | Default, recommended |
| SSH2 | Paramiko | Legacy SSH implementations |
| Telnet | Telnetlib / Netmiko | Legacy devices, last resort |

## Quick Start

```bash
# Install
pip install -e .

# Or just use individual scripts
python -m netops.inventory.scan --subnet 10.0.0.0/24
python -m netops.collect.config --host router1 --vendor cisco_ios
python -m netops.check.interfaces --host switch1 --down-only
```

## Project Structure

```
netops/
  core/           # Connection management, auth, base classes
  inventory/      # Device discovery, inventory management
  collect/        # Data collection (configs, state, logs)
  check/          # Health checks, validation, compliance
  change/         # Configuration changes (safe, with rollback)
  report/         # Output formatting, reports, diffs
  templates/      # Vendor-specific command templates
  playbooks/      # Composable multi-step workflows
```

## Design Principles

1. **One script, one job** — each utility is independently useful
2. **Composable** — pipe outputs, chain scripts, build workflows
3. **Safe by default** — read-only unless explicitly told to change
4. **Vendor-agnostic core** — vendor specifics in templates, not logic
5. **Ansible-ready** — structured output (JSON) that Ansible can consume
6. **No magic** — clear, readable Python that a network engineer can understand and modify

## Ansible Migration Path

These utilities are designed to work standalone today and integrate with Ansible tomorrow:
- JSON output format compatible with Ansible facts
- Inventory format convertible to Ansible inventory
- Each utility can become an Ansible module with minimal wrapping
- Playbooks map directly to Ansible playbooks

## What Works Today

| Area | Status |
|------|--------|
| Inventory scan (ping sweep + SNMP fingerprint) | ✅ |
| Config collection (backup) | ✅ |
| Interface health checks | ✅ |
| Health checks — CPU, memory, errors, logs (Cisco, Nokia, Brocade, Palo Alto) | ✅ |
| Credential vault (AES-256-GCM) | ✅ |
| Brocade FastIron/ICX & NOS: templates, parsers, health checks, SNMP detection | ✅ |
| Palo Alto PAN-OS: templates, parsers, policy audit, health checks | ✅ |

## License

MIT
