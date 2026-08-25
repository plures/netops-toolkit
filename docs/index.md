# netops-toolkit

`netops-toolkit` is a Python network-automation toolkit for device discovery,
inventory, operational checks, configuration collection, and controlled
changes. The core works on Python 3.9+; the optional Textual TUI needs Python
3.10+.

## Start here

1. Follow [Getting Started](guides/getting-started.md) to install locally and
   create an inventory.
2. Use [CLI Reference](guides/cli-reference.md) for the exact public command
   names and flags.
3. If devices are reachable only through a jump host, start with [Active
   Bastion Routing](guides/active-bastion.md).

## Capabilities

| Area | Primary interfaces |
| --- | --- |
| Discovery | `netops scan`, `python -m netops.inventory.scan` |
| Inventory | YAML/JSON files and `python -m netops.core.inventory export` |
| Operational checks | `netops health`, plus BGP/VLAN/interface and vendor-specific modules |
| Collection | `netops backup`, `python -m netops.collect.config` |
| Change safety | `netops diff`, `netops push`, `netops.change.plan`, `netops.change.rollback` |
| Bastion access | `netops bastion connect/status/disconnect` |
| Reports | Python API and `python -m netops.report.health_dashboard` |

## Install from source

```bash
git clone https://github.com/plures/netops-toolkit.git
cd netops-toolkit
python -m venv .venv
# Activate .venv for your shell, then:
python -m pip install -e ".[tui,snmp,report]"
```

For Linux and macOS, the repository also supplies `install.sh`, which creates
a user-local install at `~/.venv/netops`. See the repository
[README](https://github.com/plures/netops-toolkit#netops-toolkit) for
platform-specific commands and optional extras.

## Documentation map

- [Guides](guides/README.md) — task-oriented documentation
- [CLI Reference](guides/cli-reference.md) — verified command examples
- [API Reference](api/README.md) — public Python modules
- [Scanner](guides/scan.md) — SNMP discovery, file-based inputs, and safe output
- [Configuration changes](api/change.md) — plan, diff, push, and rollback
- [Reports](api/report.md) — API and health-dashboard usage
