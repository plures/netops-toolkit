# netops-toolkit

[![Version](https://img.shields.io/github/v/release/plures/netops-toolkit?display_name=tag&sort=semver)](https://github.com/plures/netops-toolkit/releases)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: BSL-1.1](https://img.shields.io/badge/License-BSL--1.1-blue.svg)](LICENSE) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE-MIT)
[![CI](https://github.com/plures/netops-toolkit/actions/workflows/release.yml/badge.svg)](https://github.com/plures/netops-toolkit/actions/workflows/release.yml)
[![interrogate](https://img.shields.io/badge/interrogate-100%25-brightgreen.svg)](https://interrogate.readthedocs.io)
[![docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://plures.github.io/netops-toolkit/)

Network automation utilities for discovery, inventory, configuration collection,
health checks, safe configuration changes, and vendor-aware parsing. The core
CLI supports Python 3.9 or later; the optional Textual TUI requires Python 3.10
or later.

## What is included

| Area | Supported interface |
| --- | --- |
| Discovery | Ping, SNMPv2c, CDP/LLDP, and optional SSH enrichment |
| Inventory | YAML/JSON inventory, filtering, and Ansible export |
| Operations | Health, BGP, VLAN, interface checks, config collection, and backups |
| Changes | Semantic diff, dry-run-safe push, rollback, and change plans |
| Access | Direct SSH/Telnet, per-device jump hosts, and active bastion routing |
| Optional tools | Textual TUI, reports, and Ansible helpers |

Supported Netmiko device types include Cisco IOS/IOS-XE/IOS-XR/NX-OS, Nokia SR
OS/SRL, Brocade FastIron/NOS, Palo Alto PAN-OS, Juniper Junos, and Arista EOS.
Use the exact device type expected by Netmiko in `vendor` fields.

## Install

### Linux and macOS

The maintained installer creates a user-local environment at `~/.venv/netops`
and installs the TUI, scanning, and HTML report extras. It selects the newest
compatible installed Python (3.9+) for that environment, so `netops` and
`netops-tui` use the same interpreter. If no compatible Python is installed,
`uv` provisions one. It does not require `sudo`.

```bash
curl -sSL https://raw.githubusercontent.com/plures/netops-toolkit/main/install.sh | bash
source ~/.venv/netops/bin/activate
netops --help
```

For an offline installation, download and extract a release archive, then run
`./install.sh` from its root.

### Linux disk quota or no-space recovery

If `uv` reports `Disk quota exceeded` or `No space left on device`, the install
did not complete; activate neither the partial environment nor an unrelated
`/home/...` path. Confirm the actual home directory with `echo "$HOME"`, then
free the uv cache and retry:

```bash
deactivate 2>/dev/null || true
uv cache clean
quota -s 2>/dev/null || true
df -h "$HOME" /tmp
curl -sSL https://raw.githubusercontent.com/plures/netops-toolkit/main/install.sh | bash
source "$HOME/.venv/netops/bin/activate"
netops --help
```

When your home directory cannot hold the environment, place both the virtual
environment and uv cache on a filesystem with adequate user quota:

```bash
export NETOPS_VENV_DIR=/path/with/space/netops
export NETOPS_UV_CACHE_DIR=/path/with/space/netops-uv-cache
curl -sSL https://raw.githubusercontent.com/plures/netops-toolkit/main/install.sh | bash
source "$NETOPS_VENV_DIR/bin/activate"
```

### Windows and source development

Clone the repository and install into a virtual environment. This is a
per-user operation; an elevated shell is not required.

```powershell
git clone https://github.com/plures/netops-toolkit.git
cd netops-toolkit
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[tui,snmp,report]"
netops --help
```

### Windows

Download the ZIP from [Releases](https://github.com/plures/netops-toolkit/releases), extract it, then run in PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\netops-toolkit-<version>\install.ps1"
```

The installer finds the newest compatible Python (3.9+) registered on the machine, then creates a virtual environment under `%LOCALAPPDATA%\netops-toolkit`. Both `netops` and `netops-tui` run from that same environment. It adds a per-user Start menu shortcut and does not require administrator rights.

To see which interpreter the installer will use without making changes:

```powershell
.\install.ps1 -CheckPython
```

The installed `netops` and `netops-tui` launchers use that managed environment.
When running `python -m netops` directly, Python necessarily uses the
interpreter that you explicitly invoked.

### Manual install from source (if you prefer)

```bash
python3 -m venv ~/.venv/netops
source ~/.venv/netops/bin/activate
pip install -e ".[tui]"          # Textual terminal UI
pip install -e ".[snmp]"         # SNMP discovery
pip install -e ".[report]"       # HTML report API
pip install -e ".[report-pdf]"   # HTML and PDF report API
pip install -e ".[ansible]"      # Ansible helpers
pip install -e ".[dev]"          # test and lint tooling
```

## First run

Copy the example inventory and replace the sample addresses and credentials.

```bash
cp examples/inventory.yaml my-inventory.yaml
netops health --inventory my-inventory.yaml
netops backup --inventory my-inventory.yaml --output ./backups
```

For a single device, the module-level collector is the direct interface:

```bash
python -m netops.collect.config \
  --host 10.0.0.1 --vendor cisco_ios --user admin
```

Supply `NETOPS_PASSWORD` rather than placing a password in shell history:

```bash
export NETOPS_PASSWORD='replace-me'
netops health --host 10.0.0.1 --vendor cisco_ios --user admin
```

On PowerShell:

```powershell
$env:NETOPS_PASSWORD = 'replace-me'
```

## Command map

`netops --help` currently lists `netops report`, but that dispatcher command is not
usable because `netops.report.generator` has no CLI entry point. Use the report
Python API or `python -m netops.report.health_dashboard` instead.

| Command | What it does |
| --- | --- |
| `netops scan` | Discover devices; use `netops scan --help` for scan flags |
| `netops health` | Run cross-vendor CPU, memory, interface, and log checks |
| `netops backup` | Collect timestamped configuration backups from inventory |
| `netops push` | Dry-run-safe configuration push; requires `--commit` to modify a device |
| `netops diff` | Compare configuration files semantically or as unified/JSON diff |
| `netops bastion` | Connect, check, or disconnect the workstation-wide SSH bastion |
| `netops tui` / `netops-tui` | Launch the optional Textual TUI |

Additional documented module CLIs include:

```bash
python -m netops.check.bgp --inventory my-inventory.yaml
python -m netops.check.vlan --inventory my-inventory.yaml --expected-vlans 10,20,30-50
python -m netops.check.interfaces --host 10.0.0.1 --vendor cisco_ios
python -m netops.change.plan plan --host 10.0.0.1 --desired desired.cfg --export plan.json
python -m netops.core.vault init
```

See the [CLI reference](docs/guides/cli-reference.md) for the verified flags
and safe change workflow.

## Active bastion routing

Select a reachable SSH bastion once, then normal TCP device connections from
the toolkit are routed through it. No device inventory is required up front.

```powershell
netops bastion connect --host bastion.example.com --username netops --password-stdin
netops bastion status
```

The password is read from standard input and is not stored in the active
bastion state file. Use `netops bastion disconnect` when the route is no
longer required. SSH forwarding is TCP-only: scan traffic behind an active
bastion uses SSH discovery rather than local ICMP/UDP SNMP probing.

For a per-device compatibility configuration, see [SSH jump-host
tunneling](docs/guides/jump-host-tunnel.md). For the recommended
workstation-wide mode, see [Active Bastion Routing](docs/guides/active-bastion.md).

## Inventory format

```yaml
defaults:
  username: admin
  transport: ssh

devices:
  core-rtr-01:
    host: 10.0.0.1
    vendor: cisco_ios
    role: core
    site: dc1
    groups: [routers, core]
```

The [inventory guide](docs/guides/inventory-management.md) explains all
available fields and exports. Never commit passwords or SNMP community strings
to a shared repository; use local inventory files, environment variables, or
the encrypted vault as appropriate.

## Documentation

- [Getting started](docs/guides/getting-started.md)
- [CLI reference](docs/guides/cli-reference.md)
- [Scanner guide](docs/guides/scan.md)
- [Active bastion routing](docs/guides/active-bastion.md)
- [Configuration changes](docs/api/change.md)
- [Python API reference](docs/api/README.md)

Build the documentation site locally with `pip install -e ".[docs]"` followed
by `mkdocs build --strict`.

## Development

```bash
pip install -e ".[dev,tui]"
python -m pytest
ruff check netops tests
```

Focused tests do not contact real devices. Some optional TUI and scanner tests
require their corresponding extras.

## License

See [LICENSE](LICENSE).
