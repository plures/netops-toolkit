# netops-toolkit

[![Version](https://img.shields.io/github/v/release/plures/netops-toolkit?display_name=tag&sort=semver)](https://github.com/plures/netops-toolkit/releases)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL--1.1-blue.svg)](LICENSE)
[![CI](https://github.com/plures/netops-toolkit/actions/workflows/release.yml/badge.svg)](https://github.com/plures/netops-toolkit/actions/workflows/release.yml)
[![interrogate](https://img.shields.io/badge/interrogate-100%25-brightgreen.svg)](https://interrogate.readthedocs.io)
[![docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://plures.io/netops-toolkit/)

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

Use a reviewed local checkout/archive and an existing compatible Python
environment containing the source host's prerequisites (including PyYAML).
The scripts invoke the registered `netops.setup.main` protected setup host.
They do not acquire Python, elevate, clear environments or edit shell settings.
Full registry selection also retains documentation tooling and the legacy
`[tui,snmp,report,docs]` delivery contract. After successful install/update the
installer offers a separate reviewed-source/new-owned-output strict MkDocs build.
Already installed docs tooling can be used independently:

```bash
NETOPS_DOCS_DIR=/absolute/path/new-owned-doc-output ./install.sh --docs-only
```

```powershell
.\install.ps1 -DocsOnly -DocsDirectory C:\path\new-owned-doc-output
```

Missing tooling or strict source-link errors remain explicit blockers. No global
pip/config/rc changes, new network or existing output/ACL adoption occurs.
The bridge's strict output receipt is not managed-generation/publisher
qualification; independent installed-delivery equivalence remains required.

```bash
./install.sh plan --root /absolute/path/new-owned-root
# After independently obtaining and reviewing an exact local setup descriptor:
./install.sh install --root /absolute/path/new-owned-root --plan-file /absolute/path/plan.json
```

Default selection covers the full native/companion registry; `--enhanced`
adds Molecule. `--capability` deliberately selects a narrower scope. The local
descriptor must bind the complete selected archive and compatible wheel/
collection closure. Missing pins block before root creation. Installed pip uses
offline, hash-required wheels, no dependency resolution/builds/cache, and checks
the resulting exact closure.

Creation, provisioning and activation have separate typed confirmations. Exit
zero requires a succeeded selected lifecycle, not merely a directory or catalog.
**Current limit:** production full-closure locks, clean bootstrap prerequisites,
qualified controller/platform/runtime/service integrations and complete crash
reconciliation remain unfinished. Native offline author execution is not
Ansible/Molecule or platform qualification. See [setup boundaries](docs/api/dependencies.md#guided-protected-source-setup).

### Partial bootstrap and recovery

Existing and partial environments are deliberately retained, not rebuilt on
retry. Keep the prior working environment, inventory, vault, backups and settings.
Do not activate a candidate merely because its directory exists. Reruns accept
only the exact protected setup ownership records; unknown roots are not adopted.
Use `resume --installation-id <id>` for recorded recovery, or reviewed `update`
to register a new descriptor while retaining the prior generation. `restore`
requires actual retained qualification. `uninstall --generation-id <id>` removes
only exact inactive manifest-owned members; active generations, unknown files
and live/crash-held run references block removal. No TTL purge occurs.

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
powershell.exe -NoProfile -File ".\netops-toolkit-<version>\install.ps1" -Action plan
```

Supply `-Python <existing-compatible-python>` when needed and
`-PlanFile <reviewed-local-descriptor>` for provisioning. `-Action` selects plan,
install, update, resume, verify, restore or uninstall. `-InstallRoot` selects the
owned root; `-Capability` narrows selection and `-Enhanced` adds Molecule.
It does not create shortcuts, elevate, configure WSL, install a service or reboot.
Native Windows is not a supported Ansible controller.

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

These explicit development installs do not activate or qualify a managed
controller. Native Windows Ansible controllers are not supported; Linux/macOS
managed controllers and any existing Windows WSL controller still require their
actual consuming-context and platform qualification. Plain pip has no new
post-install acquisition hook.

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

See the [online CLI reference](https://plures.io/netops-toolkit/guides/cli-reference/)
for the verified flags and safe change workflow.

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
tunneling](https://plures.io/netops-toolkit/guides/jump-host-tunnel/). For the
recommended workstation-wide mode, see [Active Bastion Routing](https://plures.io/netops-toolkit/guides/active-bastion/).

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

The [online inventory guide](https://plures.io/netops-toolkit/guides/inventory-management/)
explains all available fields and exports. Never commit passwords or SNMP
community strings to a shared repository; use local inventory files,
environment variables, or the encrypted vault as appropriate.

## Documentation

Browse the complete, release-matched documentation at
[plures.io/netops-toolkit](https://plures.io/netops-toolkit/), including
getting started, command reference, scanner and bastion guides, configuration
changes, and the Python API.

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

netops-toolkit is source-available under the [Business Source License 1.1](LICENSE).
Personal and non-commercial use is permitted under its Additional Use Grant;
production use outside that grant requires a commercial license from Plures. Each released version
changes to Apache License 2.0 no later than four years after its first public
distribution. For commercial terms, contact `licensing@plures.io`.
