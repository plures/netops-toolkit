# Getting Started

This guide uses only current command-line interfaces. The core toolkit requires
Python 3.9+; install the optional TUI only on Python 3.10+.

## 1. Install

### Windows

```powershell
git clone https://github.com/plures/netops-toolkit.git
cd netops-toolkit
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[snmp]"
netops --help
```

This is a per-user virtual environment and needs no administrator rights. Add
`tui` or `report` to the extras when those features are needed:

```powershell
python -m pip install -e ".[tui,snmp,report]"
```

### Linux and macOS

```bash
curl -sSL https://raw.githubusercontent.com/plures/netops-toolkit/main/install.sh | bash
source ~/.venv/netops/bin/activate
netops --help
```

Or clone the repository and use the same virtual-environment steps as above.

## 2. Create a local inventory

Copy the example before adding any device-specific data:

```bash
cp examples/inventory.yaml my-inventory.yaml
```

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

Use Netmiko device types in `vendor`. Common values are `cisco_ios`,
`cisco_xe`, `cisco_xr`, `cisco_nxos`, `nokia_sros`, `juniper_junos`,
`arista_eos`, `brocade_fastiron`, `brocade_nos`, and `paloalto_panos`.

Keep passwords and SNMP community strings out of shared inventories. For a
single session, use `NETOPS_PASSWORD`:

```bash
export NETOPS_PASSWORD='replace-me'
```

```powershell
$env:NETOPS_PASSWORD = 'replace-me'
```

For stored credentials, initialise the encrypted vault and follow the
[vault reference](../api/core.md#netopscorevault):

```bash
python -m netops.core.vault init
python -m netops.core.vault set --default --user admin
```

## 3. Run a read-only command

Run a health check against the inventory:

```bash
netops health --inventory my-inventory.yaml
```

Or collect a single configuration:

```bash
python -m netops.collect.config \
  --host 10.0.0.1 --vendor cisco_ios --user admin
```

Back up every device in the inventory:

```bash
netops backup --inventory my-inventory.yaml --output ./backups
```

## 4. Discover devices (optional)

Install the `snmp` extra, then scan a management subnet. The community string
is purposeful input for SNMPv2c discovery; pass it at runtime rather than
checking it into source control.

```bash
netops scan --subnet 10.0.0.0/24 --community 'replace-me' --output discovered.json
```

See [Network Scanner](scan.md) for file-based target lists, safe merge
behaviour, output formats, and deep SSH enrichment.

## 5. Use a bastion (optional)

For workstation-wide TCP routing through a bastion, connect once:

```powershell
netops bastion connect --host bastion.example.com --username netops --password-stdin
netops bastion status
```

Then use the normal toolkit commands. No initial inventory or per-command
proxy flag is needed. See [Active Bastion Routing](active-bastion.md) for
transport limitations and host-key behavior.

## Next steps

- [CLI Reference](cli-reference.md) — working commands and flags
- [Configuration Collector](config-collector.md) — collection and backups
- [Inventory Management](inventory-management.md) — filters and exports
- [Active Bastion Routing](active-bastion.md) — connect once, then use normal commands
- [Configuration changes](../api/change.md) — plan and safely apply changes
