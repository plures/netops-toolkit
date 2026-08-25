# CLI Reference

This reference follows the commands implemented in the current source tree.
Use `--help` on the installed version for the authoritative, version-specific
argument list.

## Dispatcher

```text
netops <command> [options]
```

| Command | Delegates to |
| --- | --- |
| `scan` | `netops.inventory.scan` |
| `health` | `netops.check.health` |
| `backup` | `netops.collect.backup` |
| `push` | `netops.change.push` |
| `diff` | `netops.change.diff` |
| `tui` | Optional Textual TUI |
| `bastion` | Active bastion management |

`netops report` is currently not a working command-line entry point. Use the
[report Python API](../api/report.md) or `netops.report.health_dashboard`.

## Discovery

```bash
netops scan --subnet 10.0.0.0/24 --community 'community-string' --output discovered.json
```

At least one target source is required. `--subnet` cannot be combined with `--csv` or `--hosts-file`; if both file options are supplied, `--csv` takes precedence.

| Flag | Meaning |
| --- | --- |
| `--subnet CIDR` | Scan a CIDR network |
| `--csv FILE` | Read addresses from a CSV `ip`, `host`, `hostname`, or `address` column |
| `--hosts-file FILE` | Read one address per line; CSV is also accepted |
| `--community STRING` | SNMPv2c community; default is `public` |
| `--output FILE` | Write the discovered inventory fragment |
| `--format {json,csv}` | Output format; default `json` |
| `--merge FILE` | Merge discovery results into an existing inventory |
| `--skip-ping` / `--skip-snmp` | Suppress the corresponding discovery phase |
| `--user`, `--password`, `--password-stdin` | Enable deep SSH enrichment after discovery |
| `--event-stream` | Emit app-facing JSON Lines; cannot be combined with `--output` or `--merge` |

The scanner requires the `snmp` extra for SNMP identification. Under an active
bastion it switches to TCP/SSH discovery and does not send local ICMP or UDP
SNMP traffic to the remote network.

## Health and checks

```bash
netops health --inventory inventory.yaml --threshold cpu=80,mem=85 --fail-on-alert
python -m netops.check.bgp --inventory inventory.yaml --expected-prefixes 10.0.0.2=100
python -m netops.check.vlan --inventory inventory.yaml --expected-vlans 10,20,30-50
python -m netops.check.interfaces --host 10.0.0.1 --vendor cisco_ios --down-only
```

`netops health` accepts exactly one of `--inventory` or `--host`, plus
`--group`, `--vendor`, `--user`, `--password`, `--threshold`, `--json`, and
`--fail-on-alert`.

The BGP module also supports `--flap-min-uptime` and `--prefix-deviation`. The
VLAN module requires one of `--expected-vlans` or `--vlan-db`, with optional
`--ignore-vlans`, `--check-trunks`, `--json`, and `--fail-on-alert`.

`netops.check.interfaces` is single-host only; it does not accept `--inventory`.

Vendor-specific commands are available as modules:

```bash
python -m netops.check.arista --inventory inventory.yaml
python -m netops.check.juniper --inventory inventory.yaml
python -m netops.check.paloalto --host 10.0.4.1 --audit
```

## Collection

```bash
python -m netops.collect.config --host 10.0.0.1 --vendor cisco_ios --user admin
netops backup --inventory inventory.yaml --output ./backups --workers 10
```

`netops.collect.config` accepts `--inventory` or `--host` (the code does not
enforce mutual exclusion), with `--group`, `--vendor`, `--user`, `--password`,
`--transport {ssh,telnet}`, `--output`, and `--json`.

`netops backup` requires both `--inventory` and `--output`. Optional flags are
`--group`, `--user`, `--password`, `--workers`, `--git`, `--no-alert`, and
`--json`. Use `--output`, not the obsolete `--output-dir` spelling.

## Diffs and changes

```bash
netops diff --before before.cfg --after after.cfg --format semantic
netops push --host 10.0.0.1 --commands changes.txt
netops push --host 10.0.0.1 --commands changes.txt --commit --confirm-timer 5
```

`netops push` is dry-run/read-only unless `--commit` is supplied. Its required
arguments are `--host` and `--commands`; the latter is one device command per
line. Supported safety and connection flags include `--confirm-timer`,
`--vendor`, `--user`, `--password`, `--transport`, `--port`, `--operator`,
`--changelog`, and `--json`. Use `--commands`, not the obsolete `--config`.

For health-validated rollback behavior, use the separate rollback module:

```bash
python -m netops.change.rollback \
  --host 10.0.0.1 --commands changes.txt --commit \
  --rollback-on-failure --validate-health
```

Create a reviewable plan before an approved change:

```bash
python -m netops.change.plan plan \
  --host 10.0.0.1 --desired desired.cfg --current running.cfg \
  --export plan.json
python -m netops.change.plan apply --plan plan.json --approve
```

`plan` requires `--host` and `--desired`; `apply` requires `--plan` and only
makes a device change with `--approve`.

## Credential vault and inventory export

```bash
python -m netops.core.vault init
python -m netops.core.vault set --default --user admin
python -m netops.core.vault get --device core-rtr-01 --groups routers,core
python -m netops.core.inventory export --inventory inventory.yaml --format ansible --output hosts.yaml
```

The vault commands are `init`, `set`, `get`, and `delete`; there is no `store`
subcommand. Store passwords interactively; use `NETOPS_VAULT_PASSWORD` only in
an appropriately protected non-interactive environment. Per-device environment
variables use `NETOPS_CRED_<NORMALIZED_HOST>_USER`, `_PASS`, and `_ENABLE`.

Inventory export formats are `ansible`, `ansible-json`, `ansible-yaml`, `json`,
and `yaml`.

## Active bastion

```powershell
netops bastion connect --host bastion.example.com --username netops --password-stdin
netops bastion status
netops bastion disconnect
```

`connect` requires `--host` and `--username`; optional arguments are `--port`,
`--key-file`, `--password-stdin`, and `--key-passphrase-stdin`. This selection
is workstation-wide for toolkit TCP connections. See [Active Bastion
Routing](active-bastion.md) for security and protocol limitations.

## TUI, reports, and Ansible helpers

Launch the optional Textual TUI with `netops tui` or `netops-tui` after
installing `.[tui]` on Python 3.10+.

The report generator is a Python API. The executable report interface is the
health dashboard:

```bash
python -m netops.report.health_dashboard \
  --inventory inventory.yaml --format html --output dashboard.html
```

Generate remediation playbooks from a saved health report:

```bash
python -m netops.playbooks.generator generate \
  --from-health-report health.json --output-dir playbooks
```

The generator uses dry-run values by default; `--live` changes the generated
playbook variables and should be reviewed before execution.
