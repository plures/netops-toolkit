# CLI Reference

All commands in netops-toolkit are invoked as Python modules (`python -m <module>`).
There are no top-level `netops` shell entry points — each subsystem has its own
module path, which you call directly.

## Table of Contents

- [Check commands](#check-commands)
  - [netops.check.bgp — BGP session monitor](#netopscheckbgp--bgp-session-monitor)
  - [netops.check.health — Device health](#netopscheckhealthdevice-health)
  - [netops.check.interfaces — Interface status](#netopscheckinterfaces--interface-status)
  - [netops.check.paloalto — Palo Alto audit & health](#netopscheckpaloalto--palo-alto-audit--health)
  - [netops.check.vlan — VLAN audit](#netopscheckvlan--vlan-audit)
- [Collect commands](#collect-commands)
  - [netops.collect.backup — Bulk config backup](#netopscollectbackup--bulk-config-backup)
  - [netops.collect.config — Config collection](#netopscollectconfig--config-collection)
- [Change commands](#change-commands)
  - [netops.change.push — Safe config push](#netopschangepush--safe-config-push)
- [Inventory commands](#inventory-commands)
  - [netops.inventory.scan — Subnet scanner](#netopsinventoryscan--subnet-scanner)
- [Core utilities](#core-utilities)
  - [netops.core.vault — Credential vault](#netopscorevault--credential-vault)
- [Common patterns](#common-patterns)

---

## Check commands

### netops.check.bgp — BGP session monitor

Monitors BGP sessions across one or many routers. Reports peer up/down status,
prefix counts vs expected, and flap detection.

Supports: Cisco IOS / IOS-XE / IOS-XR, Nokia SR-OS.

```
python -m netops.check.bgp [--inventory FILE | --host IP] [OPTIONS]
```

**Target selection (mutually exclusive, one required)**

| Flag | Description |
|------|-------------|
| `--inventory FILE`, `-i FILE` | YAML/JSON inventory file |
| `--host IP` | Single device IP/hostname |

**Options**

| Flag | Default | Description |
|------|---------|-------------|
| `--group GROUP`, `-g GROUP` | — | Filter inventory by group name |
| `--vendor VENDOR` | `cisco_ios` | Device vendor/type (single-host mode only) |
| `--user USER`, `-u USER` | — | SSH username |
| `--password PASS`, `-p PASS` | — | SSH password (or env `NETOPS_PASSWORD`) |
| `--expected-prefixes IP=N[,...]` | — | Expected prefix counts, e.g. `10.0.0.2=100,10.0.0.3=200` |
| `--flap-min-uptime SECS` | `300` | Sessions up for fewer than this many seconds are flagged as flapping |
| `--prefix-deviation PCT` | `20.0` | Alert when received prefixes deviate from expected by more than this % |
| `--json` | off | Output results as JSON |
| `--fail-on-alert` | off | Exit code 1 if any alert fires |

**Examples**

```bash
# Check all routers in inventory
python -m netops.check.bgp --inventory inventory.yaml

# Check only the core group, with prefix expectations
python -m netops.check.bgp \
  --inventory inventory.yaml \
  --group core \
  --expected-prefixes 10.0.0.2=100,10.0.0.3=200 \
  --flap-min-uptime 300 \
  --prefix-deviation 20

# Check a single router and output JSON
python -m netops.check.bgp --host 10.0.0.1 --vendor cisco_ios --json

# Use in a monitoring script — exit non-zero on any alert
python -m netops.check.bgp --inventory inventory.yaml --fail-on-alert
```

**Output (human-readable)**

```
✅ 10.0.0.1 [2024-01-15T12:00:00Z]
   Peers: 3/3 established  |  flapping: 0  |  prefix alerts: 0
   ✅ 10.0.0.2 AS65001 — Established  pfx=100/100  up=1d02h
   ✅ 10.0.0.3 AS65002 — Established  pfx=200/200  up=2w03d
   ✅ 10.0.0.4 AS65003 — Established  pfx=50  up=5d10h
```

---

### netops.check.health — Device health

Runs CPU, memory, interface-error, and log checks across vendors. Results are
returned as structured data suitable for monitoring integration.

Supports: Cisco IOS / IOS-XE / IOS-XR, Nokia SR-OS, Brocade, Palo Alto PAN-OS.

```
python -m netops.check.health [--inventory FILE | --host IP] [OPTIONS]
```

**Target selection (mutually exclusive, one required)**

| Flag | Description |
|------|-------------|
| `--inventory FILE`, `-i FILE` | YAML/JSON inventory file |
| `--host IP` | Single device IP/hostname |

**Options**

| Flag | Default | Description |
|------|---------|-------------|
| `--group GROUP`, `-g GROUP` | — | Filter inventory by group name |
| `--vendor VENDOR` | `cisco_ios` | Device vendor/type (single-host mode only) |
| `--user USER`, `-u USER` | — | SSH username |
| `--password PASS`, `-p PASS` | — | SSH password (or env `NETOPS_PASSWORD`) |
| `--threshold KEY=VAL[,...]` | `cpu=80,mem=85` | Alert thresholds, e.g. `cpu=80,mem=85` |
| `--json` | off | Output results as JSON |
| `--fail-on-alert` | off | Exit code 1 if any alert fires |

**Examples**

```bash
# Health check with custom thresholds
python -m netops.check.health \
  --inventory inv.yaml \
  --group core \
  --threshold cpu=80,mem=85

# Single device, JSON output
python -m netops.check.health \
  --host 10.0.0.1 \
  --vendor cisco_ios \
  --threshold cpu=80,mem=85 \
  --json

# Exit non-zero on any alert (for CI/monitoring)
python -m netops.check.health --inventory inv.yaml --fail-on-alert
```

**Output (human-readable)**

```
✅ 10.0.0.1 [2024-01-15T12:00:00Z]
   CPU : 23.5% (threshold 80%)
   MEM : 41.2% (threshold 85%)
   IFACE ERRORS: 0/48 interfaces with errors
   LOGS: 0 critical, 0 major
```

---

### netops.check.interfaces — Interface status

Checks interface up/down status across devices. Uses `show ip interface brief`
(Cisco) or `show port` (Nokia).

Supports: Cisco IOS / IOS-XE / IOS-XR / NX-OS, Nokia SR-OS.

```
python -m netops.check.interfaces --host IP [OPTIONS]
```

**Required**

| Flag | Description |
|------|-------------|
| `--host IP` | Device IP/hostname |

**Options**

| Flag | Default | Description |
|------|---------|-------------|
| `--vendor VENDOR` | `cisco_ios` | Device vendor/type |
| `--user USER`, `-u USER` | — | SSH username |
| `--password PASS`, `-p PASS` | — | SSH password (or env `NETOPS_PASSWORD`) |
| `--down-only` | off | Show only interfaces that are down |
| `--json` | off | Output results as JSON |

**Examples**

```bash
# Show all interfaces
python -m netops.check.interfaces \
  --host 10.0.0.1 \
  --vendor cisco_ios \
  --user admin

# Show only down interfaces
python -m netops.check.interfaces \
  --host 10.0.0.1 \
  --vendor cisco_ios \
  --down-only

# JSON output for integration
python -m netops.check.interfaces --host 10.0.0.1 --json
```

**Output (human-readable)**

```
📊 10.0.0.1: 46/48 interfaces up, 2 down
  ✅ GigabitEthernet0/0 (10.0.0.1) — up/up
  ✅ GigabitEthernet0/1 — up/up
  ❌ GigabitEthernet0/2 — administratively down/down
```

---

### netops.check.paloalto — Palo Alto audit & health

Runs security policy audit (unused/shadowed rules) and health checks (HA state,
session table utilization, content versions) on Palo Alto PAN-OS firewalls.

```
python -m netops.check.paloalto [--inventory FILE | --host IP] [OPTIONS]
```

**Target selection (mutually exclusive, one required)**

| Flag | Description |
|------|-------------|
| `--inventory FILE`, `-i FILE` | YAML/JSON inventory file |
| `--host IP` | Single device IP/hostname |

**Options**

| Flag | Default | Description |
|------|---------|-------------|
| `--group GROUP`, `-g GROUP` | — | Filter inventory by group name |
| `--vendor VENDOR` | `paloalto_panos` | Device vendor/type (single-host mode only) |
| `--user USER`, `-u USER` | — | SSH username |
| `--password PASS`, `-p PASS` | — | SSH password (or env `NETOPS_PASSWORD`) |
| `--session-threshold PCT` | `80.0` | Session table utilization alert threshold (%) |
| `--audit` | off | Run security policy audit (unused + shadowed rules) |
| `--health` | on | Run health checks — HA state, sessions, content versions (default mode) |
| `--json` | off | Output results as JSON |
| `--fail-on-alert` | off | Exit code 1 if any alert fires |

`--audit` and `--health` are mutually exclusive.

**Examples**

```bash
# Health check on all firewalls
python -m netops.check.paloalto \
  --inventory inv.yaml \
  --group firewalls \
  --health \
  --json

# Security policy audit on a single firewall
python -m netops.check.paloalto \
  --host 10.0.0.1 \
  --audit

# Custom session threshold
python -m netops.check.paloalto \
  --host 10.0.0.1 \
  --health \
  --session-threshold 70
```

**Output — health (human-readable)**

```
✅ 10.0.0.1 [2024-01-15T12:00:00Z]
   HA : mode=Active-Passive  local=active  peer=passive
   SESSIONS : 12543 active  (15.7% of 80000)
   CONTENT : threat=8678-7488  url=20230115.20003
```

**Output — policy audit (human-readable)**

```
🚨 Policy audit — 42 rules total
   ⚠️  UNUSED RULES (3):
      • legacy-permit-any  (action: allow)
      • old-dmz-access     (action: allow)
      • test-rule-delete   (action: deny)
   ✅ No shadowed rules
```

---

### netops.check.vlan — VLAN audit

Audits VLAN configuration on Cisco IOS/IOS-XE switches. Compares declared
(expected) VLANs against what is actually configured. Optionally checks trunk
interfaces too.

```
python -m netops.check.vlan [--inventory FILE | --host IP] [--expected-vlans RANGE | --vlan-db FILE] [OPTIONS]
```

**Target selection (mutually exclusive, one required)**

| Flag | Description |
|------|-------------|
| `--inventory FILE`, `-i FILE` | YAML/JSON inventory file |
| `--host IP` | Single device IP/hostname |

**VLAN source (mutually exclusive, one required)**

| Flag | Description |
|------|-------------|
| `--expected-vlans RANGE` | Comma/range notation, e.g. `10,20,30-50,100` |
| `--vlan-db FILE` | YAML file mapping VLAN IDs to names (see below) |

**Options**

| Flag | Default | Description |
|------|---------|-------------|
| `--group GROUP`, `-g GROUP` | — | Filter inventory by group name |
| `--vendor VENDOR` | `cisco_ios` | Device vendor/type (single-host mode only) |
| `--user USER`, `-u USER` | — | SSH username |
| `--password PASS`, `-p PASS` | — | SSH password (or env `NETOPS_PASSWORD`) |
| `--ignore-vlans RANGE` | — | VLAN IDs to exclude from the extra-VLANs check |
| `--check-trunks` | off | Also verify expected VLANs are active on trunk interfaces |
| `--json` | off | Output results as JSON |
| `--fail-on-alert` | off | Exit code 1 if any alert fires |

**VLAN database file format (`vlans.yaml`)**

```yaml
vlans:
  10: MANAGEMENT
  20: SERVERS
  100: DMZ
```

**Examples**

```bash
# Audit using inline VLAN range
python -m netops.check.vlan \
  --inventory inventory.yaml \
  --expected-vlans 10,20,30-50,100 \
  --check-trunks

# Audit using a VLAN database file (also validates VLAN names)
python -m netops.check.vlan \
  --inventory inventory.yaml \
  --vlan-db vlans.yaml \
  --check-trunks

# Single switch, JSON output
python -m netops.check.vlan \
  --host 10.0.0.1 \
  --vendor cisco_ios \
  --expected-vlans 10,20,100 \
  --json

# Ignore VLANs 999 and 1001 from the extra-VLANs check
python -m netops.check.vlan \
  --host 10.0.0.1 \
  --expected-vlans 10,20 \
  --ignore-vlans 999,1001
```

**Output (human-readable)**

```
🚨 10.0.0.1 [2024-01-15T12:00:00Z] — NON-COMPLIANT
   VLANs on switch: 15
   ⚠  Missing VLANs : 30, 40, 50
   ⚠  Extra VLANs   : 999
   ⚠  VLAN 20 name: expected 'SERVERS', got 'servers'
```

---

## Collect commands

### netops.collect.backup — Bulk config backup

Collects running configs from all inventory devices, saves them with timestamps,
and generates unified diffs against the previous backup so unexpected changes are
immediately visible. Optionally commits every changed file to a local git
repository.

```
python -m netops.collect.backup --inventory FILE --output DIR [OPTIONS]
```

**Required**

| Flag | Description |
|------|-------------|
| `--inventory FILE`, `-i FILE` | Inventory file (YAML/JSON) |
| `--output DIR`, `-o DIR` | Root directory for the backup archive |

**Options**

| Flag | Default | Description |
|------|---------|-------------|
| `--group GROUP`, `-g GROUP` | — | Target a specific inventory group |
| `--user USER`, `-u USER` | — | Username override |
| `--password PASS`, `-p PASS` | — | Password (or env `NETOPS_PASSWORD`) |
| `--workers N`, `-w N` | `5` | Number of concurrent collection threads |
| `--git` | off | Commit every backup to a local git repository |
| `--no-alert` | off | Suppress per-device change alerts on stderr |
| `--json` | off | Output backup summary as JSON to stdout |

**Directory layout**

```
<output>/
  <hostname>/
    20240101-120000.cfg
    20240102-130000.cfg   ← newest backup
```

Diffs are computed automatically between the two most-recent backups for each
device.

**Examples**

```bash
# Backup all devices in inventory
python -m netops.collect.backup \
  --inventory inv.yaml \
  --output /var/backups/network/

# Backup with git commits and 10 parallel workers
python -m netops.collect.backup \
  --inventory inv.yaml \
  --output /var/backups/network/ \
  --git \
  --workers 10

# Backup only the core group
python -m netops.collect.backup \
  --inventory inv.yaml \
  --output /var/backups/network/ \
  --group core

# JSON summary for pipeline integration
python -m netops.collect.backup \
  --inventory inv.yaml \
  --output /var/backups/network/ \
  --json
```

**Output (human-readable)**

```
📦 Backup complete: 12 ok, 3 changed, 0 failed
  ✅ core-rtr-01 → /var/backups/network/core-rtr-01/20240115-120000.cfg ⚠️  CHANGED
  ✅ core-rtr-02 → /var/backups/network/core-rtr-02/20240115-120000.cfg
  ✅ access-sw-01 → /var/backups/network/access-sw-01/20240115-120000.cfg ⚠️  CHANGED
```

Change diffs (first 20 lines) are written to **stderr** unless `--no-alert` is passed.

---

### netops.collect.config — Config collection

Collects the running configuration from one or many devices. Simpler than
`netops.collect.backup` — no diff tracking or git integration.

```
python -m netops.collect.config [--inventory FILE | --host IP] [OPTIONS]
```

**Target selection (one required)**

| Flag | Description |
|------|-------------|
| `--inventory FILE`, `-i FILE` | Inventory file (YAML/JSON) |
| `--host IP` | Single device IP/hostname |

**Options**

| Flag | Default | Description |
|------|---------|-------------|
| `--group GROUP`, `-g GROUP` | — | Target a specific inventory group |
| `--vendor VENDOR` | `cisco_ios` | Device type (single-host mode only) |
| `--user USER`, `-u USER` | — | Username |
| `--password PASS`, `-p PASS` | — | Password (or env `NETOPS_PASSWORD`) |
| `--transport {ssh,telnet}` | `ssh` | Transport protocol |
| `--output DIR`, `-o DIR` | — | Save configs to this directory (one file per device) |
| `--json` | off | Print all results as JSON to stdout |

When `--output` is given, files are named `<host>_<timestamp>.cfg`.
When neither `--output` nor `--json` is given, a one-line summary per device
is printed.

**Examples**

```bash
# Collect from a single device
python -m netops.collect.config \
  --host 10.0.0.1 \
  --vendor cisco_ios \
  --user admin

# Collect from all inventory devices and save to files
python -m netops.collect.config \
  --inventory inv.yaml \
  --output /tmp/configs/

# Only the core group, via Telnet, with JSON output
python -m netops.collect.config \
  --inventory inv.yaml \
  --group core \
  --transport telnet \
  --json
```

**Output (human-readable)**

```
✅ 10.0.0.1: 347 lines collected
❌ 10.0.0.2: Authentication failed.
```

---

## Change commands

### netops.change.push — Safe config push

Pushes configuration changes to a device with a pre/post diff, an optional
confirm timer, and automatic rollback if the change is not confirmed in time.
Dry-run by default — changes are only applied when `--commit` is passed.

**Workflow:**

1. Connect and snapshot the running config (pre-change).
2. When `--commit` is given, push the commands from the supplied file.
3. Snapshot the config again (post-change) and compute a unified diff.
4. If `--confirm-timer N` is set, start a countdown — type `confirm` within
   *N* minutes or the pre-change config is restored.
5. Append a structured entry to the JSON-lines change log.

```
python -m netops.change.push --host IP --commands FILE [OPTIONS]
```

**Required**

| Flag | Description |
|------|-------------|
| `--host IP` | Target device hostname or IP |
| `--commands FILE` | File containing config commands, one per line |

**Options**

| Flag | Default | Description |
|------|---------|-------------|
| `--vendor VENDOR` | `cisco_ios` | Device type |
| `--user USER`, `-u USER` | — | Username (or env `NETOPS_USER`, else system user) |
| `--password PASS`, `-p PASS` | — | Password (or env `NETOPS_PASSWORD`) |
| `--transport {ssh,telnet}` | `ssh` | Transport protocol |
| `--port PORT` | — | Override default port |
| `--commit` | off | Actually push changes (default is dry-run) |
| `--confirm-timer MINUTES` | `0` | Auto-rollback if not confirmed within N minutes (0 = disabled) |
| `--operator NAME` | current user | Operator name written to the change log |
| `--changelog FILE` | `~/.netops/changelog.jsonl` | Path to the JSON-lines change log |
| `--json` | off | Output result as JSON to stdout |

Commands file format — one command per line; lines starting with `#` and blank
lines are ignored:

```
# Enable OSPF on loopback
router ospf 1
 network 192.168.0.1 0.0.0.0 area 0
```

**Examples**

```bash
# Dry-run — show what would change without touching the device
python -m netops.change.push \
  --host router1 \
  --commands changes.txt

# Commit with a 5-minute confirm timer
python -m netops.change.push \
  --host router1 \
  --commands changes.txt \
  --commit \
  --confirm-timer 5

# Commit immediately (no confirm timer) and log JSON output
python -m netops.change.push \
  --host router1 \
  --vendor cisco_xr \
  --commands changes.txt \
  --commit \
  --json

# Custom changelog location
python -m netops.change.push \
  --host router1 \
  --commands changes.txt \
  --commit \
  --changelog /var/log/netops/changes.jsonl
```

**Output (human-readable)**

```
🔍 DRY-RUN: pre-change config captured (412 lines)
   (no changes pushed — use --commit to apply)

--- pre-change
+++ post-change  (simulated)
@@ -10,6 +10,8 @@
 router ospf 1
+ network 192.168.0.1 0.0.0.0 area 0
```

---

## Inventory commands

### netops.inventory.scan — Subnet scanner

Discovers devices on a subnet using a ping sweep followed by SNMP, CDP, and LLDP
identification. Results can be saved as a JSON inventory fragment or merged into
an existing YAML inventory file.

Requires the optional `snmp` extra for SNMP identification:

```bash
pip install netops-toolkit[snmp]
```

```
python -m netops.inventory.scan --subnet CIDR [OPTIONS]
```

**Required**

| Flag | Description |
|------|-------------|
| `--subnet CIDR` | Subnet in CIDR notation, e.g. `10.0.0.0/24` |

**Options**

| Flag | Default | Description |
|------|---------|-------------|
| `--community STRING` | `public` | SNMPv2c community string |
| `--snmp-port PORT` | `161` | SNMP UDP port |
| `--snmp-timeout SECS` | `2` | Per-host SNMP timeout in seconds |
| `--ping-workers N` | `50` | Ping sweep thread-pool size |
| `--snmp-concurrency N` | `10` | Maximum simultaneous SNMP sessions |
| `--output FILE`, `-o FILE` | — | Write JSON inventory fragment to this file |
| `--merge FILE`, `-m FILE` | — | Merge scan results into an existing inventory file |
| `--skip-ping` | off | Skip ping sweep — probe every address in the subnet |
| `--skip-snmp` | off | Skip SNMP — perform a ping sweep only |
| `--verbose`, `-v` | off | Enable debug logging |

**Examples**

```bash
# Basic ping sweep
python -m netops.inventory.scan --subnet 10.0.0.0/24

# Full discovery with SNMPv2c community string
python -m netops.inventory.scan \
  --subnet 10.0.0.0/24 \
  --community mysecret

# Save results as a JSON fragment
python -m netops.inventory.scan \
  --subnet 10.0.0.0/24 \
  --output fragment.json

# Merge newly discovered devices into an existing inventory
python -m netops.inventory.scan \
  --subnet 10.0.0.0/24 \
  --merge existing.yaml

# Ping sweep only (no SNMP)
python -m netops.inventory.scan \
  --subnet 10.0.0.0/24 \
  --skip-snmp
```

**Output**

```
🔍 Scan complete: 12 reachable, 9 identified via SNMP, 4 CDP neighbors, 0 LLDP neighbors
```

---

## Core utilities

### netops.core.vault — Credential vault

Manages an AES-256-GCM encrypted credential vault stored at
`~/.netops/vault.yaml` (override with `--vault`). Credentials are stored per
device, per group, or as a site-wide default. At runtime the vault is consulted
automatically; environment variables take precedence (see
[Common patterns](#common-patterns)).

```
python -m netops.core.vault [--vault FILE] <subcommand> [OPTIONS]
```

**Global options**

| Flag | Default | Description |
|------|---------|-------------|
| `--vault FILE` | `~/.netops/vault.yaml` | Path to the vault file |

#### Subcommands

##### `init` — initialise a new vault

```bash
python -m netops.core.vault init
```

Prompts for a master password and creates an empty vault file.

##### `set` — store credentials

```
python -m netops.core.vault set [--device HOSTNAME | --group GROUP | --default] --user USERNAME [--enable]
```

| Flag | Description |
|------|-------------|
| `--device HOSTNAME` | Store credentials for a specific device |
| `--group GROUP` | Store credentials for a device group |
| `--default` | Store site-wide default credentials |
| `--user USERNAME` | Username to store (required) |
| `--enable` | Also prompt for an enable/privileged-exec password |

**Examples**

```bash
# Store credentials for a specific device
python -m netops.core.vault set --device router1.example.com --user admin

# Store default credentials used when no device/group match is found
python -m netops.core.vault set --default --user netops

# Store credentials for a whole group, including enable password
python -m netops.core.vault set --group core-routers --user admin --enable
```

##### `get` — show credentials (passwords masked)

```
python -m netops.core.vault get --device HOSTNAME [--groups GROUP1,GROUP2]
```

| Flag | Description |
|------|-------------|
| `--device HOSTNAME` | Device hostname to look up (required) |
| `--groups GROUP1,GROUP2` | Comma-separated list of groups the device belongs to |

```bash
python -m netops.core.vault get --device router1.example.com --groups core-routers,dc1
```

Lookup order: environment variables → device → group → default.

##### `delete` — remove credentials

```
python -m netops.core.vault delete [--device HOSTNAME | --group GROUP | --default]
```

```bash
# Remove credentials for a specific device
python -m netops.core.vault delete --device router1.example.com

# Remove credentials for a group
python -m netops.core.vault delete --group core-routers

# Remove default credentials
python -m netops.core.vault delete --default
```

---

## Common patterns

### Password via environment variable

All commands accept `NETOPS_PASSWORD` (and `NETOPS_USER` where applicable) so
that passwords are never written to shell history:

```bash
export NETOPS_PASSWORD='s3cret'
python -m netops.check.health --inventory inv.yaml
```

### JSON output for pipeline integration

Every command supports `--json` to emit machine-readable output on stdout:

```bash
python -m netops.check.bgp --inventory inv.yaml --json | jq '.report.overall_alert'
```

### Exit codes for monitoring

Use `--fail-on-alert` to make a command exit with code 1 when any alert fires —
useful in CI pipelines or monitoring scripts:

```bash
python -m netops.check.health --inventory inv.yaml --fail-on-alert
echo "Exit: $?"
```

### Inventory file format

All commands that accept `--inventory` expect a YAML file in this format:

```yaml
defaults:
  username: admin
  transport: ssh

devices:
  core-rtr-01:
    host: 10.0.0.1
    vendor: cisco_ios
    groups: [routers, core]

  nokia-pe-01:
    host: 10.0.0.2
    vendor: nokia_sros
    groups: [routers, pe]
```

See [Inventory Management](inventory-management.md) for full details.
