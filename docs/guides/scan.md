# Network Scanner Guide

Discover devices on your network automatically — no manual inventory required to get started.

## What It Does

The scanner (`netops.inventory.scan`) discovers devices in a subnet by:

1. **Ping sweep** — sends ICMP pings to every address in a CIDR range; only reachable hosts are probed further.
2. **SNMP identification** — queries the MIB-II system group (RFC 1213) on each live host to read hostname, description, sysObjectID, and location.
3. **Vendor detection** — maps `sysDescr` / `sysObjectID` to a Netmiko-compatible vendor string automatically.
4. **CDP discovery** (Cisco) — walks the Cisco CDP MIB to find directly connected neighbors.
5. **LLDP discovery** (IEEE 802.1AB) — walks the LLDP-MIB to find neighbors on any 802.1AB-capable device.

The result is an inventory fragment you can write to a new file or merge into an existing one.

## Prerequisites

### Install SNMP support

The scanner requires `pysnmp >= 7.0`. Install the optional dependency group:

```bash
pip install 'netops-toolkit[snmp]'
```

The ping sweep works without any extra packages. Use `--skip-snmp` if you only want to find live hosts.

### Network requirements

| Feature | Port | Protocol |
|---------|------|----------|
| Ping sweep | — | ICMP |
| SNMP identification | 161 (UDP) | SNMPv2c |
| CDP / LLDP discovery | 161 (UDP) | SNMPv2c |

The scanner only reads — it never writes to devices.

## Quick Start

### Discover a /24 subnet

```bash
python -m netops.inventory.scan --subnet 10.0.0.0/24
```

This prints a JSON inventory fragment to stdout:

```json
{
  "devices": {
    "core-rtr-01": {
      "host": "10.0.0.1",
      "vendor": "cisco_ios",
      "site": "Main DC, Row 3",
      "tags": {
        "sys_descr": "Cisco IOS Software, Version 15.7(3)M...",
        "neighbors": "cdp:dist-sw-01,cdp:dist-sw-02"
      }
    },
    "dist-sw-01": {
      "host": "10.0.0.2",
      "vendor": "cisco_xe",
      "tags": {
        "sys_descr": "Cisco IOS Software [Everest], Catalyst L3...",
        "neighbors": "cdp:core-rtr-01,lldp:access-sw-03"
      }
    }
  }
}
```

### Save to a file

```bash
python -m netops.inventory.scan --subnet 10.0.0.0/24 --output fragment.json
```

### Merge into an existing inventory

```bash
python -m netops.inventory.scan --subnet 10.0.0.0/24 --merge my-inventory.yaml
```

New devices are added. Existing entries are only updated where the current value is empty or `"unknown"` — your manually-set values are never overwritten.

## Step-by-Step: First Scan

### Step 1: Decide your scan range

Pick a CIDR range that covers your management network. Common examples:

| Scope | Example |
|-------|---------|
| Small office (/24, up to 254 hosts) | `10.0.0.0/24` |
| Campus block (/22, up to 1,022 hosts) | `172.16.0.0/22` |
| Single device (/32) | `192.168.1.1/32` |
| Specific range | Use one CIDR per run |

### Step 2: Run a quick ping-only scan first

```bash
python -m netops.inventory.scan --subnet 10.0.0.0/24 --skip-snmp
```

Output summary (stderr):
```
🔍 Scan complete: 14 reachable, 0 identified via SNMP, 0 CDP neighbors, 0 LLDP neighbors
```

This tells you how many devices are pingable before attempting SNMP.

### Step 3: Run a full scan with your SNMP community

```bash
python -m netops.inventory.scan \
  --subnet 10.0.0.0/24 \
  --community mysecretcommunity \
  --output scan-fragment.json
```

### Step 4: Review the fragment

```bash
cat scan-fragment.json | python -m json.tool
```

Check that vendors were detected correctly. Devices that couldn't be identified show `"vendor": "unknown"`.

### Step 5: Merge into your inventory

If you already have an inventory:

```bash
python -m netops.inventory.scan \
  --subnet 10.0.0.0/24 \
  --community mysecretcommunity \
  --merge my-inventory.yaml
```

Or start a fresh one from the fragment:

```bash
cp scan-fragment.json my-inventory.json
# Then add credentials, groups, etc. by hand
```

## Configuration: All CLI Options

```bash
python -m netops.inventory.scan --help
```

| Option | Default | What It Does |
|--------|---------|-------------|
| `--subnet` | *(required)* | Subnet in CIDR notation, e.g. `10.0.0.0/24` |
| `--community` | `public` | SNMPv2c community string |
| `--snmp-port` | `161` | SNMP UDP port |
| `--snmp-timeout` | `2` | Per-host SNMP timeout in seconds |
| `--ping-workers` | `50` | Thread pool size for concurrent pings |
| `--snmp-concurrency` | `10` | Max simultaneous SNMP sessions |
| `--output` / `-o` | stdout | Write JSON inventory fragment to this file |
| `--merge` / `-m` | — | Merge scan results into an existing inventory file |
| `--skip-ping` | false | Skip ping sweep — probe every address in the subnet |
| `--skip-snmp` | false | Skip SNMP — perform a ping sweep only |
| `--verbose` / `-v` | false | Enable debug logging |

### Tuning for large subnets

For a /16 (up to 65,534 hosts), increase concurrency:

```bash
python -m netops.inventory.scan \
  --subnet 10.0.0.0/16 \
  --ping-workers 200 \
  --snmp-concurrency 30 \
  --community public
```

> **Note:** Higher concurrency puts more load on your network and management plane. Start with defaults and increase gradually.

### Scanning without ping

Some firewalls block ICMP but allow SNMP. Use `--skip-ping` to probe all addresses directly:

```bash
python -m netops.inventory.scan \
  --subnet 10.0.0.0/24 \
  --skip-ping \
  --community mysecretcommunity
```

> **Warning:** Scanning all addresses in a /16 without ping takes significantly longer.

## Using the Python API

```python
from netops.inventory.scan import (
    scan_subnet,
    results_to_inventory_fragment,
    merge_inventory,
    identify_vendor,
    ping_sweep,
)
```

### `ping_sweep(subnet, max_workers=50, timeout=1)`

Returns a sorted list of reachable IP address strings for the given CIDR subnet.

```python
from netops.inventory.scan import ping_sweep

live_hosts = ping_sweep("10.0.0.0/24", max_workers=100, timeout=2)
print(live_hosts)
# ['10.0.0.1', '10.0.0.2', '10.0.0.5']
```

### `scan_subnet(subnet, community="public", ...)`

Full scan: ping sweep → SNMP identification → CDP/LLDP topology. Returns a list of `ScanResult` objects.

```python
from netops.inventory.scan import scan_subnet

results = scan_subnet(
    subnet="10.0.0.0/24",
    community="mysecretcommunity",
    snmp_timeout=3,
    ping_workers=100,
    snmp_concurrency=20,
)

for r in results:
    print(r.host, r.vendor, r.hostname)
```

#### `ScanResult` attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `host` | `str` | IP address |
| `reachable` | `bool` | Responded to ping (or `skip_ping` was set) |
| `hostname` | `Optional[str]` | `sysName` from SNMP (domain stripped) |
| `sys_descr` | `Optional[str]` | `sysDescr` — full platform description |
| `sys_obj_id` | `Optional[str]` | `sysObjectID` — enterprise OID |
| `vendor` | `Optional[str]` | Netmiko vendor string, e.g. `cisco_ios` |
| `location` | `Optional[str]` | `sysLocation` from SNMP |
| `cdp_neighbors` | `list[dict]` | List of CDP neighbor dicts (keys: `device_id`, `platform`, `address`, `protocol`) |
| `lldp_neighbors` | `list[dict]` | List of LLDP neighbor dicts (keys: `sys_name`, `sys_desc`, `chassis_id`, `protocol`) |
| `error` | `Optional[str]` | Error message if SNMP failed |

#### `ScanResult.to_inventory_entry()`

Converts a single result to an inventory device dict compatible with `netops.core.Inventory`:

```python
entry = result.to_inventory_entry()
# {'host': '10.0.0.1', 'vendor': 'cisco_ios', 'site': 'Main DC', 'tags': {'sys_descr': '...'}}
```

### `identify_vendor(sys_descr, sys_obj_id="")`

Map a raw `sysDescr` string (and optionally `sysObjectID`) to a Netmiko vendor string. Useful when you already have SNMP data and just need the vendor mapping.

```python
from netops.inventory.scan import identify_vendor

vendor = identify_vendor("Cisco IOS Software, Version 15.7(3)M")
# 'cisco_ios'

vendor = identify_vendor("IOS XE Software, Catalyst, Version 17.06.01")
# 'cisco_xe'

vendor = identify_vendor("", ".1.3.6.1.4.1.6527.1.3.2")
# 'nokia_sros'
```

### `results_to_inventory_fragment(results)`

Convert a list of `ScanResult` objects to an inventory fragment dict:

```python
from netops.inventory.scan import scan_subnet, results_to_inventory_fragment

results = scan_subnet("10.0.0.0/24")
fragment = results_to_inventory_fragment(results)
# {'devices': {'core-rtr-01': {...}, 'dist-sw-01': {...}}}
```

Neighbor information is encoded in the `neighbors` tag as a comma-separated string of `cdp:<device_id>` and `lldp:<sys_name>` entries.

### `merge_inventory(existing_path, fragment)`

Merge a fragment into an existing YAML or JSON inventory. Returns the merged dict. Supports `.yaml`, `.yml`, and `.json` files.

```python
from netops.inventory.scan import scan_subnet, results_to_inventory_fragment, merge_inventory
import json
from pathlib import Path

results = scan_subnet("10.0.0.0/24", community="mycommunity")
fragment = results_to_inventory_fragment(results)
merged = merge_inventory("my-inventory.yaml", fragment)

# Save the merged result
import yaml
Path("my-inventory.yaml").write_text(yaml.dump(merged, default_flow_style=False))
```

**Merge semantics:**
- New devices are added as-is.
- For existing devices, a field is only updated if its current value is `None`, `""`, or `"unknown"`.
- Tag dicts are merged at the sub-key level with the same rules.
- Manually set values are never overwritten.

## Output Format

The scanner produces an inventory fragment — a JSON/YAML dict with a `"devices"` key:

```json
{
  "devices": {
    "core-rtr-01": {
      "host": "10.0.0.1",
      "vendor": "cisco_ios",
      "site": "Main DC, Rack 3",
      "tags": {
        "sys_descr": "Cisco IOS Software, Version 15.7(3)M, RELEASE SOFTWARE",
        "neighbors": "cdp:dist-sw-01,cdp:dist-sw-02,lldp:fw-01"
      }
    },
    "10.0.0.7": {
      "host": "10.0.0.7",
      "vendor": "unknown",
      "tags": {}
    }
  }
}
```

**Notes:**
- The device key is `sysName` (with domain stripped) when SNMP is successful, otherwise the IP address.
- `site` comes from `sysLocation` and is omitted when empty.
- `vendor: "unknown"` means the host was reachable but SNMP failed or `sysDescr` didn't match any known pattern.

## Supported Vendors

The scanner detects the following platforms automatically via `sysDescr` pattern matching and `sysObjectID` enterprise prefix fallback:

| Vendor | Detected String | Vendor Code |
|--------|----------------|-------------|
| Cisco IOS | `"Cisco IOS Software"` or OID `.1.3.6.1.4.1.9.` | `cisco_ios` |
| Cisco IOS-XE | `"IOS XE"` or `"IOS-XE"` | `cisco_xe` |
| Cisco IOS-XR | `"IOS XR"` | `cisco_xr` |
| Cisco NX-OS | `"NX-OS"` or `"NXOS"` | `cisco_nxos` |
| Nokia SR OS | `"Nokia"` or `"TiMOS"`, OID `.1.3.6.1.4.1.6527.` | `nokia_sros` |
| Nokia SR Linux | `"Nokia"` + `"SRL"` | `nokia_srl` |
| Juniper JunOS | `"Juniper"` or `"Junos"`, OID `.1.3.6.1.4.1.2636.` | `juniper_junos` |
| Arista EOS | `"Arista"`, OID `.1.3.6.1.4.1.30065.` | `arista_eos` |
| Brocade FastIron | `"Brocade"` / `"Foundry"` / `"FastIron"`, OID `.1.3.6.1.4.1.1991.` | `brocade_fastiron` |
| Brocade NOS | `"Brocade Network OS"`, OID `.1.3.6.1.4.1.1588.` | `brocade_nos` |
| Unknown | No match | `unknown` |

Devices detected as `unknown` are still included in the fragment — add them to your inventory manually and set the vendor.

## Troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| `ImportError: pysnmp is required` | SNMP extra not installed | `pip install 'netops-toolkit[snmp]'` |
| `0 reachable` from ping sweep | ICMP blocked | Use `--skip-ping` to probe all addresses directly |
| All vendors show `"unknown"` | Wrong community string | Check with `snmpwalk -c <community> -v2c <host> sysDescr.0` |
| `0 identified via SNMP` | SNMP not enabled on devices | Enable SNMPv2c on your devices; check ACLs |
| Scanner hangs on large /16 | Too many concurrent sessions | Reduce `--snmp-concurrency` and `--ping-workers` |
| CDP/LLDP neighbors empty | Protocol disabled or community read-only restriction | Check that CDP/LLDP is enabled and the community allows table reads |
| `ImportError: PyYAML required` | YAML output requested without pyyaml | `pip install pyyaml` |
| Device shows IP instead of hostname | `sysName` not set or SNMP failed | Set a hostname on the device, or rename in inventory manually |

### Verify SNMP manually

Before scanning, confirm SNMP is reachable with the system `snmpwalk` command:

```bash
snmpwalk -c public -v2c 10.0.0.1 system
```

If this works, the scanner will find the device. If it times out, check firewall rules on UDP port 161.

### Enable verbose logging

```bash
python -m netops.inventory.scan --subnet 10.0.0.0/24 --verbose 2>&1 | head -50
```

This shows per-host ping results and SNMP errors.

## Integration with Inventory Management

> **Full pipeline walkthrough:** [Auto-Inventory Generation Pipeline](auto-inventory.md) explains every stage from scan to Ansible — vendor detection, deduplication, vault integration, and more.

After scanning, the fragment slots directly into your inventory workflow:

```bash
# 1. Scan and create an initial inventory
python -m netops.inventory.scan --subnet 10.0.0.0/24 --output my-inventory.json

# 2. Add credentials and groups by hand (or use the vault)
# See: docs/guides/inventory-management.md

# 3. Rescan a new subnet and merge additions
python -m netops.inventory.scan --subnet 10.0.1.0/24 --merge my-inventory.yaml

# 4. Use the inventory with other tools
python -m netops.collect.config --inventory my-inventory.yaml
```

See [Inventory Management](inventory-management.md) for full details on the inventory format, groups, tags, and Ansible export.
