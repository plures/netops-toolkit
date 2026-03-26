# `netops.inventory` — Network Device Discovery

Discover and enrich device inventory via SNMP/CDP/LLDP/ping sweep.

---

## `netops.inventory.scan`

Subnet scanner — discover devices via SNMP/CDP/LLDP/ping sweep.

**CLI usage:**
```
python -m netops.inventory.scan --subnet 10.0.0.0/24 --community public
python -m netops.inventory.scan --subnet 10.0.0.0/24 --output fragment.json
python -m netops.inventory.scan --subnet 10.0.0.0/24 --merge existing.yaml
python -m netops.inventory.scan --csv hosts.csv --deep --user admin
python -m netops.inventory.scan --hosts-file ips.txt --deep --user admin
```

### Classes

#### `ScanResult`

Scan result for a single host.

**Fields:**
- `host: str` — IP address of the scanned host
- `reachable: bool` — `True` when the host responded to ping
- `hostname: Optional[str]` — SNMP sysName or DNS hostname (default: `None`)
- `sys_descr: Optional[str]` — SNMP sysDescr (default: `None`)
- `sys_obj_id: Optional[str]` — SNMP sysObjectID (default: `None`)
- `vendor: Optional[str]` — detected Netmiko vendor string (default: `None`)
- `location: Optional[str]` — SNMP sysLocation (default: `None`)
- `cdp_neighbors: list[dict]` — list of CDP neighbour dicts (default: `[]`)
- `lldp_neighbors: list[dict]` — list of LLDP neighbour dicts (default: `[]`)
- `error: Optional[str]` — error message if scanning failed (default: `None`)
- `version: Optional[str]` — OS/firmware version (default: `None`)
- `model: Optional[str]` — hardware model (default: `None`)
- `serial: Optional[str]` — chassis serial number (default: `None`)
- `uptime: Optional[str]` — device uptime string (default: `None`)
- `image: Optional[str]` — system image file path (default: `None`)
- `hardware_revision: Optional[str]` — hardware revision (default: `None`)
- `total_memory: Optional[str]` — total memory string (default: `None`)
- `free_memory: Optional[str]` — free memory string (default: `None`)
- `reload_reason: Optional[str]` — last reload reason (default: `None`)
- `mac_address: Optional[str]` — management MAC address (default: `None`)
- `config_register: Optional[str]` — Cisco config register value (default: `None`)
- `cpu_type: Optional[str]` — CPU type string (default: `None`)
- `flash_size: Optional[str]` — flash storage size (default: `None`)
- `domain_name: Optional[str]` — DNS domain name (default: `None`)
- `interface_count: Optional[str]` — number of interfaces (default: `None`)

**Methods:**

##### `to_inventory_entry() -> dict`
Convert to an inventory device dict (compatible with `core.Inventory`).

### Functions

#### `ping_host(host: str, timeout: int = 1, count: int = 1) -> bool`
Return `True` if *host* responds to ICMP ping.

#### `ping_sweep(subnet: str, max_workers: int = 50, timeout: int = 1) -> list[str]`
Ping sweep a subnet and return a sorted list of reachable IP address strings.

**Args:**
- `subnet` — CIDR notation subnet (e.g. `"10.0.0.0/24"`)
- `max_workers` — thread pool size for concurrent pings
- `timeout` — per-host ping timeout in seconds

#### `identify_vendor(sys_descr: str, sys_obj_id: str = '') -> str`
Map *sysDescr* / *sysObjectID* to a Netmiko-compatible vendor string.

Returns one of: `cisco_ios`, `cisco_xe`, `cisco_xr`, `cisco_nxos`,
`nokia_sros`, `nokia_srl`, `juniper_junos`, `arista_eos`,
`brocade_fastiron`, `brocade_nos`, or `"unknown"`.

#### `scan_subnet(subnet: str, community: str = 'public', snmp_port: int = 161, snmp_timeout: int = 2, ping_workers: int = 50, ping_timeout: int = 1, snmp_concurrency: int = 10, skip_ping: bool = False, skip_snmp: bool = False) -> list[ScanResult]`
Full subnet scan: ping sweep → SNMP identification → CDP/LLDP topology.

**Args:**
- `subnet` — CIDR notation subnet (e.g. `"10.0.0.0/24"`)
- `community` — SNMPv2c community string
- `snmp_port` — SNMP UDP port (default: `161`)
- `snmp_timeout` — per-host SNMP timeout in seconds
- `ping_workers` — ping sweep thread-pool size
- `ping_timeout` — per-host ping timeout in seconds
- `snmp_concurrency` — max simultaneous SNMP sessions
- `skip_ping` — skip ping sweep and probe all addresses in the subnet
- `skip_snmp` — skip SNMP — perform a ping-sweep only

Returns a sorted list of `ScanResult` objects (one per reachable host).

Requires `pysnmp >= 7.0`. Install with `pip install 'netops-toolkit[snmp]'`.

#### `results_to_inventory_fragment(results: list[ScanResult]) -> dict`
Convert scan results to an inventory fragment (`{"devices": {...}}` dict).

The fragment is compatible with `netops.core.Inventory` and can be written
directly as a JSON file or merged into an existing inventory.

#### `merge_inventory(existing_path: str, fragment: dict) -> dict`
Merge a scan fragment into an existing inventory file.

New devices are added. Existing entries are updated only where the current
value is `None`, `"unknown"`, or `""` — manually-set values are never
overwritten.

**Args:**
- `existing_path` — path to an existing YAML or JSON inventory file; if the file does not exist, an empty inventory is used as the base
- `fragment` — inventory fragment produced by `results_to_inventory_fragment`

Returns the merged inventory dict.

#### `deep_enrich(fragment: dict, username: str, password: str, concurrency: int = 5, timeout: int = 15) -> dict`
Enrich an inventory fragment with SSH-gathered details.

Connects to each device in the fragment, auto-detects vendor if unknown,
and updates vendor, version, model, serial in-place.

**Args:**
- `fragment` — inventory fragment (`{"devices": {...}}`)
- `username` — SSH username for all devices
- `password` — SSH password for all devices
- `concurrency` — max parallel SSH sessions
- `timeout` — per-device connection timeout in seconds

Returns the enriched fragment (modified in-place and returned).

#### `main() -> None`
CLI entry point for the network device discovery scanner.
