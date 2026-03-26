# `netops.parsers` — Output Parsers

Vendor-specific parsers for CLI and structured API output.

---

## `netops.parsers.arista`

Parsers for Arista EOS eAPI JSON responses and CLI text output.

Arista EOS supports two output modes:

- **eAPI JSON** — structured JSON returned by the `/command-api` endpoint or
  via Netmiko with `output_format="json"`. These are the *primary* parsers
  and accept already-decoded `dict` objects.
- **CLI text** — plain-text `show` output, used as a fallback when eAPI is
  unavailable. These parsers operate on raw strings.

All parser functions return lists or dicts that match the health-check schema
used by the rest of the toolkit.

### Functions

#### `parse_cpu_memory_eos(data: dict) -> dict`
Parse `show version` eAPI JSON response for CPU and memory.

Returns: `cpu_utilization`, `memory_total_kb`, `memory_used_kb`,
`memory_util`, `uptime_seconds`, `eos_version`, `serial_number`, `model`.
All values are `None` when parsing fails.

#### `parse_interfaces_eos(data: dict) -> list[dict]`
Parse `show interfaces` eAPI JSON response.

Each returned dict: `name`, `description`, `line_protocol`, `oper_status`,
`link_status`, `in_errors`, `out_errors`, `in_discards`, `out_discards`,
`crc_errors`, `has_errors`, `is_up`.

#### `parse_interface_counters_eos(data: dict) -> list[dict]`
Parse `show interfaces counters errors` eAPI JSON response.

Each returned dict: `name`, `fcs_errors`, `align_errors`, `symbol_errors`,
`rx_pause`, `in_errors`, `out_errors`, `has_errors`.

#### `parse_transceivers_eos(data: dict) -> list[dict]`
Parse `show interfaces transceiver` eAPI JSON response.

Each returned dict: `interface`, `media_type`, `tx_power_dbm`,
`rx_power_dbm`, `tx_bias_ma`, `temperature_c`, `supply_voltage`, `alert`.

#### `parse_bgp_summary_eos(data: dict) -> list[dict]`
Parse `show bgp summary` eAPI JSON response (IPv4 unicast).

Each returned dict: `neighbor`, `peer_as`, `state`, `up_down`,
`prefixes_rcvd`, `is_established`.

#### `parse_bgp_evpn_eos(data: dict) -> list[dict]`
Parse `show bgp evpn summary` eAPI JSON response.
Returns the same per-peer structure as `parse_bgp_summary_eos`.

#### `parse_ospf_neighbors_eos(data: dict) -> list[dict]`
Parse `show ip ospf neighbor` eAPI JSON response.

Each returned dict: `neighbor_id`, `interface`, `address`, `state`,
`priority`, `dead_time`, `is_full`.

#### `parse_mlag_eos(data: dict) -> dict`
Parse `show mlag` eAPI JSON response.

Returns: `state`, `peer_state`, `peer_link`, `peer_link_status`,
`local_interface`, `local_ip`, `peer_ip`, `config_sanity`, `is_active`,
`is_peer_active`, `peer_link_ok`.

#### `parse_mlag_config_sanity_eos(data: dict) -> dict`
Parse `show mlag config-sanity` eAPI JSON response.

Returns: `consistent`, `global_inconsistencies`,
`interface_inconsistencies`.

#### `parse_environment_eos(data: dict) -> dict`
Parse `show environment all` eAPI JSON response.

Returns: `power_supplies`, `fans`, `temperatures`, `overall_ok`.

#### `parse_bgp_summary_eos_text(output: str) -> list[dict]`
Parse `show bgp summary` plain-text output from Arista EOS.
Returns the same structure as `parse_bgp_summary_eos`.

#### `parse_ospf_neighbors_eos_text(output: str) -> list[dict]`
Parse `show ip ospf neighbor` plain-text output from Arista EOS.
Returns the same structure as `parse_ospf_neighbors_eos`.

#### `parse_mlag_eos_text(output: str) -> dict`
Parse `show mlag` plain-text output from Arista EOS.
Returns the same structure as `parse_mlag_eos`.

---

## `netops.parsers.bgp`

Parsers for BGP CLI output.

Supports Cisco IOS/IOS-XE (`show ip bgp summary`) and Cisco IOS-XR
(`show bgp summary`). Nokia SR-OS BGP output is handled by
`netops.parsers.nokia_sros.parse_bgp_summary`.

### Functions

#### `parse_bgp_summary_cisco(output: str) -> list[dict]`
Parse `show ip bgp summary` / `show bgp summary` output.

Handles Cisco IOS, IOS-XE, and IOS-XR formats.

Each returned dict: `neighbor`, `peer_as`, `msg_rcvd`, `msg_sent`,
`up_down`, `state` (`'Established'` or FSM state string),
`prefixes_received` (int when established, otherwise `None`).

Returns an empty list when the output cannot be parsed.

#### `updown_to_seconds(updown: str) -> int | None`
Convert a BGP session up/down time string to total seconds.

Handles:
- `HH:MM:SS` — e.g. `'00:15:30'`
- `XdYh` — e.g. `'2d03h'`, `'1d02h'`
- `XwYd` — e.g. `'1w2d'`
- `XhYm` — Nokia SR-OS, e.g. `'00h15m'`
- `never` — session was never established → `None`

Returns `None` when the string is `'never'` or cannot be parsed.

---

## `netops.parsers.brocade`

Parsers for Brocade FastIron / Network OS / Fabric OS CLI output.

### Functions

#### `parse_interfaces(output: str) -> list[dict]`
Parse `show interfaces` or `show interface brief` output.

Supports Brocade FastIron/ICX interface summary lines. Each returned dict:
`name`, `status`, `protocol`, `up`.

Field names match the Cisco / Nokia parser convention so callers can treat
output from all vendors uniformly. Handles both the detailed form
(`GigabitEthernet1/1/1 is up, line protocol is up`) and the brief tabular
form.

#### `parse_ip_routes(output: str) -> list[dict]`
Parse `show ip route` output from Brocade FastIron/ICX.

Each returned dict: `type`, `network`, `next_hop`, `interface`, `metric`.
Returns an empty list when the output cannot be parsed.

#### `parse_version(output: str) -> dict`
Parse `show version` output from a Brocade FastIron/ICX device.

Returns: `model`, `version`, `vendor` (always `'Brocade'`).
Returns a dict with `None` values when the output cannot be parsed.

#### `parse_fabric(output: str) -> dict`
Parse `show fabric` output from a Brocade Fabric OS (FOS) SAN switch.

Returns: `fabric_name`, `fabric_os`, `switches` (list of `{name, domain}`),
`ports` (list of `{port, state}`).

---

## `netops.parsers.cisco`

Parsers for Cisco IOS/IOS-XE show command output.

Covers OSPF neighbor tables, device environment (temperature, fans, power
supplies), and `show version` (uptime, reload reason, IOS version).

### Functions

#### `parse_ospf_neighbors(output: str) -> list[dict]`
Parse `show ip ospf neighbor` output from Cisco IOS/IOS-XE.

Each returned dict: `neighbor_id`, `priority`, `state`, `dead_time`,
`address`, `interface`, `is_full`.

Returns an empty list when no neighbors are parsed.

#### `parse_environment_cisco(output: str) -> dict`
Parse `show environment all` output from Cisco IOS/IOS-XE.

Handles both IOS (router) and IOS-XE (Catalyst switch) output formats.

Returns: `fans` (list of `{name, status, ok}`), `temperatures` (list of
`{name, celsius, status, ok}`), `power_supplies` (list of `{name, status, ok}`),
`overall_ok`.

#### `parse_version_cisco(output: str) -> dict`
Parse `show version` output from Cisco IOS/IOS-XE.

Returns: `version`, `platform`, `uptime`, `reload_reason`, `image`.
All values are `None` when the output cannot be parsed.

#### `parse_inventory_cisco(output: str) -> list[dict]`
Parse `show inventory` output from Cisco IOS/NX-OS/IOS-XE.

Each returned dict: `name`, `descr`, `pid`, `vid`, `sn`.

#### `parse_serial_cisco(output: str) -> str | None`
Extract the chassis serial number from `show inventory` output.

Returns the serial number for the first entry whose name contains "chassis"
(case-insensitive), or the first entry if no chassis is found.
Returns `None` if parsing fails.

---

## `netops.parsers.health`

Parsers for health-check CLI output (CPU, memory, interface errors, logs).

Supports Cisco IOS/XE/XR/NXOS, Nokia SR-OS, and Brocade FastIron/NOS output
formats.

### Functions

#### `parse_cpu_cisco(output: str) -> dict`
Parse `show processes cpu` output from Cisco IOS/XE/XR.

Returns: `five_seconds`, `one_minute`, `five_minutes` (all `float`).
Returns an empty dict when the output cannot be parsed.

#### `parse_cpu_nokia(output: str) -> dict`
Parse `show system cpu` output from Nokia SR-OS.

Returns: `avg`, `peak` (both `float`).
Returns an empty dict when the output cannot be parsed.

#### `parse_memory_cisco(output: str) -> dict`
Parse `show processes memory` output from Cisco IOS/XE.

Returns: `total`, `used`, `free` (all `int`), `utilization` (`float`, 0–100).
Returns an empty dict when the output cannot be parsed.

#### `parse_memory_nokia(output: str) -> dict`
Parse `show system memory-pools` output from Nokia SR-OS.

Returns: `total`, `used`, `free` (all `int`), `utilization` (`float`, 0–100).
Returns an empty dict when the output cannot be parsed.

#### `parse_interface_errors_cisco(output: str) -> list[dict]`
Parse `show interfaces` output for error counters on Cisco IOS/XE/XR.

Each returned dict: `name`, `input_errors`, `output_errors`, `crc`, `drops`,
`has_errors`.

#### `parse_interface_errors_nokia(output: str) -> list[dict]`
Parse `show port detail` output for error counters on Nokia SR-OS.

Each returned dict: `name`, `input_errors`, `output_errors`, `crc`, `drops`,
`has_errors`.

#### `parse_logs_cisco(output: str) -> list[dict]`
Scan `show logging` output for severity 0–3 (critical/major) events.

Each returned dict: `facility`, `severity`, `mnemonic`, `message`.

#### `parse_logs_nokia(output: str) -> list[dict]`
Scan Nokia SR-OS log output for CRITICAL and MAJOR severity events.

Each returned dict: `timestamp`, `severity`, `subject`, `message`.

#### `parse_cpu_brocade(output: str) -> dict`
Parse `show cpu` output from Brocade FastIron/ICX.

Returns: `one_second`, `five_seconds`, `one_minute` (all `float`).

#### `parse_memory_brocade(output: str) -> dict`
Parse `show memory` output from Brocade FastIron/ICX.

Returns: `total`, `used`, `free` (all `int`), `utilization` (`float`, 0–100).

#### `parse_interface_errors_brocade(output: str) -> list[dict]`
Parse `show interfaces` output for error counters on Brocade FastIron/ICX.

Each returned dict: `name`, `input_errors`, `output_errors`, `crc`, `drops`,
`has_errors`.

#### `parse_logs_brocade(output: str) -> list[dict]`
Scan `show logging` output for critical/error severity events on Brocade.

Each returned dict: `timestamp`, `severity` (`'CRITICAL'`, `'ERROR'`, or
`'WARNING'`), `message`.

#### `parse_cpu_paloalto(output: str) -> dict`
Parse `show system resources follow duration 1` output from PAN-OS.

Extracts from the `top`-style output. Returns: `user`, `system`, `idle`,
`utilization` (all `float`).

#### `parse_memory_paloalto(output: str) -> dict`
Parse `show system resources follow duration 1` output from PAN-OS.

Extracts the memory summary line. Returns: `total`, `used`, `free` (all
`int`), `utilization` (`float`, 0–100).

---

## `netops.parsers.juniper`

Parsers for Juniper JunOS CLI output.

Supports both plain-text (`show …`) and XML-like text output produced by
JunOS `show` commands. All parsers operate on strings and do **not** require
`lxml` or `ncclient`.

### Functions

#### `parse_re_status(output: str) -> list[dict]`
Parse `show chassis routing-engine` output.

Each returned dict represents one RE slot: `slot`, `mastership`, `state`,
`cpu_util`, `memory_util`, `memory_total`, `memory_used`, `uptime`,
`temperature`.

#### `parse_fpc_status(output: str) -> list[dict]`
Parse `show chassis fpc` output.

Each returned dict: `slot`, `state`, `cpu_util`, `memory_used`,
`memory_total`, `temperature`, `ok`.

#### `parse_interface_errors_junos(output: str) -> list[dict]`
Parse `show interfaces extensive` (or `show interfaces detail`) output.

Each returned dict: `name`, `input_errors`, `output_errors`, `input_drops`,
`output_drops`, `crc_errors`, `has_errors`.

#### `parse_bgp_summary_junos(output: str) -> list[dict]`
Parse `show bgp summary` output from JunOS.

Each returned dict: `neighbor`, `peer_as`, `state`, `up_down`,
`prefixes_received`, `active_prefixes`.

#### `parse_ospf_neighbors_junos(output: str) -> list[dict]`
Parse `show ospf neighbor` output from JunOS.

Each returned dict: `neighbor_id`, `address`, `interface`, `state`,
`dead_time`, `priority`, `is_full`.

#### `parse_chassis_alarms(output: str) -> list[dict]`
Parse `show chassis alarms` output.

Each returned dict: `time`, `class_`, `description`, `is_major`.

#### `parse_chassis_environment(output: str) -> dict`
Parse `show chassis environment` output.

Returns: `power_supplies`, `fans`, `temperatures`, `overall_ok`.

#### `parse_route_summary(output: str) -> list[dict]`
Parse `show route summary` output.

Each returned dict: `table`, `active_routes`, `holddown_routes`,
`hidden_routes`, `total_routes`.

---

## `netops.parsers.nokia_sros`

Parsers for Nokia SR OS CLI output.

### Functions

#### `parse_interfaces(output: str) -> list[dict]`
Parse `show port` output into a list of interface dicts.

Each dict: `name`, `status`, `protocol`, `up`.
Field names match the Cisco `parse_cisco_interfaces` convention.

#### `parse_bgp_summary(output: str) -> list[dict]`
Parse `show router bgp summary` output into a BGP peer list.

Each dict: `neighbor`, `description`, `peer_as`, `received`, `sent`,
`active`, `up_down`, `state`.

#### `parse_ospf_neighbors(output: str) -> list[dict]`
Parse `show router ospf neighbor` output into an adjacency list.

Each dict: `interface`, `router_id`, `state`, `priority`, `retx_queue`.

---

## `netops.parsers.paloalto`

Parsers for Palo Alto Networks PAN-OS CLI output.

Supports structured output for the core `show` commands used by health
checks and security policy audits.

### Functions

#### `parse_system_info(output: str) -> dict`
Parse `show system info` output from a PAN-OS device.

Returns: `hostname`, `ip_address`, `model`, `serial`, `panos_version`,
`app_version`, `threat_version`, `url_version`, `ha_mode`, `ha_state`.
`None` for any field that cannot be parsed.

#### `parse_interfaces(output: str) -> list[dict]`
Parse `show interface all` output from a PAN-OS device.

Each returned dict: `name`, `state`, `ip`, `vsys`, `zone`, `up`.

#### `parse_routes(output: str) -> list[dict]`
Parse `show routing route` output from a PAN-OS device.

Each returned dict: `destination`, `nexthop`, `metric`, `flags`, `active`,
`type`, `age`, `interface`.

#### `parse_session_info(output: str) -> dict`
Parse `show session info` output from a PAN-OS device.

Returns: `max_sessions`, `active_sessions`, `active_tcp`, `active_udp`,
`active_icmp`, `session_utilization`. Any field is `None` when unparseable.

#### `parse_security_policy(output: str) -> list[dict]`
Parse `show running security-policy` output from a PAN-OS device.

Each returned dict: `name`, `from_zones`, `to_zones`, `sources`,
`destinations`, `applications`, `services`, `action`.

#### `parse_security_policy_stats(output: str) -> list[dict]`
Parse `show security policy statistics` output from a PAN-OS device.

Each returned dict: `name`, `hit_count`, `last_hit`.

#### `parse_ha_state(output: str) -> dict`
Parse `show high-availability state` output from a PAN-OS device.

Returns: `enabled`, `mode`, `local_state`, `peer_state`, `peer_ip`,
`preemptive`.

---

## `netops.parsers.vlan`

Parsers for VLAN CLI output.

Supports Cisco IOS/IOS-XE: `show vlan brief` → `parse_vlan_brief`;
`show interfaces trunk` → `parse_interfaces_trunk`.

### Functions

#### `expand_vlan_range(ranges: str) -> set[int]`
Expand a VLAN range string into a set of integer VLAN IDs.

Examples:
- `"10"` → `{10}`
- `"10,20,30"` → `{10, 20, 30}`
- `"10-14"` → `{10, 11, 12, 13, 14}`
- `"1,10-12,20"` → `{1, 10, 11, 12, 20}`
- `"none"` → `set()`
- `""` → `set()`

Non-parseable tokens are silently ignored.

#### `parse_vlan_brief(output: str) -> list[dict]`
Parse `show vlan brief` output. Handles Cisco IOS and IOS-XE formats.

Each returned dict: `vlan_id`, `name`, `status`, `ports`.

#### `parse_interfaces_trunk(output: str) -> list[dict]`
Parse `show interfaces trunk` output. Handles Cisco IOS and IOS-XE formats.

Parses all four stanzas (port/mode/encap/status/native-VLAN; allowed VLANs;
active VLANs; forwarding VLANs) and merges per-port.

Each returned dict: `port`, `mode`, `encapsulation`, `status`, `native_vlan`,
`allowed_vlans`, `active_vlans`, `forwarding_vlans`.
