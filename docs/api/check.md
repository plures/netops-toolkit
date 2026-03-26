# `netops.check` — Health & Compliance Checks

Composable health, BGP, interface, VLAN, and vendor-specific checks.

---

## `netops.check.health`

Composable health checks for network devices.

Runs CPU, memory, interface-error, and log checks across vendors and reports
results as structured JSON for monitoring integration.

**CLI usage:**
```
python -m netops.check.health --inventory inv.yaml --group core \
    --threshold cpu=80,mem=85
python -m netops.check.health --host 10.0.0.1 --vendor cisco_ios \
    --threshold cpu=80,mem=85 --json
```

### Functions

#### `check_cpu(conn: DeviceConnection, device_type: str, threshold: float) -> dict`
Return CPU utilisation check result.

#### `check_memory(conn: DeviceConnection, device_type: str, threshold: float) -> dict`
Return memory utilisation check result.

#### `check_interface_errors(conn: DeviceConnection, device_type: str) -> dict`
Return interface error-counter check result.

#### `check_logs(conn: DeviceConnection, device_type: str) -> dict`
Return log-scan check result (critical/major events).

#### `run_health_check(params: ConnectionParams, cpu_threshold: float = DEFAULT_CPU_THRESHOLD, mem_threshold: float = DEFAULT_MEM_THRESHOLD) -> dict`
Run all health checks against a single device.

Returns a result dict with keys:
- `host` — device IP/hostname
- `timestamp` — ISO-8601 UTC timestamp
- `success` — `True` when connection succeeded
- `checks` — dict of individual check results
- `overall_alert` — `True` when any check triggered an alert
- `error` — error message when connection failed

#### `build_health_report(results: list[dict]) -> dict`
Build an aggregated health report from a list of per-device results.

**Parameters:**
- `results` — list of dicts returned by `run_health_check`

Returns a summary dict with keys:
- `devices` — total devices polled
- `devices_reachable` — devices successfully reached
- `devices_with_alerts` — count of devices with at least one alert
- `cpu_alerts` — count of devices with a CPU alert
- `memory_alerts` — count of devices with a memory alert
- `interface_error_alerts` — count of devices with interface error alerts
- `log_alerts` — count of devices with log alerts
- `overall_alert` — `True` when any device triggered an alert
- `results` — original per-device result list

#### `main() -> None`
CLI entry point for composable device health checks.

---

## `netops.check.bgp`

BGP session monitor — peer status, prefix counts, flap detection.

Checks BGP sessions across one or many routers and reports peer up/down
status, prefix count vs expected (alert on configurable deviation %),
flap detection, and a summary report aggregated across all polled routers.

Supports Cisco IOS/IOS-XE/IOS-XR and Nokia SR-OS.

**CLI usage:**
```
python -m netops.check.bgp --inventory inventory.yaml \
    --expected-prefixes 10.0.0.2=100,10.0.0.3=200 \
    --flap-min-uptime 300 --prefix-deviation 20
python -m netops.check.bgp --host 10.0.0.1 --vendor cisco_ios --json
```

### Functions

#### `check_bgp_peers(params: ConnectionParams, expected_prefixes: Optional[dict[str, int]] = None, flap_min_uptime: int = DEFAULT_FLAP_MIN_UPTIME, prefix_deviation_pct: float = DEFAULT_PREFIX_DEVIATION_PCT) -> dict`
Check BGP peer status on a single device.

**Parameters:**
- `params` — device connection parameters
- `expected_prefixes` — optional dict mapping neighbor IP → expected prefix count; an alert fires when the actual count deviates by more than `prefix_deviation_pct` percent
- `flap_min_uptime` — sessions established for fewer than this many seconds are flagged as potentially flapping (default: 300 s)
- `prefix_deviation_pct` — percentage threshold for prefix-count deviation alerts (default: 20%)

Returns a result dict with keys:
- `host` — device IP/hostname
- `timestamp` — ISO-8601 UTC timestamp
- `success` — `True` when the device was reached
- `peers` — list of per-peer check dicts
- `summary` — aggregate counts across all peers on this device
- `overall_alert` — `True` when any alert fired
- `error` — error message when connection failed

#### `build_bgp_report(results: list[dict]) -> dict`
Build an aggregated BGP report from a list of per-device results.

**Parameters:**
- `results` — list of dicts returned by `check_bgp_peers`

Returns a summary dict with keys:
- `routers` — total routers polled
- `routers_reachable` — routers successfully reached
- `total_peers` — total BGP peers across all routers
- `established` — peers in Established state
- `not_established` — peers not in Established state
- `flapping` — peers flagged as potentially flapping
- `prefix_alerts` — peers with prefix-count deviations
- `overall_alert` — `True` when any alert fired
- `peers` — flat list of all peer dicts with `router` key

#### `main() -> None`
CLI entry point for the BGP session monitor.

---

## `netops.check.interfaces`

Check interface status across devices.

**CLI usage:**
```
python -m netops.check.interfaces --inventory inventory.yaml --down-only
python -m netops.check.interfaces --host 10.0.0.1 --vendor cisco_ios
```

### Functions

#### `parse_cisco_interfaces(output: str) -> list[dict]`
Parse `show ip interface brief` output.

#### `check_interfaces(params: ConnectionParams, down_only: bool = False) -> dict`
Check interface status on a device.

#### `main() -> None`
CLI entry point for the interface status checker.

---

## `netops.check.vlan`

VLAN audit — compare declared vs actual VLAN configuration across switches.

Checks VLAN configuration on a switch fabric and reports missing VLANs,
extra VLANs, name mismatches, trunk mismatches, and per-switch compliance
status. Supports Cisco IOS/IOS-XE.

**CLI usage:**
```
python -m netops.check.vlan --inventory inventory.yaml \
    --expected-vlans 10,20,30-50,100 \
    --check-trunks
python -m netops.check.vlan --host 10.0.0.1 --vendor cisco_ios \
    --vlan-db vlans.yaml --json
```

**VLAN database file (`vlans.yaml`) format:**
```yaml
vlans:
  10: MANAGEMENT
  20: SERVERS
  100: DMZ
```

### Functions

#### `audit_vlans(params: ConnectionParams, expected_vlans: set[int], expected_names: Optional[dict[int, str]] = None, check_trunks: bool = False, ignore_vlans: Optional[set[int]] = None) -> dict`
Audit VLAN configuration on a single switch.

**Parameters:**
- `params` — device connection parameters
- `expected_vlans` — set of VLAN IDs that should be present on the switch
- `expected_names` — optional mapping of VLAN ID → declared name; name mismatches are included when provided
- `check_trunks` — when `True`, also check `show interfaces trunk` and flag expected VLANs not active on trunking interfaces
- `ignore_vlans` — additional VLAN IDs to exclude from the extra-VLANs check (system VLANs 1002–1005 are always excluded)

Returns a result dict with keys:
- `host` — device IP/hostname
- `timestamp` — ISO-8601 UTC timestamp
- `success` — `True` when the device was reached
- `actual_vlans` — list of per-VLAN dicts from `parse_vlan_brief`
- `trunks` — list of trunk-port dicts (empty when `check_trunks` is `False`)
- `missing_vlans` — VLAN IDs in `expected_vlans` but absent from the switch
- `extra_vlans` — VLAN IDs on switch but not in `expected_vlans`
- `name_mismatches` — list of `{vlan_id, expected_name, actual_name}`
- `trunk_mismatches` — list of `{port, missing_vlans}` (empty when `check_trunks` is `False`)
- `compliant` — `True` when no discrepancies were found
- `alerts` — human-readable list of alert messages
- `error` — error message when the connection failed

#### `build_vlan_report(results: list[dict]) -> dict`
Build an aggregated VLAN audit report from per-switch results.

**Parameters:**
- `results` — list of dicts returned by `audit_vlans`

Returns a summary dict with keys:
- `switches` — total switches polled
- `switches_reachable` — switches successfully reached
- `switches_compliant` — fully compliant switches
- `overall_alert` — `True` when any switch is non-compliant
- `missing_vlan_switches` — list of `{host, missing_vlans}`
- `extra_vlan_switches` — list of `{host, extra_vlans}`
- `name_mismatch_switches` — list of `{host, name_mismatches}`
- `trunk_mismatch_switches` — list of `{host, trunk_mismatches}`

#### `main() -> None`
CLI entry point for the VLAN configuration auditor.

---

## `netops.check.arista`

Arista EOS health checker.

Provides health checks for Arista EOS devices (DCS-7xxx, DCS-720x, etc.):
CPU and memory utilisation, interface error counters and transceiver DOM,
BGP/EVPN session state, OSPF adjacency verification, MLAG health and
config-consistency, and environment (temperature sensors, fans, power supplies).

eAPI JSON is the primary transport. Plain-text CLI output is used as a fallback
when eAPI is unavailable.

**CLI usage:**
```
python -m netops.check.arista --host 10.0.0.1 --user netops \
    --threshold cpu=80,mem=85 --json
python -m netops.check.arista --inventory inv.yaml --group arista \
    --threshold cpu=80,mem=85 --fail-on-alert
```

### Functions

#### `check_eos_cpu_memory(conn: DeviceConnection, cpu_threshold: float, mem_threshold: float) -> dict`
Return CPU and memory utilisation check result. Queries `show version` (JSON).

Returns: `cpu_utilization`, `memory_util`, `cpu_threshold`, `mem_threshold`,
`cpu_alert`, `mem_alert`, `alert`, `eos_version`, `model`, `serial_number`, `error`.

#### `check_eos_interfaces(conn: DeviceConnection) -> dict`
Return interface error-counter check result. Queries `show interfaces` (JSON).

Returns: `interfaces`, `total`, `with_errors`, `alert`, `error`.

#### `check_eos_transceivers(conn: DeviceConnection) -> dict`
Return transceiver DOM check result. Queries `show interfaces transceiver` (JSON).

Returns: `transceivers`, `total`, `with_alerts`, `alert`, `error`.

#### `check_eos_bgp(conn: DeviceConnection) -> dict`
Return BGP session state check result. Queries `show bgp summary` (JSON).

Returns: `peers`, `total`, `established`, `not_established`, `alert`, `error`.

#### `check_eos_bgp_evpn(conn: DeviceConnection) -> dict`
Return BGP EVPN session state check result. Queries `show bgp evpn summary` (JSON).
Returns the same structure as `check_eos_bgp`.

#### `check_eos_ospf(conn: DeviceConnection) -> dict`
Return OSPF neighbour state check result. Queries `show ip ospf neighbor` (JSON).

Returns: `neighbors`, `total`, `full`, `not_full`, `alert`, `error`.

#### `check_eos_mlag(conn: DeviceConnection) -> dict`
Return MLAG health check result. Queries `show mlag` and `show mlag config-sanity` (JSON).

Returns: `mlag`, `config_sanity`, `is_active`, `peer_link_ok`, `peer_active`,
`config_consistent`, `alert`, `error`.

#### `check_eos_environment(conn: DeviceConnection) -> dict`
Return environment (temperature, fans, PSUs) check result. Queries `show environment all` (JSON).

Returns: `power_supplies`, `fans`, `temperatures`, `overall_ok`, `alert`, `error`.

#### `run_health_check(params: ConnectionParams, cpu_threshold: float = DEFAULT_CPU_THRESHOLD, mem_threshold: float = DEFAULT_MEM_THRESHOLD, check_bgp: bool = True, check_evpn: bool = False, check_ospf: bool = True, check_mlag: bool = True, check_transceivers: bool = False) -> dict`
Run all EOS health checks against a single device.

Runs: `cpu_memory`, `interfaces`, `transceivers` (if enabled), `bgp` (if enabled),
`bgp_evpn` (if enabled), `ospf` (if enabled), `mlag` (if enabled), `environment`.

Returns: `host`, `timestamp`, `success`, `checks`, `overall_alert`, `error`.

#### `build_eos_health_report(results: list[dict]) -> dict`
Build an aggregated health report from a list of per-device results.

Returns a summary dict with keys: `devices`, `devices_reachable`,
`devices_with_alerts`, `cpu_memory_alerts`, `interface_alerts`, `bgp_alerts`,
`ospf_alerts`, `mlag_alerts`, `environment_alerts`, `overall_alert`, `results`.

#### `main(argv: Optional[list[str]] = None) -> int`
CLI entry point for Arista EOS health checks.

---

## `netops.check.cisco`

Cisco IOS/IOS-XE health checker.

Extends the generic health check with Cisco-specific checks: CPU utilisation,
memory utilisation, interface error counters (CRC, input/output errors, drops),
BGP neighbour state and prefix counts, OSPF adjacency verification, environment
(temperature, power supplies, fans), and uptime/last reload reason.

Supports IOS 15.x+ and IOS-XE 16.x+.

**CLI usage:**
```
python -m netops.check.cisco --host 10.0.0.1 --user admin \
    --threshold cpu=80,mem=85 --json
python -m netops.check.cisco --inventory inv.yaml --group core \
    --threshold cpu=80,mem=85 --fail-on-alert
```

### Functions

#### `check_cisco_cpu(conn: DeviceConnection, threshold: float) -> dict`
Return CPU utilisation check result for a Cisco IOS/IOS-XE device.

Returns: `utilization` (1-min avg CPU %), `threshold`, `alert`, `raw`.

#### `check_cisco_memory(conn: DeviceConnection, threshold: float) -> dict`
Return memory utilisation check result for a Cisco IOS/IOS-XE device.

Returns: `utilization` (memory used %), `threshold`, `alert`, `raw`.

#### `check_cisco_interfaces(conn: DeviceConnection) -> dict`
Return interface error-counter check result for a Cisco IOS/IOS-XE device.

Returns: `interfaces`, `total`, `with_errors`, `alert`.

#### `check_cisco_logs(conn: DeviceConnection) -> dict`
Return log-scan check result (severity 0–3 events) for a Cisco IOS/IOS-XE device.

Returns: `critical_count`, `major_count`, `events`, `alert`.

#### `check_cisco_bgp(conn: DeviceConnection, device_type: str = 'cisco_ios') -> dict`
Return BGP neighbour state check result for a Cisco IOS/IOS-XE device.

Returns: `peers`, `total`, `established`, `not_established`, `alert`.

#### `check_cisco_ospf(conn: DeviceConnection) -> dict`
Return OSPF adjacency check result for a Cisco IOS/IOS-XE device.

Returns: `neighbors`, `total`, `full`, `not_full`, `alert`.

#### `check_cisco_environment(conn: DeviceConnection) -> dict`
Return environment check result for a Cisco IOS/IOS-XE device.

Returns: `fans`, `temperatures`, `power_supplies`, `overall_ok`, `alert`.

#### `check_cisco_uptime(conn: DeviceConnection) -> dict`
Return uptime and reload reason check result for a Cisco IOS/IOS-XE device.

Returns: `version`, `platform`, `uptime`, `reload_reason`, `image`, `alert` (always `False`).

#### `run_cisco_health_check(params: ConnectionParams, cpu_threshold: float = DEFAULT_CPU_THRESHOLD, mem_threshold: float = DEFAULT_MEM_THRESHOLD, include_bgp: bool = True, include_ospf: bool = True, include_environment: bool = True) -> dict`
Run all Cisco IOS/IOS-XE health checks against a single device.

**Parameters:**
- `params` — device connection parameters
- `cpu_threshold` — CPU alert threshold in percent (default: 80)
- `mem_threshold` — memory alert threshold in percent (default: 85)
- `include_bgp` — when `True` (default), run the BGP peer check
- `include_ospf` — when `True` (default), run the OSPF adjacency check
- `include_environment` — when `True` (default), run the environment check

#### `build_cisco_health_report(results: list[dict]) -> dict`
Build an aggregated health report from a list of per-device results.

Returns a summary dict with keys: `devices`, `devices_reachable`,
`devices_with_alerts`, `cpu_alerts`, `memory_alerts`, `interface_error_alerts`,
`log_alerts`, `bgp_alerts`, `ospf_alerts`, `environment_alerts`,
`overall_alert`, `results`.

#### `main() -> None`
CLI entry point for Cisco IOS/IOS-XE health checks.

---

## `netops.check.juniper`

Juniper JunOS health checker.

Provides health checks for Juniper JunOS devices (MX, QFX, EX, SRX):
Routing Engine (RE) CPU and memory utilisation, FPC slot operational status,
interface error counters, BGP neighbour state and prefix counts, OSPF adjacency
verification, chassis alarms (major/minor), chassis environment (power, cooling,
temperature), and routing table summary.

Supports JunOS 18.x+. Works with both XML RPC and CLI (text) modes via Netmiko's
`juniper` / `juniper_junos` device type.

**CLI usage:**
```
python -m netops.check.juniper --host 10.0.0.1 --user netops \
    --threshold cpu=80,mem=85 --json
python -m netops.check.juniper --inventory inv.yaml --group juniper \
    --threshold cpu=80,mem=85 --fail-on-alert
```

### Functions

#### `check_junos_re(conn: DeviceConnection, cpu_threshold: float, mem_threshold: float) -> dict`
Return Routing Engine CPU and memory check result. Queries `show chassis routing-engine`.

Returns: `routing_engines`, `cpu_utilization`, `mem_utilization`, `cpu_threshold`,
`mem_threshold`, `cpu_alert`, `mem_alert`, `alert`, `error`.

#### `check_junos_fpc(conn: DeviceConnection) -> dict`
Return FPC slot status check result. Queries `show chassis fpc`.

Returns: `fpcs`, `total`, `online`, `offline`, `alert`, `error`.

#### `check_junos_interfaces(conn: DeviceConnection) -> dict`
Return interface error-counter check result. Queries `show interfaces extensive`.

Returns: `interfaces`, `total`, `with_errors`, `alert`, `error`.

#### `check_junos_bgp(conn: DeviceConnection) -> dict`
Return BGP neighbour state check result. Queries `show bgp summary`.

Returns: `peers`, `total`, `established`, `not_established`, `alert`, `error`.

#### `check_junos_ospf(conn: DeviceConnection) -> dict`
Return OSPF neighbour state check result. Queries `show ospf neighbor`.

Returns: `neighbors`, `total`, `full`, `not_full`, `alert`, `error`.

#### `check_junos_alarms(conn: DeviceConnection) -> dict`
Return chassis alarm check result. Queries `show chassis alarms`.

Returns: `alarms`, `major_count`, `minor_count`, `alert`, `error`.

#### `check_junos_environment(conn: DeviceConnection) -> dict`
Return chassis environment check result. Queries `show chassis environment`.

Returns: `power_supplies`, `fans`, `temperatures`, `overall_ok`, `alert`, `error`.

#### `check_junos_routes(conn: DeviceConnection) -> dict`
Return routing table summary check result (informational). Queries `show route summary`.

Returns: `tables`, `alert` (always `False`), `error`.

#### `run_health_check(params: ConnectionParams, cpu_threshold: float = DEFAULT_CPU_THRESHOLD, mem_threshold: float = DEFAULT_MEM_THRESHOLD, check_bgp: bool = True, check_ospf: bool = True) -> dict`
Run all JunOS health checks against a single device.

Runs: `RE`, `FPC`, `interfaces`, `BGP` (if enabled), `OSPF` (if enabled),
`alarms`, `environment`, `routes`.

Returns: `host`, `timestamp`, `success`, `checks`, `overall_alert`, `error`.

#### `build_junos_health_report(results: list[dict]) -> dict`
Build an aggregated health report from a list of per-device results.

Returns a summary dict with keys: `devices`, `devices_reachable`,
`devices_with_alerts`, `re_alerts`, `fpc_alerts`, `interface_alerts`,
`bgp_alerts`, `ospf_alerts`, `alarm_alerts`, `environment_alerts`,
`overall_alert`, `results`.

#### `main() -> None`
CLI entry point for JunOS health checks.

---

## `netops.check.paloalto`

Security policy audit and health checks for Palo Alto Networks PAN-OS devices.

**CLI usage:**
```
python -m netops.check.paloalto --host 10.0.0.1 --audit
python -m netops.check.paloalto --inventory inv.yaml --group firewalls \
    --health --json
```

### Functions

#### `check_unused_rules(policy: list[dict], stats: list[dict]) -> list[dict]`
Identify security rules that have never been matched.

Correlates `policy` (from `parse_security_policy`) with `stats` (from
`parse_security_policy_stats`) and returns those rules whose hit count is zero.

Each returned dict is the original rule dict augmented with a `hit_count` key.

#### `check_shadowed_rules(policy: list[dict]) -> list[dict]`
Identify security rules that are shadowed by an earlier, broader rule.

A rule R[i] is considered *shadowed* when there exists an earlier rule R[j]
(j < i) whose source zones, destination zones, sources, destinations, and
applications all cover R[i]'s (or use `any`).

Each returned dict is the original rule dict augmented with `shadowed_by` —
the name of the first earlier rule that shadows it.

#### `run_policy_audit(conn: DeviceConnection) -> dict`
Run a full security policy audit against a connected device.

Returns: `policy`, `stats`, `unused_rules`, `shadowed_rules`, `rule_count`,
`alert`, `error`.

#### `check_ha(conn: DeviceConnection) -> dict`
Return HA state check result.

Returns: `enabled`, `mode`, `local_state`, `peer_state`, `peer_ip`, `alert`, `error`.

#### `check_sessions(conn: DeviceConnection, threshold: float) -> dict`
Return session table utilization check result.

Returns: `max_sessions`, `active_sessions`, `session_utilization`, `threshold`,
`alert`, `error`.

#### `check_threat_status(conn: DeviceConnection) -> dict`
Return threat and URL filtering content status (informational).

Returns: `threat_version`, `url_version`, `ha_mode`, `alert` (always `False`), `error`.

#### `run_health_check(params: ConnectionParams, session_threshold: float = DEFAULT_SESSION_THRESHOLD) -> dict`
Run all PAN-OS-specific health checks (HA state, sessions, threat status).

Returns: `host`, `timestamp`, `success`, `checks`, `overall_alert`, `error`.

#### `main() -> None`
CLI entry point for the Palo Alto PAN-OS security policy auditor.
