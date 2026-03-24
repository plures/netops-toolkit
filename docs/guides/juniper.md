# Juniper JunOS Health Check Guide

netops-toolkit provides a comprehensive health-check module for Juniper JunOS
devices (MX, QFX, EX, SRX).  All checks are **read-only** — no configuration
is modified.

## Supported Device Types

| `vendor` value     | Netmiko driver       | Typical hardware                    |
|--------------------|----------------------|-------------------------------------|
| `juniper_junos`    | `juniper_junos`      | MX, QFX, EX, SRX (JunOS 18.x+)    |
| `juniper`          | `juniper`            | Older JunOS (legacy driver)         |

## Checks Performed

| Check               | Command                           | Alert condition                                      |
|---------------------|-----------------------------------|------------------------------------------------------|
| RE CPU & Memory     | `show chassis routing-engine`     | Any RE CPU ≥ threshold (default 80%) or memory ≥ threshold (default 85%) |
| FPC status          | `show chassis fpc`                | Any non-empty FPC slot is not Online                 |
| Interface errors    | `show interfaces extensive`       | Any interface has non-zero error/drop counters       |
| BGP                 | `show bgp summary`                | Any peer not in Established state                    |
| OSPF                | `show ospf neighbor`              | Any adjacency not in Full state                      |
| Chassis alarms      | `show chassis alarms`             | Any **Major** alarm is active                        |
| Environment         | `show chassis environment`        | Any power supply, fan, or temperature sensor not OK  |
| Route summary       | `show route summary`              | Informational only (never alerts)                    |

## Inventory Configuration

```yaml
defaults:
  username: netops
  transport: ssh

devices:
  mx-core-01:
    host: 10.0.1.1
    vendor: juniper_junos
    groups: [core, juniper]

  qfx-leaf-01:
    host: 10.0.1.2
    vendor: juniper_junos
    groups: [fabric, juniper]

  srx-fw-01:
    host: 10.0.1.3
    vendor: juniper_junos
    groups: [security, juniper]
```

## Running from the CLI

```bash
# Single device — all checks with default thresholds
python -m netops.check.juniper --host 10.0.1.1 --user netops \
    --threshold cpu=80,mem=85 --json

# All devices in group
python -m netops.check.juniper \
    --inventory examples/inventory.yaml \
    --group juniper \
    --threshold cpu=80,mem=85

# Skip BGP and OSPF (e.g. pure L2 fabric switches)
python -m netops.check.juniper --host 10.0.1.2 --user netops \
    --no-bgp --no-ospf

# Exit with code 1 if any alert fires (useful in CI/CD pipelines)
python -m netops.check.juniper --inventory inv.yaml --group core \
    --fail-on-alert

# JSON output — pipe to jq for filtering
python -m netops.check.juniper --host 10.0.1.1 --user netops --json \
    | jq '.checks.alarms'
```

### CLI Options

| Flag                | Description                                                     |
|---------------------|-----------------------------------------------------------------|
| `--host IP`         | Single device IP or hostname                                    |
| `--inventory FILE`  | YAML/JSON inventory file                                        |
| `--group GROUP`     | Filter inventory to a specific group                            |
| `--vendor STRING`   | Netmiko device type (default: `juniper_junos`)                  |
| `--user USER`       | SSH username (or set `NETOPS_PASSWORD` env var for password)    |
| `--threshold K=V`   | Alert thresholds, e.g. `cpu=80,mem=85`                         |
| `--no-bgp`          | Skip BGP neighbour checks                                       |
| `--no-ospf`         | Skip OSPF adjacency checks                                      |
| `--json`            | Output results as JSON                                          |
| `--fail-on-alert`   | Exit with code 1 when any alert fires                           |

## Using from Python

```python
from netops.core.connection import ConnectionParams
from netops.check.juniper import run_health_check, build_junos_health_report

params = ConnectionParams(
    host="10.0.1.1",
    username="netops",
    password="secret",
    device_type="juniper_junos",
)

result = run_health_check(params, cpu_threshold=80, mem_threshold=85)

if result["overall_alert"]:
    print("⚠️  Alerts detected!")

checks = result["checks"]
print(f"RE CPU: {checks['re']['cpu_utilization']}%")
print(f"RE MEM: {checks['re']['mem_utilization']}%")
print(f"FPC offline: {checks['fpc']['offline']}")
print(f"BGP not-established: {checks['bgp']['not_established']}")
print(f"OSPF not-full: {checks['ospf']['not_full']}")
print(f"Major alarms: {checks['alarms']['major_count']}")
```

### Aggregating Multiple Devices

```python
from netops.check.juniper import build_junos_health_report

results = [run_health_check(p) for p in device_params_list]
report = build_junos_health_report(results)

print(f"Devices polled : {report['devices']}")
print(f"Reachable      : {report['devices_reachable']}")
print(f"With alerts    : {report['devices_with_alerts']}")
print(f"RE alerts      : {report['re_alerts']}")
print(f"FPC alerts     : {report['fpc_alerts']}")
print(f"BGP alerts     : {report['bgp_alerts']}")
print(f"Alarm alerts   : {report['alarm_alerts']}")
```

## Parsers

The individual parsers in `netops.parsers.juniper` can be used directly when
you already have CLI output (e.g. collected via `netops.collect`):

```python
from netops.parsers.juniper import (
    parse_re_status,
    parse_fpc_status,
    parse_interface_errors_junos,
    parse_bgp_summary_junos,
    parse_ospf_neighbors_junos,
    parse_chassis_alarms,
    parse_chassis_environment,
    parse_route_summary,
)

# --- Routing Engine ---
re_data = parse_re_status(re_output)
for re in re_data:
    print(f"RE{re['slot']}: {re['mastership']}  CPU={re['cpu_util']}%  "
          f"MEM={re['memory_util']}%  temp={re['temperature']}°C")

# --- FPC ---
for fpc in parse_fpc_status(fpc_output):
    status = "✅" if fpc["ok"] else "❌"
    print(f"{status} FPC{fpc['slot']}: {fpc['state']}")

# --- BGP ---
for peer in parse_bgp_summary_junos(bgp_output):
    print(f"  {peer['neighbor']}  AS{peer['peer_as']}  {peer['state']}")

# --- Chassis alarms ---
for alarm in parse_chassis_alarms(alarm_output):
    print(f"  [{alarm['class_']}] {alarm['description']}")

# --- Chassis environment ---
env = parse_chassis_environment(env_output)
print(f"Environment OK: {env['overall_ok']}")
```

## Result Schema

`run_health_check()` returns:

```json
{
  "host": "10.0.1.1",
  "timestamp": "2024-03-15T10:00:00Z",
  "success": true,
  "overall_alert": false,
  "checks": {
    "re": {
      "routing_engines": [...],
      "cpu_utilization": 5.0,
      "mem_utilization": 65.0,
      "cpu_threshold": 80.0,
      "mem_threshold": 85.0,
      "cpu_alert": false,
      "mem_alert": false,
      "alert": false
    },
    "fpc": {
      "fpcs": [...],
      "total": 4,
      "online": 2,
      "offline": 0,
      "alert": false
    },
    "interfaces": {
      "interfaces": [...],
      "total": 48,
      "with_errors": 0,
      "alert": false
    },
    "bgp": {
      "peers": [...],
      "total": 3,
      "established": 3,
      "not_established": 0,
      "alert": false
    },
    "ospf": {
      "neighbors": [...],
      "total": 2,
      "full": 2,
      "not_full": 0,
      "alert": false
    },
    "alarms": {
      "alarms": [],
      "major_count": 0,
      "minor_count": 0,
      "alert": false
    },
    "environment": {
      "power_supplies": [...],
      "fans": [...],
      "temperatures": [...],
      "overall_ok": true,
      "alert": false
    },
    "routes": {
      "tables": [
        {"table": "inet.0", "active_routes": 1204, "total_routes": 1219,
         "holddown_routes": 0, "hidden_routes": 0}
      ],
      "alert": false
    }
  }
}
```

## Modes: XML RPC vs CLI Text

This module uses **CLI text** mode (Netmiko's standard SSH + CLI scraping).
JunOS XML RPC (NETCONF / `junos-eznc`) is **not** required.

If you prefer XML RPC, you can use the `netops.parsers.juniper` parsers
independently with your own NETCONF/PyEZ integration, passing the converted
text output.

## Supported JunOS Versions

The parsers have been tested against CLI output from JunOS **18.1** through
**22.4**.  Minor formatting differences across software versions are handled
by the flexible regex-based parsers.
