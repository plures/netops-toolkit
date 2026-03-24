# Cisco IOS/IOS-XE Health Check Guide

netops-toolkit provides a comprehensive health-check module for Cisco IOS 15.x+
and IOS-XE 16.x+ devices.  All checks are **read-only** — no configuration is
modified.

## Supported Device Types

| `vendor` value | Netmiko driver   | Typical hardware                        |
|----------------|------------------|-----------------------------------------|
| `cisco_ios`    | `cisco_ios`      | ISR, Catalyst (IOS 15.x+)              |
| `cisco_xe`     | `cisco_xe`       | ASR, CSR, Catalyst 9000 (IOS-XE 16.x+) |
| `cisco_xr`     | `cisco_xr`       | ASR 9000, NCS (IOS-XR) — BGP only      |

## Checks Performed

| Check            | Command                    | Alert condition                     |
|------------------|----------------------------|-------------------------------------|
| CPU              | `show processes cpu`       | 1-min average ≥ threshold (default 80%) |
| Memory           | `show processes memory`    | Used % ≥ threshold (default 85%)   |
| Interface errors | `show interfaces`          | Any interface has non-zero CRC/input/output errors or drops |
| Syslog           | `show logging`             | Severity 0–3 events present         |
| BGP              | `show ip bgp summary`      | Any peer not in Established state   |
| OSPF             | `show ip ospf neighbor`    | Any adjacency not in FULL state     |
| Environment      | `show environment all`     | Any fan/temperature/PSU not OK      |
| Uptime/reload    | `show version`             | Informational only (never alerts)   |

## Inventory Configuration

```yaml
defaults:
  username: admin
  transport: ssh

devices:
  core-sw-01:
    host: 10.0.1.1
    vendor: cisco_ios
    groups: [core, cisco]

  dist-sw-01:
    host: 10.0.1.2
    vendor: cisco_xe
    groups: [distribution, cisco]
```

## Running from the CLI

```bash
# Single device — all checks
python -m netops.check.cisco --host 10.0.1.1 --user admin \
    --threshold cpu=80,mem=85 --json

# All devices in group
python -m netops.check.cisco \
    --inventory examples/inventory.yaml \
    --group cisco \
    --threshold cpu=80,mem=85

# Skip BGP and OSPF (e.g. pure L2 switch)
python -m netops.check.cisco --host 10.0.1.1 --user admin \
    --no-bgp --no-ospf

# Exit with code 1 when any alert fires (for CI/CD gates)
python -m netops.check.cisco \
    --inventory examples/inventory.yaml \
    --fail-on-alert
```

Example output:

```
✅ 10.0.1.1 [2026-03-24T12:00:00Z]
   CPU : 8.0% (threshold 80.0%)
   MEM : 35.0% (threshold 85.0%)
   IFACE ERRORS: 0/24 interfaces with errors
   LOGS: 0 critical, 0 major
   BGP: 4/4 established (0 down)
   OSPF: 3/3 FULL (0 not FULL)
   ENV: OK  fans=2  temps=2  psu=2
   UPTIME: 10 weeks, 2 days, 14 hours, 56 minutes  IOS 16.12.4
   RELOAD: Reload command
```

## Python API

### Running all checks

```python
from netops.check.cisco import run_cisco_health_check, build_cisco_health_report
from netops.core.connection import ConnectionParams

params = ConnectionParams(
    host="10.0.1.1",
    username="admin",
    password="s3cr3t",
    device_type="cisco_ios",
)

result = run_cisco_health_check(
    params,
    cpu_threshold=80.0,
    mem_threshold=85.0,
    include_bgp=True,
    include_ospf=True,
    include_environment=True,
)

print(result["overall_alert"])   # True / False
print(result["checks"]["cpu"]["utilization"])
print(result["checks"]["bgp"]["not_established"])
print(result["checks"]["ospf"]["not_full"])
print(result["checks"]["uptime"]["uptime"])
```

### Aggregated report across multiple routers

```python
results = [run_cisco_health_check(p) for p in device_params]
report  = build_cisco_health_report(results)

print(report["devices"])               # total devices polled
print(report["bgp_alerts"])            # devices with BGP peer(s) down
print(report["ospf_alerts"])           # devices with OSPF adjacency issues
print(report["environment_alerts"])    # devices with hardware issues
```

### Individual check functions

```python
from netops.check.cisco import (
    check_cisco_cpu,
    check_cisco_memory,
    check_cisco_interfaces,
    check_cisco_logs,
    check_cisco_bgp,
    check_cisco_ospf,
    check_cisco_environment,
    check_cisco_uptime,
)

with DeviceConnection(params) as conn:
    cpu  = check_cisco_cpu(conn, threshold=80.0)
    mem  = check_cisco_memory(conn, threshold=85.0)
    ifc  = check_cisco_interfaces(conn)
    logs = check_cisco_logs(conn)
    bgp  = check_cisco_bgp(conn)
    ospf = check_cisco_ospf(conn)
    env  = check_cisco_environment(conn)
    ver  = check_cisco_uptime(conn)
```

## Parsers

### OSPF neighbors

```python
from netops.parsers.cisco import parse_ospf_neighbors

output = """
Neighbor ID     Pri   State           Dead Time   Address         Interface
192.168.1.2       1   FULL/DR         00:00:37    10.0.0.2        GigabitEthernet0/0
192.168.1.3       1   FULL/BDR        00:00:38    10.0.0.3        GigabitEthernet0/0
192.168.1.4       0   INIT/DROTHER    00:00:35    10.0.0.4        GigabitEthernet0/1
"""

neighbors = parse_ospf_neighbors(output)
# [
#   {"neighbor_id": "192.168.1.2", "priority": 1, "state": "FULL/DR",
#    "dead_time": "00:00:37", "address": "10.0.0.2",
#    "interface": "GigabitEthernet0/0", "is_full": True},
#   {"neighbor_id": "192.168.1.3", "priority": 1, "state": "FULL/BDR",
#    "dead_time": "00:00:38", "address": "10.0.0.3",
#    "interface": "GigabitEthernet0/0", "is_full": True},
#   {"neighbor_id": "192.168.1.4", "priority": 0, "state": "INIT/DROTHER",
#    "dead_time": "00:00:35", "address": "10.0.0.4",
#    "interface": "GigabitEthernet0/1", "is_full": False},
# ]
```

### Environment

```python
from netops.parsers.cisco import parse_environment_cisco

output = """
Switch 1 FAN 1 is OK
Switch 1 FAN 2 is OK
Switch 1: TEMPERATURE is OK
SYSTEM INLET       : 28 Celsius, Critical threshold is 60 Celsius
SYSTEM OUTLET      : 35 Celsius, Critical threshold is 65 Celsius
Switch 1: POWER-SUPPLY 1 is PRESENT
Switch 1: POWER-SUPPLY 2 is NOT PRESENT
"""

env = parse_environment_cisco(output)
# {
#   "fans":           [{"name": "FAN1", "status": "OK", "ok": True}, ...],
#   "temperatures":   [{"name": "TEMPERATURE", "celsius": None, "status": "OK", "ok": True},
#                      {"name": "SYSTEM INLET", "celsius": 28, "status": "OK", "ok": True}, ...],
#   "power_supplies": [{"name": "PS1", "status": "PRESENT", "ok": True},
#                      {"name": "PS2", "status": "NOT PRESENT", "ok": False}],
#   "overall_ok":     False,   # PS2 not present
# }
```

### Version / uptime

```python
from netops.parsers.cisco import parse_version_cisco

output = """
Cisco IOS XE Software, Version 16.12.4
cisco C9300-48P (X86) processor with 1393712K bytes of memory.
Router uptime is 10 weeks, 2 days, 14 hours, 56 minutes
Last reload reason: Reload command
System image file is "bootflash:cat9k_iosxe.16.12.04.SPA.bin"
"""

info = parse_version_cisco(output)
# {
#   "version":       "16.12.4",
#   "platform":      "C9300-48P",
#   "uptime":        "10 weeks, 2 days, 14 hours, 56 minutes",
#   "reload_reason": "Reload command",
#   "image":         "bootflash:cat9k_iosxe.16.12.04.SPA.bin",
# }
```

## Command Templates

```python
from netops.templates.cisco_ios import SHOW, HEALTH

# Standard show commands
print(SHOW["version"])          # show version
print(SHOW["ospf_neighbors"])   # show ip ospf neighbor
print(SHOW["environment"])      # show environment all

# Health check commands
print(HEALTH["cpu"])            # show processes cpu sorted | head 20
print(HEALTH["memory"])         # show processes memory sorted | head 20
print(HEALTH["bgp_summary"])    # show ip bgp summary
print(HEALTH["ospf_neighbors"]) # show ip ospf neighbor
print(HEALTH["environment"])    # show environment all
print(HEALTH["version"])        # show version
```

## Result Schema

Every check function returns a dict that always includes an ``alert`` key.
The composite `run_cisco_health_check` wraps all checks under a ``checks``
dict and sets ``overall_alert`` when any individual check fires:

```json
{
  "host": "10.0.1.1",
  "timestamp": "2026-03-24T12:00:00Z",
  "success": true,
  "checks": {
    "cpu":              {"utilization": 8.0,  "threshold": 80.0, "alert": false, "raw": {...}},
    "memory":           {"utilization": 35.0, "threshold": 85.0, "alert": false, "raw": {...}},
    "interface_errors": {"total": 24, "with_errors": 0, "alert": false, "interfaces": [...]},
    "logs":             {"critical_count": 0, "major_count": 0,  "alert": false, "events": []},
    "bgp":              {"total": 4, "established": 4, "not_established": 0, "alert": false, "peers": [...]},
    "ospf":             {"total": 3, "full": 3, "not_full": 0, "alert": false, "neighbors": [...]},
    "environment":      {"overall_ok": true,  "alert": false, "fans": [...], "temperatures": [...], "power_supplies": [...]},
    "uptime":           {"uptime": "10 weeks, ...", "version": "16.12.4", "reload_reason": "Reload command", "alert": false}
  },
  "overall_alert": false,
  "error": null
}
```
