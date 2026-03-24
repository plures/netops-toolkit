# Brocade Router Support

netops-toolkit supports Brocade FastIron/ICX routers and switches (via
`brocade_fastiron`) as well as Brocade Network OS devices (via `brocade_nos`).
Both use standard SSH transport through Netmiko.

## Supported Device Types

| `vendor` value       | Netmiko driver        | Typical hardware          |
|----------------------|-----------------------|---------------------------|
| `brocade_fastiron`   | `brocade_fastiron`    | ICX 7xxx, FastIron series |
| `brocade_nos`        | `brocade_nos`         | VDX series (Network OS)   |

## Inventory Configuration

Add Brocade devices to your inventory YAML file:

```yaml
defaults:
  username: admin
  transport: ssh

devices:
  brocade-rtr-01:
    host: 10.0.3.1
    vendor: brocade_fastiron
    role: core
    site: dc1
    groups: [routers, core, dc1, brocade]
    tags:
      environment: production
      platform: ICX7550

  brocade-vdx-01:
    host: 10.0.3.2
    vendor: brocade_nos
    role: distribution
    site: dc1
    groups: [switches, distribution, dc1, brocade]
    tags:
      environment: production
      platform: VDX6740
```

## Command Templates

Import the template dict to get vendor-normalised command strings:

```python
from netops.templates.brocade import SHOW, HEALTH

# Show commands
print(SHOW["version"])            # show version
print(SHOW["interfaces"])         # show interface brief
print(SHOW["routes"])             # show ip route
print(SHOW["fabric"])             # show fabric  (FOS SAN switches)

# Health commands
print(HEALTH["cpu"])              # show cpu
print(HEALTH["memory"])           # show memory
print(HEALTH["interface_errors"]) # show interfaces | include error|discard|drop
```

## CLI Parsers

### Interface state

```python
from netops.parsers.brocade import parse_interfaces

output = """
GigabitEthernet1/1/1 is up, line protocol is up
GigabitEthernet1/1/2 is down, line protocol is down
"""

interfaces = parse_interfaces(output)
# [
#   {"name": "GigabitEthernet1/1/1", "status": "up", "protocol": "up",  "up": True},
#   {"name": "GigabitEthernet1/1/2", "status": "down","protocol": "down","up": False},
# ]
```

### IP routing table

```python
from netops.parsers.brocade import parse_ip_routes

output = """
B    10.0.0.0/8         192.168.1.254    e1/1  1
C    192.168.1.0/24     DIRECT           e1/2  1
S    0.0.0.0/0          10.0.0.1         e1/1  1
"""

routes = parse_ip_routes(output)
# [
#   {"type": "B", "network": "10.0.0.0/8",    "next_hop": "192.168.1.254", "interface": "e1/1", "metric": 1},
#   {"type": "C", "network": "192.168.1.0/24","next_hop": "DIRECT",        "interface": "e1/2", "metric": 1},
#   {"type": "S", "network": "0.0.0.0/0",     "next_hop": "10.0.0.1",      "interface": "e1/1", "metric": 1},
# ]
```

### Software version

```python
from netops.parsers.brocade import parse_version

output = """
HW: ICX7550-48
SW: Version 09.0.10T215 Copyright (c) 1996-2023 Ruckus Networks, Inc.
"""

info = parse_version(output)
# {"model": "ICX7550-48", "version": "09.0.10T215", "vendor": "Brocade"}
```

### Fabric state (FOS SAN switches)

```python
from netops.parsers.brocade import parse_fabric

output = """
Fabric Name: FabricA
Fabric OS:  v9.1.0
Switch: fc-sw-01 (domain 1)
  Port 0/1: Online
  Port 0/2: Offline
"""

fabric = parse_fabric(output)
# {
#   "fabric_name": "FabricA",
#   "fabric_os":   "v9.1.0",
#   "switches":    [{"name": "fc-sw-01", "domain": 1}],
#   "ports":       [{"port": "0/1", "state": "Online"}, {"port": "0/2", "state": "Offline"}],
# }
```

## Health Checks

Brocade devices are automatically detected when the `vendor` field contains
`brocade`.  All four standard checks — CPU, memory, interface errors, and logs
— are supported.

```bash
# Run health checks against all Brocade devices in an inventory group
python -m netops.check.health \
    --inventory examples/inventory.yaml \
    --group brocade \
    --threshold cpu=80,mem=85

# Single device
python -m netops.check.health \
    --host 10.0.3.1 \
    --vendor brocade_fastiron \
    --threshold cpu=80,mem=85 \
    --json
```

Example output:

```
✅ 10.0.3.1 [2024-03-24T06:00:00Z]
   CPU : 12.0% (threshold 80.0%)
   MEM : 48.8% (threshold 85.0%)
   IFACE ERRORS: 0/24 interfaces with errors
   LOGS: 0 critical, 0 major
```

## Automatic Vendor Detection (SNMP scan)

When scanning a subnet, Brocade devices are identified automatically from their
SNMP `sysDescr` or enterprise OID:

```bash
python -m netops.inventory.scan --subnet 10.0.3.0/24 --community public
```

| sysDescr keyword            | OID prefix                | Detected as        |
|-----------------------------|---------------------------|--------------------|
| `Brocade`, `Foundry`, `FastIron` | `1.3.6.1.4.1.1991.`  | `brocade_fastiron` |
| `Brocade Network OS`        | `1.3.6.1.4.1.1588.`       | `brocade_nos`      |
