# Palo Alto Networks Firewall Support

netops-toolkit supports Palo Alto Networks firewalls running PAN-OS via the
`paloalto_panos` vendor type.  SSH connectivity is handled by Netmiko
(`paloalto_panos` driver) and all commands are read-only by default — no
configuration is pushed unless `commit` is explicitly invoked.

## Supported Device Types

| `vendor` value    | Netmiko driver      | Typical hardware                |
|-------------------|---------------------|---------------------------------|
| `paloalto_panos`  | `paloalto_panos`    | PA-220, PA-800, PA-3200, PA-5200, PA-7000 series |

## Inventory Configuration

Add Palo Alto firewalls to your inventory YAML file:

```yaml
defaults:
  username: admin
  transport: ssh

devices:
  paloalto-fw-01:
    host: 10.0.4.1
    vendor: paloalto_panos
    role: edge
    site: dc1
    groups: [firewalls, edge, dc1, paloalto]
    tags:
      environment: production
      platform: PA-3220
      ha_role: active

  paloalto-fw-02:
    host: 10.0.4.2
    vendor: paloalto_panos
    role: edge
    site: dc1
    groups: [firewalls, edge, dc1, paloalto]
    tags:
      environment: production
      platform: PA-3220
      ha_role: passive
```

## Command Templates

Import the template dict to get vendor-normalised command strings:

```python
from netops.templates.paloalto import SHOW, HEALTH

# Show commands
print(SHOW["system_info"])       # show system info
print(SHOW["interfaces"])        # show interface all
print(SHOW["routes"])            # show routing route
print(SHOW["sessions"])          # show session info
print(SHOW["security_policy"])   # show running security-policy
print(SHOW["ha_state"])          # show high-availability state

# Health commands
print(HEALTH["resources"])       # show system resources follow duration 1
print(HEALTH["session_info"])    # show session info
print(HEALTH["ha_state"])        # show high-availability state
```

## CLI Parsers

### System information

```python
from netops.parsers.paloalto import parse_system_info

output = """
Hostname: pa-fw-01
IP address: 10.0.0.1
Model: PA-3220
Serial: 0123456789AB
PAN-OS Version: 10.2.3
App version: 8700-7709
Threat version: 8700-7709
URL filtering version: 20231201.20079
HA mode: Active-Passive
HA state: active
"""

info = parse_system_info(output)
# {
#   "hostname":       "pa-fw-01",
#   "ip_address":     "10.0.0.1",
#   "model":          "PA-3220",
#   "serial":         "0123456789AB",
#   "panos_version":  "10.2.3",
#   "app_version":    "8700-7709",
#   "threat_version": "8700-7709",
#   "url_version":    "20231201.20079",
#   "ha_mode":        "Active-Passive",
#   "ha_state":       "active",
# }
```

### Interface state

```python
from netops.parsers.paloalto import parse_interfaces

output = """
Name            State   IP (prefix)          VSys   Zone
ethernet1/1     up      10.0.1.1/24          vsys1  trust
ethernet1/2     up      203.0.113.1/30       vsys1  untrust
ethernet1/3     down    unassigned           vsys1
loopback.1      up      1.1.1.1/32           vsys1
"""

interfaces = parse_interfaces(output)
# [
#   {"name": "ethernet1/1", "state": "up",   "ip": "10.0.1.1/24",     "vsys": "vsys1", "zone": "trust",   "up": True},
#   {"name": "ethernet1/2", "state": "up",   "ip": "203.0.113.1/30",  "vsys": "vsys1", "zone": "untrust", "up": True},
#   {"name": "ethernet1/3", "state": "down", "ip": None,              "vsys": "vsys1", "zone": None,      "up": False},
#   {"name": "loopback.1",  "state": "up",   "ip": "1.1.1.1/32",      "vsys": "vsys1", "zone": None,      "up": True},
# ]
```

### Routing table

```python
from netops.parsers.paloalto import parse_routes

output = """
destination         nexthop         metric  flags  age   interface
0.0.0.0/0           10.0.0.1        10      A S    1d    ethernet1/2
10.0.1.0/24         0.0.0.0         0       A C    -     ethernet1/1
"""

routes = parse_routes(output)
# [
#   {"destination": "0.0.0.0/0",   "nexthop": "10.0.0.1", "metric": 10, "flags": "A S",
#    "active": True, "type": "S", "age": "1d",  "interface": "ethernet1/2"},
#   {"destination": "10.0.1.0/24", "nexthop": "0.0.0.0",  "metric": 0,  "flags": "A C",
#    "active": True, "type": "C", "age": None,  "interface": "ethernet1/1"},
# ]
```

### Session table

```python
from netops.parsers.paloalto import parse_session_info

output = """
Number of sessions supported:      131072
Number of active sessions:         1234
Number of active TCP sessions:     1000
Number of active UDP sessions:     200
Number of active ICMP sessions:    34
Session utilization:               1%
"""

info = parse_session_info(output)
# {
#   "max_sessions":        131072,
#   "active_sessions":     1234,
#   "active_tcp":          1000,
#   "active_udp":          200,
#   "active_icmp":         34,
#   "session_utilization": 1.0,
# }
```

### Security policy

```python
from netops.parsers.paloalto import parse_security_policy

output = """
Rule: web-access
  from trust
  to untrust
  source [ any ]
  destination [ any ]
  application [ web-browsing ssl ]
  service [ application-default ]
  action allow
"""

rules = parse_security_policy(output)
# [
#   {
#     "name":         "web-access",
#     "from_zones":   ["trust"],
#     "to_zones":     ["untrust"],
#     "sources":      ["any"],
#     "destinations": ["any"],
#     "applications": ["web-browsing", "ssl"],
#     "services":     ["application-default"],
#     "action":       "allow",
#   },
# ]
```

### HA state

```python
from netops.parsers.paloalto import parse_ha_state

output = """
Group 1:
  Mode: Active-Passive
  Local state: active
  Peer state: passive
  Peer IP: 10.0.0.2
  Preemptive: no
"""

ha = parse_ha_state(output)
# {
#   "enabled":     True,
#   "mode":        "Active-Passive",
#   "local_state": "active",
#   "peer_state":  "passive",
#   "peer_ip":     "10.0.0.2",
#   "preemptive":  False,
# }
```

## Security Policy Audit

The security policy audit checks for:

* **Unused rules** — rules with a hit count of zero (never matched traffic)
* **Shadowed rules** — rules that will never match because an earlier,
  broader rule already covers the same traffic

```python
from netops.check.paloalto import check_unused_rules, check_shadowed_rules
from netops.parsers.paloalto import parse_security_policy, parse_security_policy_stats

policy = parse_security_policy(policy_output)
stats  = parse_security_policy_stats(stats_output)

unused   = check_unused_rules(policy, stats)
shadowed = check_shadowed_rules(policy)
```

### Running from the CLI

```bash
# Policy audit — single device
python -m netops.check.paloalto --host 10.0.4.1 --audit

# Policy audit — all firewalls in inventory group
python -m netops.check.paloalto \
    --inventory examples/inventory.yaml \
    --group paloalto \
    --audit --json

# Health checks — HA state, sessions, content versions
python -m netops.check.paloalto \
    --host 10.0.4.1 \
    --health \
    --session-threshold 80
```

Example audit output:

```
✅ Policy audit — 5 rules total
   ⚠️  UNUSED RULES (2):
      • unused-rule  (action: allow)
      • block-all    (action: deny)
   ✅ No shadowed rules
```

Example health output:

```
✅ 10.0.4.1 [2024-03-24T06:00:00Z]
   HA : mode=Active-Passive  local=active  peer=passive
   SESSIONS : 1234 active  (1.0% of 131072)
   CONTENT : threat=8700-7709  url=20231201.20079
```

## Standard Health Checks

Palo Alto devices are automatically detected in the standard health check
module when the `vendor` field contains `paloalto` or `panos`.  CPU and
memory are parsed from the `show system resources` output.

```bash
# Standard health check (CPU, memory, interface errors, logs)
python -m netops.check.health \
    --inventory examples/inventory.yaml \
    --group paloalto \
    --threshold cpu=80,mem=85

# Single device
python -m netops.check.health \
    --host 10.0.4.1 \
    --vendor paloalto_panos \
    --threshold cpu=80,mem=85 \
    --json
```

## Safe-by-Default / Commit Model

PAN-OS uses a two-phase commit model: changes made via CLI enter a
*candidate configuration* and are not applied until `commit` is issued.
netops-toolkit is **read-only by default** — it never pushes or commits
configuration unless you explicitly call `conn.send_config(...)` followed
by `conn.send("commit")` in your own automation scripts.

## Automatic Vendor Detection (SNMP scan)

When scanning a subnet, Palo Alto devices can be identified from their
SNMP `sysDescr`:

```bash
python -m netops.inventory.scan --subnet 10.0.4.0/24 --community public
```

| sysDescr keyword         | Detected as        |
|--------------------------|--------------------|
| `Palo Alto`, `PAN-OS`    | `paloalto_panos`   |
