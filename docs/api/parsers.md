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

::: netops.parsers.arista

---

## `netops.parsers.bgp`

Cisco IOS/IOS-XE/IOS-XR BGP summary parsers.

::: netops.parsers.bgp

---

## `netops.parsers.brocade`

Brocade FastIron/ICX and Network OS/VDX CLI output parsers.

::: netops.parsers.brocade

---

## `netops.parsers.cisco`

Cisco IOS/IOS-XE CLI output parsers — OSPF neighbors, environment,
version, inventory, and serial number.

::: netops.parsers.cisco

---

## `netops.parsers.health`

Multi-vendor CPU, memory, interface error, and log parsers.

::: netops.parsers.health

---

## `netops.parsers.juniper`

Juniper JunOS CLI output parsers — Routing Engine, FPC, BGP, OSPF,
chassis alarms, environment, and route summary.

::: netops.parsers.juniper

---

## `netops.parsers.nokia_sros`

Nokia SR-OS CLI output parsers — interfaces, BGP, OSPF, system info,
chassis, environment, routes, and LSPs.

::: netops.parsers.nokia_sros

---

## `netops.parsers.paloalto`

Palo Alto PAN-OS CLI output parsers — system info, interfaces, routes,
sessions, security policy, and HA state.

::: netops.parsers.paloalto

---

## `netops.parsers.vlan`

Cisco VLAN CLI parsers — VLAN brief table, trunk interfaces.

::: netops.parsers.vlan
