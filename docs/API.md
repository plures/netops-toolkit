# netops-toolkit API

Public modules and key entry points.

## Core

### `netops.core.connection`

**Enums / Dataclasses**
- `Transport` — `SSH`, `SSH2`, `TELNET`
- `AuthMethod` — `PASSWORD`, `KEY`, `KEY_PASSWORD`
- `ConnectionParams`
  - `effective_port: int` property

**Class**
- `DeviceConnection`
  - `connect(): None`
  - `disconnect(): None`
  - `send(command: str, expect_string: str | None = None): str`
  - `send_config(commands: list[str]): str`

### `netops.core.inventory`

**Dataclass**
- `Device` — `hostname`, `host`, `vendor`, auth fields, tags/metadata

**Class**
- `Inventory`
  - `add(device: Device): None`
  - `get(hostname: str): Device | None`
  - `filter(group?: str, vendor?: str, role?: str, site?: str, tag?: tuple): list[Device]`
  - `from_file(path: str | Path): Inventory`
  - `to_ansible(): dict`
  - `to_ansible_yaml(): str`
  - `to_ansible_json(): str`
  - `to_file(path: str | Path, format: str = "yaml"): None`

**Re-exports** (from `netops.core`)
- `DeviceConnection`, `Device`, `Inventory`

## Reports (`netops.report`)

**Classes**
- `ReportGenerator` — `build_report()`, `generate_html()`, `generate_pdf()`
- `ReportMailer` — SMTP email sender for reports
- `ReportScheduler` — cron-style scheduled report generation

**Functions**
- `generate_report(...)` — convenience wrapper to build + render
- `default_output_filename(prefix: str | None = None): str`
- `aggregate_dashboard(results: dict): dict`
- `format_table(rows: list[dict], columns: list[str]): str`
- `render_html(report_data: dict): str`

## Checks / Parsers / Templates

These are vendor-specific helpers for health checks and output parsing. Import from their modules:

- `netops.check.*` — validation checks (health, bgp, vlan, interfaces, vendor-specific)
- `netops.parsers.*` — CLI output parsers (cisco, juniper, arista, paloalto, nokia, brocade, bgp, vlan)
- `netops.templates.*` — command templates per vendor

## Change Management (`netops.change`)

Modules:
- `diff` — config diff engine
- `plan` — change approval workflow
- `push` — safe config push with confirm timer
- `rollback` — rollback automation

## Playbooks (`netops.playbooks`)

- `generator` — produce Ansible remediation playbooks from check failures

## Ansible Integration (`netops.ansible`)

- `dynamic_inventory` — Ansible-compatible dynamic inventory script

## Inventory Scanning (`netops.inventory.scan`)

- Device discovery utilities (see module docstring for usage)
