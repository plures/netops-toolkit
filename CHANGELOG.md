# Changelog

All notable changes to netops-toolkit are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added
- **Brocade router support** (PR #18) — full vendor integration:
  - `netops/templates/brocade.py`: `SHOW` and `HEALTH` command template dicts
    for FastIron/ICX and Fabric OS (SAN) devices.
  - `netops/parsers/brocade.py`: CLI output parsers —
    `parse_interfaces`, `parse_ip_routes`, `parse_version`, `parse_fabric`.
  - `netops/parsers/health.py`: Brocade health parsers —
    `parse_cpu_brocade`, `parse_memory_brocade`,
    `parse_interface_errors_brocade`, `parse_logs_brocade`.
  - `netops/check/health.py`: `_is_brocade()` helper; CPU, memory, interface
    error, and log checks routed to Brocade parsers when
    `vendor` contains `brocade`.
  - `netops/inventory/scan.py`: `identify_vendor()` now recognises Brocade
    devices from `sysDescr` keywords (`Brocade`, `Foundry`, `FastIron`,
    `Brocade Network OS`) and enterprise OIDs
    (`1.3.6.1.4.1.1991.*` → `brocade_fastiron`,
     `1.3.6.1.4.1.1588.*` → `brocade_nos`).
  - `examples/inventory.yaml`: added `brocade-rtr-01` and `brocade-vdx-01`
    example device entries.
  - `docs/guides/brocade.md`: new vendor guide covering inventory
    configuration, command templates, CLI parsers, health checks, and SNMP
    auto-detection.

---

## [0.11.2] — 2024-03-24

### Changed
- Internal release; no user-facing changes.
