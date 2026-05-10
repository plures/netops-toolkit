## [0.37.0] — 2026-05-10

- feat: add offline bundle to release pipeline + TUI (63f7b23)
- docs: refresh ROADMAP.md with OASIS strategic alignment (00856d3)
- docs: update copilot-instructions with praxis, design-dojo, automation rules (d44a03f)
- feat(release): add target_version input for milestone-driven releases (722f061)
- feat(lifecycle): milestone-close triggers roadmap-aware release (a02cd25)
- docs: update copilot-instructions with Plures stack architecture (efdb797)
- docs: update copilot-instructions with Plures stack architecture (e5d78dc)
- feat(lifecycle v12): auto-release when milestone completes (1693b90)
- feat(lifecycle v11): smart CI failure handling — infra vs code (8942ad1)

## [0.0.1] — 2026-04-17

- fix(lifecycle): label-based retry counter + CI fix priority (2c990ba)
- ci: inline lifecycle workflow — fix schedule failures (3a52b4d)
- chore: centralize release to org-wide reusable workflow (eef1d38)

# Changelog

All notable changes to netops-toolkit are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

---

## [0.33.2] — 2026-03-24

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

## [0.33.0] — 2026-02-17

### Added
- **Nokia SR-OS health checker** (`netops/check/nokia_sros.py` via
  `netops/check/health.py`) — CPU, memory, interface error, and log checks
  for Nokia 7750/7450/7210/7705/7250 IXR/7730 SXR running TiMOS.
- **Nokia SR-OS parsers** (`netops/parsers/nokia_sros.py`) —
  `parse_interfaces`, `parse_bgp_summary`, `parse_bof`, and helpers for
  classic CLI formatting variations across TiMOS releases.
- **Nokia SR-OS command templates** (`netops/templates/nokia_sros.py`) —
  `SHOW` and `HEALTH` template dicts aligned with the Nokia SR-OS CLI.
- `netops/inventory/scan.py`: `identify_vendor()` now detects Nokia devices
  from `sysDescr` keywords and enterprise OIDs
  (`1.3.6.1.4.1.6527.*` → `nokia_sros`).
- Tests: `tests/test_parsers_nokia.py` covering all Nokia SR-OS parsers.
- `docs/guides/auto-inventory.md`: document Nokia SNMP auto-detection.

---

## [0.32.0] — 2026-01-20

### Added
- **Ansible roles integration tests** (`tests/test_ansible_roles.py`) —
  validates that generated playbooks reference the correct Ansible role
  structure and that the remediation templates produce importable YAML.
- **`netops_facts` Ansible module** (`netops/ansible/modules/netops_facts.py`) —
  collects structured device facts (health, interfaces, BGP, VLANs, or all)
  and returns them as `ansible_facts.netops` for use in playbooks.
- **`netops_command` Ansible module** (`netops/ansible/modules/netops_command.py`) —
  thin Ansible wrapper around the Netmiko backend; sends arbitrary CLI
  commands and returns raw output with optional `wait_for` matching.
- Tests: `tests/test_ansible.py` covering both Ansible module wrappers.

---

## [0.31.0] — 2025-12-08

### Added
- **Report scheduler** (`netops/report/scheduler.py`) — threading-based
  daily/weekly schedule for automated report generation; no external
  scheduler library required.
- **Report mailer** (`netops/report/mailer.py`) — HTML and optional PDF
  attachment delivery via `smtplib`; supports STARTTLS/SSL, CC/BCC, and
  custom From headers.

---

## [0.30.0] — 2025-11-03

### Added
- **Ansible dynamic inventory** (`netops/ansible/dynamic_inventory.py`) —
  generates Ansible-compatible JSON inventory from a netops `inventory.yaml`;
  auto-creates `vendor_*`, `site_*`, and `role_*` groups; supports on-disk
  JSON cache (default TTL 300 s, configurable via `--cache-ttl`); injects
  per-device credentials from `CredentialVault` when
  `$NETOPS_VAULT_PASSWORD` is set.
- CLI flags: `--vault`, `--cache-ttl`, `--no-cache`, `--refresh-cache`,
  `--cache-path`.
- `docs/guides/auto-inventory.md`: guide for using the dynamic inventory with
  `ansible-playbook -i`.

---

## [0.29.0] — 2025-09-22

### Added
- **Health dashboard** (`netops/report/health_dashboard.py`) — aggregates
  health check results from all supported vendors into a single normalised
  view; renders as terminal table, JSON document, or self-contained HTML page.
- Normalised row schema with `device`, `vendor`, `site`, `category`, `status`,
  `detail`, and `timestamp` fields.
- Jinja2 HTML template (`netops/report/templates/health_dashboard.html.j2`).
- CLI: `python -m netops.report.health_dashboard --format table/json/html`.
- Tests: `tests/test_health_dashboard.py`.

---

## [0.28.0] — 2025-08-11

### Added
- **Playbook generator** (`netops/playbooks/generator.py`) — auto-generates
  Ansible remediation playbooks from health check failures:
  - Vendor-specific collection modules (`cisco.ios.ios_command`, etc.).
  - Pre/post validation tasks around each remediation block.
  - `block/rescue` structure so rollback tasks run automatically on failure.
  - Default dry-run mode (`dry_run: "true"` variable); safe to inspect in CI.
  - Human-review pause before live execution (skip with `--no-pause`).
- `FailureType` enum and `GeneratedPlaybook` dataclass (public API).
- Remediation templates (`netops/playbooks/templates/remediation.py`) for 8
  failure types; `VENDOR_COMMAND_MODULE` / `VENDOR_CONFIG_MODULE` mappings.
- CLI: `python -m netops.playbooks.generator generate/save/list`.
- Tests: `tests/test_playbook_generator.py`.

---

## [0.27.0] — 2025-06-30

### Added
- **Report generator** (`netops/report/generator.py`) — produces HTML and
  optional PDF network health reports from combined health, BGP, and VLAN
  check results using Jinja2 templates.
- Optional dependency groups: `report` (`jinja2`) and `report-pdf`
  (`jinja2 + weasyprint`).
- Default HTML Jinja2 template (`netops/report/templates/default.html.j2`).
- `build_health_report()` helper added to `netops/check/health.py`.
- Tests: `tests/test_report.py`.

---

## [0.26.0] — 2025-05-19

### Added
- **Palo Alto PAN-OS support** — security policy audit and health checks:
  - `netops/templates/paloalto.py`: command templates for PAN-OS.
  - `netops/parsers/paloalto.py`: parsers for session tables, security
    policies, HA state, and system health.
  - `netops/check/paloalto.py`: policy audit (shadow rules, unused rules,
    any/any rules) and health checker (HA, CPU, sessions, interfaces).
  - `netops/inventory/scan.py`: OID `1.3.6.1.4.1.25461.*` → `paloalto_panos`.
- Tests: `tests/test_parsers_paloalto.py`, `tests/test_paloalto_policy.py`.
- `docs/guides/paloalto.md`: vendor guide for PAN-OS inventory, health, and
  policy audit.

---

## [0.25.0] — 2025-04-07

### Added
- **Change rollback** (`netops/change/rollback.py`) — automated rollback with
  pre/post health validation:
  - Captures running config and health baseline before the change.
  - Compares pre/post health; any new alert triggers validation failure.
  - Restores pre-change config automatically on failure when
    `--rollback-on-failure` is set.
  - Writes structured entries to a JSON-lines audit log.
- `RollbackRecord` dataclass; `append_audit_log()` / `load_audit_log()`.
- CLI: `python -m netops.change.rollback --commit --rollback-on-failure
  --validate-health`.
- Tests: `tests/test_change_rollback.py`.

---

## [0.24.0] — 2025-02-24

### Added
- **Change plan** (`netops/change/plan.py`) — approval workflow with
  plan → dry-run → review → approve → execute stages:
  - `generate_plan()` produces a `ChangePlan` with per-device `ChangeStep`
    list, semantic diff preview, and risk score.
  - `export_plan()` / `load_plan()` for JSON/YAML offline review.
  - `apply_plan()` requires `approved=True`; dry-run never modifies devices.
  - `RiskLevel` (LOW/MEDIUM/HIGH) and `DeviceRole` enums.
- CLI: `python -m netops.change.plan plan --dry-run / apply --plan <file>
  --approve`.
- Tests: `tests/test_change_plan.py`.

---

## [0.23.0] — 2025-01-13

### Added
- **Change push** (`netops/change/push.py`) — safe configuration push with
  pre/post diff and auto-rollback confirm timer:
  - Snapshots running config before and after the change.
  - Optional `--confirm-timer N` countdown; restores pre-change config if the
    operator does not type `confirm` within *N* minutes.
  - Appends structured entries to a JSON-lines changelog.
- `ChangeRecord` dataclass; `append_changelog()` / `load_changelog()`.
- CLI: `python -m netops.change.push --host DEVICE --commands FILE --commit
  --confirm-timer 5`.
- Tests: `tests/test_change_push.py`.

---

## [0.22.0] — 2024-11-25

### Added
- **Config diff engine** (`netops/change/diff.py`) — semantic-aware
  configuration diff supporting Cisco IOS, JunOS (set and bracketed), and
  flat (Nokia SR-OS) formats:
  - `diff_configs(before, after, style=None)` → `DiffResult`.
  - `parse_config(text, ConfigStyle)` for structured config trees.
  - Three output formats: `unified`, `semantic` (tree view with parent
    context), and `json`.
- CLI: `python -m netops.change.diff --before FILE --after FILE
  --format unified/semantic/json`.
- Tests: `tests/test_change_diff.py`.
- `docs/guides/config-diff.md`: guide for the diff engine.

---

## [0.21.0] — 2024-10-14

### Added
- **VLAN audit** (`netops/check/vlan.py`) — compares declared vs actual VLAN
  configuration across Cisco IOS/IOS-XE switches:
  - Detects missing VLANs, extra VLANs, name mismatches, and trunk
    mismatches.
  - Per-switch compliance status summary.
- VLAN parsers (`netops/parsers/vlan.py`) — `parse_vlan_brief`,
  `parse_vlan_detail`, `parse_trunk_interfaces`.
- VLAN command templates added to `netops/templates/cisco_ios.py`.
- CLI: `python -m netops.check.vlan --expected-vlans 10,20,30-50,100
  --check-trunks`.
- Tests: `tests/test_vlan.py`.

---

## [0.20.0] — 2024-09-02

### Added
- **SNMP inventory scanner** (`netops/inventory/scan.py`) — discovers devices
  on a subnet via ping sweep, SNMP `sysDescr`/`sysName`/`sysObjectID`, CDP,
  and LLDP:
  - `identify_vendor()` maps OIDs and description keywords to
    `device_type` strings for Cisco, Juniper, Arista, Nokia, and Palo Alto.
  - Outputs inventory fragments as JSON; merges with existing `inventory.yaml`.
  - CSV and hosts-file input modes for ad-hoc scans.
  - Optional `pysnmp` dependency (`pip install netops-toolkit[snmp]`).
- CLI: `python -m netops.inventory.scan --subnet 10.0.0.0/24 --community
  public --merge existing.yaml`.
- Tests: `tests/test_scan.py`.
- `docs/guides/scan.md`: subnet scanner guide.

---

## [0.19.0] — 2024-07-22

### Added
- **Configuration backup** (`netops/collect/backup.py`) — bulk config backup
  with diff tracking:
  - Collects running configs from all inventory devices concurrently
    (`--workers N`).
  - Saves to a timestamped per-device directory tree; generates unified diffs
    against the previous backup.
  - Optional git integration (`--git`) commits every changed file.
- Tests: `tests/test_backup.py`.

---

## [0.18.0] — 2024-06-16

### Added
- **Credential vault** (`netops/core/vault.py`) — AES-256-GCM encrypted
  storage for device credentials:
  - Key derived via PBKDF2-HMAC-SHA256.
  - Lookup order: environment variables → device-specific → group → default.
  - Environment variable names are normalised (hyphens/dots → underscores,
    upper-cased) — e.g. `core-rtr-01` → `NETOPS_CRED_CORE_RTR_01_USER`.
- CLI: `python -m netops.core.vault init / set --device / --group /
  --default`.
- Tests: `tests/test_vault.py`.

---

## [0.17.0] — 2024-05-27

### Added
- **Arista EOS health checker** (`netops/check/arista.py`) — CPU/memory,
  interface errors and transceiver DOM, BGP/EVPN sessions, OSPF adjacencies,
  MLAG health and config-consistency, environment (temperature, fans, PSUs):
  - Primary transport: eAPI JSON; plain-text CLI fallback for BGP/OSPF/MLAG.
  - `--threshold cpu=N,mem=N` and `--fail-on-alert` flags.
- Arista parsers (`netops/parsers/arista.py`) — `parse_cpu_memory_eos`,
  `parse_interfaces_eos`, `parse_bgp_summary_eos`, `parse_bgp_evpn_eos`,
  `parse_ospf_neighbors_eos`, `parse_mlag_eos`, `parse_mlag_config_sanity_eos`,
  `parse_environment_eos`.
- Arista command templates (`netops/templates/arista_eos.py`).
- Tests: `tests/test_arista_health.py`.

---

## [0.16.0] — 2024-05-06

### Added
- **Config collector** (`netops/collect/config.py`) — collects the running
  configuration from a device and returns a structured result dict with
  `host`, `device_type`, `collected_at`, `config`, and `success` keys.
- CLI: `python -m netops.collect.config --inventory inventory.yaml
  --group core`.
- `docs/guides/config-collector.md`: guide for the config collector.

---

## [0.15.0] — 2024-05-06

### Added
- **BGP check module** (`netops/check/bgp.py`) — validates BGP session state
  and prefix counts across vendors; `build_bgp_report()` helper.
- BGP parsers (`netops/parsers/bgp.py`) — `parse_bgp_summary_cisco`,
  `parse_bgp_summary_junos`, `parse_bgp_summary_arista`.
- Tests: `tests/test_bgp.py`.

---

## [0.14.0] — 2024-04-22

### Added
- **Cisco IOS/IOS-XE health checker** (`netops/check/cisco.py`) — CPU/memory,
  interface error counters, BGP neighbour state, OSPF adjacencies, environment
  (temperature, PSUs, fans), and uptime/last-reload-reason checks.
- Cisco parsers (`netops/parsers/cisco.py`) — `parse_cpu_cisco`,
  `parse_memory_cisco`, `parse_environment_cisco`, `parse_ospf_neighbors`.
- Cisco command templates (`netops/templates/cisco_ios.py`).
- Tests: `tests/test_cisco_health.py`.
- `docs/guides/cisco-health.md`: Cisco health check guide.

---

## [0.13.0] — 2024-04-08

### Added
- **Juniper JunOS health checker** (`netops/check/juniper.py`) — Routing
  Engine (RE) CPU/memory, FPC slot status, interface errors, BGP sessions,
  OSPF adjacencies, chassis alarms (major/minor), environment (power, cooling,
  temperature), and routing table summary.
- JunOS parsers (`netops/parsers/juniper.py`) — `parse_re_status`,
  `parse_fpc_status`, `parse_bgp_summary_junos`, `parse_ospf_neighbors_junos`,
  `parse_chassis_alarms`, `parse_chassis_environment`, `parse_route_summary`.
- JunOS command templates (`netops/templates/junos.py`).
- Tests: `tests/test_juniper_health.py`.
- `docs/guides/juniper.md`: Juniper vendor guide.

---

## [0.12.0] — 2024-03-25

### Added
- **Generic health check framework** (`netops/check/health.py`) — orchestrates
  CPU, memory, interface-error, and log checks across vendors; dispatches to
  vendor-specific parsers based on `device_type`; `run_health_check()` public
  API.
- **Interface checker** (`netops/check/interfaces.py`) — collects interface
  status and error counters from inventory devices; `run_interface_check()`.
- **Core connection layer** (`netops/core/connection.py`) — `DeviceConnection`
  /`ConnectionParams` with Netmiko backend; supports SSH and telnet transports;
  `send()` returns raw CLI string.
- **Inventory loader** (`netops/core/inventory.py`) — loads `inventory.yaml`;
  `Inventory.get_devices()` with optional group filter.
- Health parsers (`netops/parsers/health.py`) — vendor-agnostic CPU/memory/
  interface-error/log parsers; Cisco IOS baseline.
- Tests: `tests/test_health.py`, `tests/test_interfaces.py`.
- `docs/guides/getting-started.md`, `docs/guides/interface-checker.md`,
  `docs/guides/inventory-management.md`.

---

## [0.11.2] — 2024-03-24

### Changed
- Internal release; no user-facing changes.
